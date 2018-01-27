# -*- coding: utf-8 -*-
"""Filter file."""

from __future__ import unicode_literals

import logging
import re

from artifacts import definitions as artifact_types
from artifacts import errors as artifacts_errors
from artifacts import reader as artifacts_reader
from artifacts import registry as artifacts_registry

from dfvfs.helpers import file_system_searcher
from dfwinreg import registry_searcher


from plaso.lib import py2to3
from plaso.lib import errors


ARTIFACTS_FILTER_FILE = 'ARTIFACTS_FILTER_FILE'
COMPATIBLE_DFWINREG_KEYS = ['HKEY_LOCAL_MACHINE']


class ArtifactsFilterFile(object):
  """Forensic artifacts file.

  A forensic artifacts file contains one or more forensic artifacts filters.

  Forensic artifacts are defined in:
  https://github.com/ForensicArtifacts/artifacts/blob/master/docs/Artifacts%20definition%20format%20and%20style%20guide.asciidoc
  """

  def __init__(self, path, knowledge_base):
    """Initializes a filter file.

    Args:
      path (str): path to a file that contains one or more forensic artifacts.
    """
    super(ArtifactsFilterFile, self).__init__()
    self._path = path
    self._knowledge_base = knowledge_base

  # TODO: split read and validation from BuildFindSpecs, raise instead of log
  # TODO: determine how to apply the path filters for exclusion.

  def BuildFindSpecs(self, environment_variables=None):
    """Build find specification from a forensic artifacts file.

    Args:
      environment_variables (Optional[list[EnvironmentVariableArtifact]]):
          environment variables.
    """
    path_attributes = self._BuildPathAttributes(environment_variables)

    find_specs = {}
    artifact_registry = artifacts_registry.ArtifactDefinitionsRegistry()
    artifact_reader = artifacts_reader.YamlArtifactsReader()

    try:
      artifact_registry.ReadFromFile(artifact_reader, self._path)

    except (KeyError, artifacts_errors.FormatError) as exception:
      raise errors.BadConfigOption((
          'Unable to read artifact definitions from: {0:s} with '
          'error: ''{1!s}').format(self._path, exception))

    undefined_artifacts = artifact_registry.GetUndefinedArtifacts()
    if undefined_artifacts:
      raise artifacts_errors.MissingDependencyError(
          'Artifacts group referencing undefined artifacts: {0}'.format(
              undefined_artifacts))

    for definition in artifact_registry.GetDefinitions():
      for source in definition.sources:
        if source.type_indicator == artifact_types.TYPE_INDICATOR_FILE:
          for path_entry in source.paths:
            self.BuildFindSpecsFromFileArtifact(path_entry, source.separator,
                                                path_attributes, find_specs)
        elif (source.type_indicator ==
              artifact_types.TYPE_INDICATOR_WINDOWS_REGISTRY_KEY):
          keys = set(source.keys)
          for key_entry in keys:
            if self._CheckKeyCompatibility(key_entry):
              self.BuildFindSpecsFromRegistryArtifact(key_entry,
                                                      path_attributes,
                                                      find_specs)
        elif (source.type_indicator ==
              artifact_types.TYPE_INDICATOR_WINDOWS_REGISTRY_VALUE):
          logging.warning(('Unable to handle Registry Value, extracting '
                           'key only: {0:s} ').format(source.key_value_pairs))

          for key_pair in source.key_value_pairs:
            if keys is None:
              keys = set()
              keys.add(key_pair.get('key'))
            keys.add(key_pair.get('key'))
          for key_entry in keys:
            if self._CheckKeyCompatibility(key_entry):
              self.BuildFindSpecsFromRegistryArtifact(key_entry,
                                                      path_attributes,
                                                      find_specs)
        else:
          logging.warning(('Unable to handle artifact, plaso does not '
                           'support: {0:s} ').format(source.type_indicator))
    self._knowledge_base.SetValue(ARTIFACTS_FILTER_FILE, find_specs)

  def BuildFindSpecsFromFileArtifact(self, path_entry, separator,
                                     path_attributes, find_specs):
    """Build find specification from a forensic artifacts file.

    Args:
      path_entry (str):  Current file system path to add.
          environment variables.
      separator (str): File system path separator.
      path_attributes list(str):  Environment variable attributes used to
          dynamically populate environment variables in key.
      find_specs dict[artifacts.artifact_types]:  Dictionary containing
          find_specs.
    """
    for path in self._ExpandGlobs(path_entry):
      if path_attributes:
        try:
          if '%%environ_' in path:
            path = path.replace('%%environ_', '{')
            path = path.replace('%%', '}')
            path = path.format(**path_attributes)
        except KeyError as exception:
          logging.error((
              'Unable to expand path filter: {0:s} with error: '
              '{1:s}').format(path, exception))
          continue

      if '%%' in path:
        logging.warning((
            'Unable to expand path attribute, unknown '
            'variable: {0:s} ').format(path))
        continue

      if not path.startswith('/') and not path.startswith('\\'):
        logging.warning((
            'The path filter must be defined as an absolute path: '
            '{0:s}').format(path))
        continue

      # Convert the path filters into a list of path segments and
      # strip the root path segment.
      path_segments = path.split(separator)
      path_segments.pop(0)

      if not path_segments[-1]:
        logging.warning(
            'Empty last path segment in path filter: {0:s}'.format(path))
        continue

      find_spec = file_system_searcher.FindSpec(
          location_glob=path_segments, case_sensitive=False)
      if artifact_types.TYPE_INDICATOR_FILE in find_specs:
        find_specs[artifact_types.TYPE_INDICATOR_FILE].append(
            find_spec)
      else:
        find_specs[artifact_types.TYPE_INDICATOR_FILE] = []
        find_specs[artifact_types.TYPE_INDICATOR_FILE].append(
            find_spec)

  def BuildFindSpecsFromRegistryArtifact(self, key_entry,
                                         path_attributes, find_specs):
    """Build find specification from a forensic artifacts file.

    Args:
      key_entry (str):  Current file system key to add.
      path_attributes list(str):  Environment variable attributes used to
          dynamically populate environment variables in key.
      find_specs dict[artifacts.artifact_types]:  Dictionary containing
          find_specs.
    """
    for key in self._ExpandGlobs(key_entry):
      if path_attributes:
        try:
          key = key.replace('%%environ_', '{')
          key = key.replace('%%', '}')
          key = key.format(**path_attributes)
        except KeyError as exception:
          logging.error((
              'Unable to expand path filter: {0:s} with error: '
              '{1:s}').format(key, exception))
          continue
      find_spec = registry_searcher.FindSpec(
          key_path_glob=key)
    if (artifact_types.TYPE_INDICATOR_WINDOWS_REGISTRY_KEY
        in find_specs):
      find_specs[artifact_types.TYPE_INDICATOR_WINDOWS_REGISTRY_KEY].append(
          find_spec)
    else:
      find_specs[
          artifact_types.TYPE_INDICATOR_WINDOWS_REGISTRY_KEY] = []
      find_specs[artifact_types.TYPE_INDICATOR_WINDOWS_REGISTRY_KEY].append(
          find_spec)

  def _CheckKeyCompatibility(self, key):
    """Check if a registry key is compatible with dfwinreg.

    Args:
      key (str):  String key to to check for dfwinreg compatibility.

    Returns:
      (bool): Boolean whether key is compatible or not.
    """
    key_path_prefix = key.split('\\')[0]
    if key_path_prefix in COMPATIBLE_DFWINREG_KEYS:
      return True
    # logging.warning('Key {0:s}, has a prefix {1:s} that is not supported '
    #                'by dfwinreg presently'.format(key, key_path_prefix))
    return False

  def _ExpandGlobs(self, path):
    """Expand globs present in an artifact entry.

    Args:
      path (str):  String path to be expanded.

    Returns:
      list[str]: String path expanded for each glob.
    """

    match = re.search(r'(.*)\*\*(\d+)?$', path)
    if match:
      if match.group(2):
        iterations = match.group(2)
      else:
        iterations = 10
      paths = [self._BuildString(match.group(1), counter) for counter in
               range(int(iterations))]
      return paths
    else:
      return [path]

  def _BuildString(self, path, count):
    """Append wildcard entries to end of string.

    Args:
      path (str):  String path to append wildcards to.

    Returns:
      path (str): String path expanded with wildcards.
    """
    for _ in range(count):
      path += r'\*'
    return path

  def _BuildPathAttributes(self, environment_variables=None):
    """Build find specification from a forensic artifacts file.

    Args:
      environment_variables (Optional[list[EnvironmentVariableArtifact]]):
          environment variables.

    Returns:
      path_attributes dict[str]:  Dictionary containing the path attributes, per
          their name.
    """
    path_attributes = {}
    if environment_variables:
      for environment_variable in environment_variables:
        attribute_name = environment_variable.name.lower()
        attribute_value = environment_variable.value
        if not isinstance(attribute_value, py2to3.STRING_TYPES):
          continue

        # Remove the drive letter.
        if len(attribute_value) >= 2 and attribute_value[1] == ':':
          _, _, attribute_value = attribute_value.rpartition(':')
        path_attributes[attribute_name] = attribute_value

    return path_attributes
