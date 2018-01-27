# -*- coding: utf-8 -*-
"""Filter file."""

from __future__ import unicode_literals

import logging

from dfvfs.helpers import file_system_searcher

from plaso.lib import py2to3


class ForensicArtifactsFilterFile(object):
  """Forensic artifacts file.

  A forensic artifacts file contains one or more forensic artifacts filters.

  Forensic artifacts are defined in:
  https://github.com/ForensicArtifacts/artifacts/blob/master/docs/Artifacts%20definition%20format%20and%20style%20guide.asciidoc

  If the path filter needs to have curly brackets in the path then these need
  to be escaped with another curly bracket, for example
  "\\System\\{my_attribute}\\{{123-AF25-E523}}\\KeyName", where
  "{{123-AF25-E523}}" will be replaced with "{123-AF25-E523}" at runtime.
  """

  def __init__(self, path):
    """Initializes a filter file.

    Args:
      path (str): path to a file that contains one or more forensic artifacts.
    """
    super(ForensicArtifactsFilterFile, self).__init__()
    self._path = path

  # TODO: split read and validation from BuildFindSpecs, raise instead of log
  # TODO: determine how to apply the path filters for exclusion.

  def BuildFindSpecs(self, environment_variables=None):
    """Build find specification from a forensic artifacts file.

    Args:
      environment_variables (Optional[list[EnvironmentVariableArtifact]]):
          environment variables.

    Returns:
      list[dfvfs.FindSpec]: find specification.
    """
    path_attributes = {}
    if environment_variables:
      for environment_variable in environment_variables:
        attribute_name = environment_variable.name.lower()
        attribute_value = environment_variable.value
        if not isinstance(attribute_value, py2to3.STRING_TYPES):
          continue

        # Remove the drive letter.
        if len(attribute_value) > 2 and attribute_value[1] == ':':
          _, _, attribute_value = attribute_value.rpartition(':')

        if attribute_value.startswith('\\'):
          attribute_value = attribute_value.replace('\\', '/')

        path_attributes[attribute_name] = attribute_value

    find_specs = []
    with open(self._path, 'rb') as file_object:
      for line in file_object:
        line = line.strip()
        if line.startswith('#'):
          continue

        if path_attributes:
          try:
            line = line.format(**path_attributes)
          except KeyError as exception:
            logging.error((
                'Unable to expand path filter: {0:s} with error: '
                '{1:s}').format(line, exception))
            continue

        if not line.startswith('/'):
          logging.warning((
              'The path filter must be defined as an abolute path: '
              '{0:s}').format(line))
          continue

        # Convert the path filters into a list of path segments and strip
        # the root path segment.
        path_segments = line.split('/')
        path_segments.pop(0)

        if not path_segments[-1]:
          logging.warning(
              'Empty last path segment in path filter: {0:s}'.format(line))
          continue

        find_spec = file_system_searcher.FindSpec(
            location_regex=path_segments, case_sensitive=False)
        find_specs.append(find_spec)

    return find_specs
