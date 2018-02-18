# -*- coding: utf-8 -*-
"""The artifacts filter file CLI arguments helper."""

from __future__ import unicode_literals

import os

from artifacts import errors as artifacts_errors
from artifacts import reader as artifacts_reader
from artifacts import registry as artifacts_registry

from plaso.cli import tools
from plaso.cli.helpers import interface
from plaso.cli.helpers import manager
from plaso.lib import errors


class ArtifactsFilterFileArgumentsHelper(interface.ArgumentsHelper):
  """Artifacts filter file CLI arguments helper."""

  NAME = 'artifacts_filter_file'
  DESCRIPTION = 'Artifacts filter file command line arguments.'

  @classmethod
  def AddArguments(cls, argument_group):
    """Adds command line arguments to an argument group.

    This function takes an argument parser or an argument group object and adds
    to it all the command line arguments this helper supports.

    Args:
      argument_group (argparse._ArgumentGroup|argparse.ArgumentParser):
          argparse group.
    """
    argument_group.add_argument(
        '--artifacts_filter_file', '--artifacts-filter-file',
        dest='artifacts_filter_file', type=str, default=None,
        action='store', help=(
            'Path to a directory containing artifact filter definitions, which '
            'are .yaml files. Artifact definitions can be used to describe and '
            'quickly collect data of interest, such as specific files or '
            'Windows Registry keys.'))

  @classmethod
  def ParseOptions(cls, options, configuration_object):
    """Parses and validates options.

    Args:
      options (argparse.Namespace): parser options.
      configuration_object (CLITool): object to be configured by the argument
          helper.

    Raises:
      BadConfigObject: when the configuration object is of the wrong type.
      BadConfigOption: if the required artifact definitions are not defined.
    """
    if not isinstance(configuration_object, tools.CLITool):
      raise errors.BadConfigObject(
          'Configuration object is not an instance of CLITool')

    artifacts_filter_file = cls._ParseStringOption(options,
                                                   'artifacts_filter_file')

    # Search the data location for the filter file.
    if artifacts_filter_file and not os.path.isfile(artifacts_filter_file):
      data_location = getattr(configuration_object, '_data_location', None)
      if data_location:
        artifacts_filter_file_basename = os.path.basename(artifacts_filter_file)
        artifacts_filter_file_path = os.path.join(
            data_location, artifacts_filter_file_basename)
        if os.path.isfile(artifacts_filter_file_path):
            artifacts_filter_file = artifacts_filter_file_path

    if artifacts_filter_file and not os.path.isfile(artifacts_filter_file):
      raise errors.BadConfigOption(
          'No such artifacts filter file: {0:s}.'.format(
              artifacts_filter_file))

    if artifacts_filter_file and os.path.isfile(artifacts_filter_file):
      registry = artifacts_registry.ArtifactDefinitionsRegistry()
      reader = artifacts_reader.YamlArtifactsReader()

      try:
        registry.ReadFromFile(reader, artifacts_filter_file)

      except (KeyError, artifacts_errors.FormatError) as exception:
        raise errors.BadConfigOption((
            'Unable to read artifact filter definitions from: {0:s} with error:'
            ' {1!s}').format(artifacts_filter_file, exception))

    setattr(configuration_object, '_artifacts_filter_file',
            artifacts_filter_file)


manager.ArgumentHelperManager.RegisterHelper(ArtifactsFilterFileArgumentsHelper)
