#!/usr/bin/python
# -*- coding: utf-8 -*-
"""Tests for the artifacts file filter functions."""

from __future__ import unicode_literals

import logging
import os
import tempfile
import unittest

from artifacts import definitions as artifact_types

from dfwinreg import registry as dfwinreg_registry
from dfwinreg import registry_searcher as dfwinreg_registry_searcher

from dfvfs.helpers import file_system_searcher
from dfvfs.lib import definitions as dfvfs_definitions
from dfvfs.path import factory as path_spec_factory
from dfvfs.resolver import resolver as path_spec_resolver

from plaso.containers import artifacts
from plaso.engine import artifacts_filter_file
from plaso.engine import knowledge_base as knowledge_base_engine
from plaso.parsers import winreg as windows_registry_parser

from tests import test_lib as shared_test_lib


class BuildFindSpecsFromFileTest(shared_test_lib.BaseTestCase):
  """Tests for the BuildFindSpecsFromFile function."""

  @shared_test_lib.skipUnlessHasTestFile(['System.evtx'])
  @shared_test_lib.skipUnlessHasTestFile(['testdir', 'filter_1.txt'])
  @shared_test_lib.skipUnlessHasTestFile(['testdir', 'filter_3.txt'])
  def testBuildFindSpecsFromFile(self):
    """Tests the BuildFindSpecsFromFile function."""
    artifacts_filter_file_path = ''
    knowledge_base = knowledge_base_engine.KnowledgeBase()
    with tempfile.NamedTemporaryFile(delete=False) as temp_file:
      test_filter_file = artifacts_filter_file.ArtifactsFilterFile(
          temp_file.name, knowledge_base)
      temp_file.write(b'name: TestFiles\n')
      temp_file.write(b'doc: Test Doc\n')
      temp_file.write(b'sources:\n')
      temp_file.write(b'- type: FILE\n')
      temp_file.write(b'  attributes:\n')
      temp_file.write(b'    paths: [\'%%environ_systemdrive%%\\AUTHORS\']\n')
      temp_file.write(b'    separator: \'\\\'\n')
      temp_file.write(b'labels: [System]\n')
      temp_file.write(b'supported_os: [Windows]\n')
      temp_file.write(b'\n---\n')
      temp_file.write(b'name: TestFiles2\n')
      temp_file.write(b'doc: Test Doc2\n')
      temp_file.write(b'sources:\n')
      temp_file.write(b'- type: FILE\n')
      temp_file.write(b'  attributes:\n')
      temp_file.write(b'    paths: \n')
      temp_file.write(b'      - \'%%environ_systemdrive%%\\test_data\\'
                      b'*.evtx\'\n')
      temp_file.write(b'      - \'\\test_data\\testdir\\filter_*.txt\'\n')
      temp_file.write(b'      - \'\\does_not_exist\\some_file_*.txt\'\n')
      temp_file.write(b'      - \'failing\\\'\n')
      temp_file.write(b'    separator: \'\\\'\n')
      temp_file.write(b'labels: [System]\n')
      temp_file.write(b'supported_os: [Windows]\n')
      temp_file.write(b'\n')

    environment_variable = artifacts.EnvironmentVariableArtifact(
        case_sensitive=False, name='SystemDrive', value='C:')

    test_filter_file.BuildFindSpecs(
        environment_variables=[environment_variable])
    find_specs = knowledge_base.GetValue(
        artifacts_filter_file.ARTIFACTS_FILTER_FILE)


    try:
      os.remove(artifacts_filter_file_path)
    except (OSError, IOError) as exception:
      logging.warning(
          'Unable to remove artifacts_filter file: {0:s} with error: {1!s}'.
          format(artifacts_filter_file_path, exception))

    self.assertEqual(len(find_specs[artifact_types.TYPE_INDICATOR_FILE]), 4)

    path_spec = path_spec_factory.Factory.NewPathSpec(
        dfvfs_definitions.TYPE_INDICATOR_OS, location='.')
    file_system = path_spec_resolver.Resolver.OpenFileSystem(path_spec)
    searcher = file_system_searcher.FileSystemSearcher(
        file_system, path_spec)

    path_spec_generator = searcher.Find(
        find_specs=find_specs[artifact_types.TYPE_INDICATOR_FILE])
    self.assertIsNotNone(path_spec_generator)

    path_specs = list(path_spec_generator)
    # Two evtx, one symbolic link to evtx, one AUTHORS, two filter_*.txt files,
    # total 6 path specifications.
    self.assertEqual(len(path_specs), 6)

    with self.assertRaises(IOError):
      test_filter_file = artifacts_filter_file.ArtifactsFilterFile(
          'thisfiledoesnotexist', knowledge_base)
      test_filter_file.BuildFindSpecs()

    file_system.Close()

  @shared_test_lib.skipUnlessHasTestFile(['SYSTEM'])
  def testBuildRegistryFindSpecsFromFile(self):
    """Tests the BuildFindSpecsFromFile function."""
    artifacts_filter_file_path = ''
    knowledge_base = knowledge_base_engine.KnowledgeBase()
    with tempfile.NamedTemporaryFile(delete=False) as temp_file:
      test_filter_file = artifacts_filter_file.ArtifactsFilterFile(
          temp_file.name, knowledge_base)
      temp_file.write(b'name: TestRegistry\n')
      temp_file.write(b'doc: Test Registry Doc\n')
      temp_file.write(b'sources:\n')
      temp_file.write(b'- type: REGISTRY_KEY\n')
      temp_file.write(b'  attributes:\n')
      temp_file.write(b'    keys: [\'HKEY_LOCAL_MACHINE\\System\\CurrentControl'
                      b'Set\\Control\\SecurityProviders\\*\']\n')
      temp_file.write(b'supported_os: [Windows]\n')

    test_filter_file.BuildFindSpecs(
        environment_variables=None)
    find_specs = knowledge_base.GetValue(
        artifacts_filter_file.ARTIFACTS_FILTER_FILE)

    try:
      os.remove(artifacts_filter_file_path)
    except (OSError, IOError) as exception:
      logging.warning(
          'Unable to remove artifacts_filter file: {0:s} with error: {1!s}'.
          format(artifacts_filter_file_path, exception))

    self.assertEqual(
        len(find_specs[artifact_types.TYPE_INDICATOR_WINDOWS_REGISTRY_KEY]), 1)

    win_registry_reader = (
        windows_registry_parser.FileObjectWinRegistryFileReader())

    file_entry = self._GetTestFileEntry(['SYSTEM'])
    file_object = file_entry.GetFileObject()

    registry_file = win_registry_reader.Open(file_object)

    win_registry = dfwinreg_registry.WinRegistry()
    key_path_prefix = win_registry.GetRegistryFileMapping(registry_file)
    registry_file.SetKeyPathPrefix(key_path_prefix)
    win_registry.MapFile(key_path_prefix, registry_file)

    searcher = dfwinreg_registry_searcher.WinRegistrySearcher(win_registry)
    key_paths = list(searcher.Find(find_specs=find_specs[
        artifact_types.TYPE_INDICATOR_WINDOWS_REGISTRY_KEY]))

    self.assertIsNotNone(key_paths)

    # Three key paths found
    self.assertEqual(len(key_paths), 3)

    with self.assertRaises(IOError):
      test_filter_file = artifacts_filter_file.ArtifactsFilterFile(
          'thisfiledoesnotexist', knowledge_base)
      test_filter_file.BuildFindSpecs()

if __name__ == '__main__':
  unittest.main()
