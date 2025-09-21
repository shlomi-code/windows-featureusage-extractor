#!/usr/bin/env python3
"""
Unit tests for Registry access module
"""

import unittest
import sys
import os
from unittest.mock import Mock, patch, MagicMock
import winreg

# Add the modules directory to the path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'modules'))

from featureusage.registry_access import RegistryAccess


class TestRegistryAccess(unittest.TestCase):
    """Test cases for RegistryAccess class"""
    
    def setUp(self):
        """Set up test fixtures"""
        self.registry = RegistryAccess()
    
    @patch('winreg.OpenKey')
    def test_open_key_success(self, mock_open_key):
        """Test successful key opening"""
        mock_key = Mock()
        mock_open_key.return_value = mock_key
        
        result = self.registry.open_key(winreg.HKEY_CURRENT_USER, "Test\\Path")
        
        self.assertEqual(mock_key, result)
        mock_open_key.assert_called_once_with(winreg.HKEY_CURRENT_USER, "Test\\Path")
    
    @patch('winreg.OpenKey')
    def test_open_key_failure(self, mock_open_key):
        """Test key opening failure"""
        mock_open_key.side_effect = OSError("Key not found")
        
        result = self.registry.open_key(winreg.HKEY_CURRENT_USER, "NonExistent\\Path")
        
        self.assertIsNone(result)
    
    @patch('winreg.QueryInfoKey')
    def test_query_info_key_success(self, mock_query_info):
        """Test successful key info query"""
        mock_key = Mock()
        mock_query_info.return_value = (5, 3, 1234567890)  # values, subkeys, last_modified
        
        result = self.registry.query_info_key(mock_key)
        
        self.assertEqual((5, 3, 1234567890), result)
        mock_query_info.assert_called_once_with(mock_key)
    
    @patch('winreg.QueryInfoKey')
    def test_query_info_key_failure(self, mock_query_info):
        """Test key info query failure"""
        mock_key = Mock()
        mock_query_info.side_effect = OSError("Access denied")
        
        result = self.registry.query_info_key(mock_key)
        
        self.assertIsNone(result)
    
    @patch('winreg.EnumKey')
    def test_enum_key_success(self, mock_enum_key):
        """Test successful key enumeration"""
        mock_key = Mock()
        mock_enum_key.return_value = "TestSubKey"
        
        result = self.registry.enum_key(mock_key, 0)
        
        self.assertEqual("TestSubKey", result)
        mock_enum_key.assert_called_once_with(mock_key, 0)
    
    @patch('winreg.EnumKey')
    def test_enum_key_failure(self, mock_enum_key):
        """Test key enumeration failure"""
        mock_key = Mock()
        mock_enum_key.side_effect = OSError("No more items")
        
        result = self.registry.enum_key(mock_key, 0)
        
        self.assertIsNone(result)
    
    @patch('winreg.EnumValue')
    def test_enum_value_success(self, mock_enum_value):
        """Test successful value enumeration"""
        mock_key = Mock()
        mock_enum_value.return_value = ("TestValue", "TestData", winreg.REG_SZ)
        
        result = self.registry.enum_value(mock_key, 0)
        
        self.assertEqual(("TestValue", "TestData", winreg.REG_SZ), result)
        mock_enum_value.assert_called_once_with(mock_key, 0)
    
    @patch('winreg.EnumValue')
    def test_enum_value_failure(self, mock_enum_value):
        """Test value enumeration failure"""
        mock_key = Mock()
        mock_enum_value.side_effect = OSError("No more items")
        
        result = self.registry.enum_value(mock_key, 0)
        
        self.assertIsNone(result)
    
    @patch('winreg.OpenKey')
    @patch('winreg.QueryValueEx')
    def test_read_registry_value_success(self, mock_query_value, mock_open_key):
        """Test successful registry value reading"""
        mock_key = Mock()
        mock_open_key.return_value = mock_key
        mock_query_value.return_value = ("TestData", winreg.REG_SZ)
        
        result = self.registry.read_registry_value(winreg.HKEY_CURRENT_USER, "Test\\Path", "TestValue")
        
        self.assertEqual("TestData", result)
        mock_open_key.assert_called_once_with(winreg.HKEY_CURRENT_USER, "Test\\Path")
        mock_query_value.assert_called_once_with(mock_key, "TestValue")
    
    @patch('winreg.QueryValueEx')
    def test_read_registry_value_failure(self, mock_query_value):
        """Test registry value reading failure"""
        mock_query_value.side_effect = OSError("Value not found")
        
        result = self.registry.read_registry_value(winreg.HKEY_CURRENT_USER, "Test\\Path", "NonExistentValue")
        
        self.assertIsNone(result)
    
    @patch('winreg.CloseKey')
    def test_close_key(self, mock_close_key):
        """Test key closing"""
        mock_key = Mock()
        
        self.registry.close_key(mock_key)
        
        mock_close_key.assert_called_once_with(mock_key)
    
    def test_close_key_none(self):
        """Test closing None key"""
        # Should not raise an exception
        self.registry.close_key(None)
    
    @patch('winreg.OpenKey')
    @patch('winreg.QueryValueEx')
    def test_read_registry_value_success_with_mock(self, mock_query_value, mock_open_key):
        """Test reading registry value with mocked registry calls"""
        mock_key = Mock()
        mock_open_key.return_value = mock_key
        mock_query_value.return_value = ("TestData", winreg.REG_SZ)
        
        result = self.registry.read_registry_value(winreg.HKEY_CURRENT_USER, "Test\\Path", "TestValue")
        
        self.assertEqual("TestData", result)
        mock_open_key.assert_called_once_with(winreg.HKEY_CURRENT_USER, "Test\\Path")
        mock_query_value.assert_called_once_with(mock_key, "TestValue")
    
    @patch('winreg.OpenKey')
    @patch('winreg.QueryValueEx')
    def test_read_registry_value_failure_with_mock(self, mock_query_value, mock_open_key):
        """Test reading registry value failure with mocked registry calls"""
        mock_key = Mock()
        mock_open_key.return_value = mock_key
        mock_query_value.side_effect = OSError("Value not found")
        
        result = self.registry.read_registry_value(winreg.HKEY_CURRENT_USER, "Test\\Path", "TestValue")
        
        self.assertIsNone(result)


if __name__ == '__main__':
    unittest.main()


