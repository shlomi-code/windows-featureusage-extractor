#!/usr/bin/env python3
"""
Unit tests for main FeatureUsage extractor module
"""

import unittest
import sys
import os
from unittest.mock import Mock, patch, MagicMock
from datetime import datetime

# Add the modules directory to the path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'modules'))

# Import the main extractor
sys.path.insert(0, os.path.dirname(__file__))
from featureusage_extractor import FeatureUsageExtractor


class TestFeatureUsageExtractor(unittest.TestCase):
    """Test cases for FeatureUsageExtractor class"""
    
    def setUp(self):
        """Set up test fixtures"""
        # Mock all the dependencies
        with patch('featureusage_extractor.GUIDResolver'), \
             patch('featureusage_extractor.AppResolver'), \
             patch('featureusage_extractor.RegistryAccess'), \
             patch('featureusage_extractor.JSONExporter'), \
             patch('featureusage_extractor.HTMLExporter'):
            
            self.extractor = FeatureUsageExtractor()
            
            # Mock the registry access
            self.extractor.registry = Mock()
            self.extractor.guid_resolver = Mock()
            self.extractor.app_resolver = Mock()
            self.extractor.json_exporter = Mock()
            self.extractor.html_exporter = Mock()
    
    def test_initialization(self):
        """Test extractor initialization"""
        self.assertIsNotNone(self.extractor.current_user_sid)
        self.assertIsNotNone(self.extractor.featureusage_path)
        self.assertIsNotNone(self.extractor.results)
        self.assertIn("extraction_time", self.extractor.results)
        self.assertIn("current_user_sid", self.extractor.results)
        self.assertIn("featureusage_data", self.extractor.results)
    
    def test_get_current_user_sid(self):
        """Test getting current user SID"""
        with patch.dict(os.environ, {'USERNAME': 'testuser', 'USERDOMAIN': 'TESTDOMAIN'}):
            sid = self.extractor._get_current_user_sid()
            self.assertIsNotNone(sid)
    
    def test_get_current_user_sid_fallback(self):
        """Test getting current user SID with fallback"""
        with patch.dict(os.environ, {}, clear=True):
            sid = self.extractor._get_current_user_sid()
            self.assertEqual("Current User", sid)
    
    def test_parse_featureusage_data_valid(self):
        """Test parsing valid FeatureUsage data"""
        # Create mock binary data (simplified)
        data = b'\x00' * 24  # 8 bytes header + 16 bytes entry
        
        result = self.extractor._parse_featureusage_data(data)
        
        # Should return a list (may be empty due to parsing logic)
        self.assertIsInstance(result, list)
    
    def test_parse_featureusage_data_invalid(self):
        """Test parsing invalid FeatureUsage data"""
        # Test with insufficient data
        data = b'\x00' * 4
        
        result = self.extractor._parse_featureusage_data(data)
        
        # Should return empty list
        self.assertEqual([], result)
    
    def test_parse_featureusage_data_none(self):
        """Test parsing None data"""
        result = self.extractor._parse_featureusage_data(None)
        
        # Should return empty list
        self.assertEqual([], result)
    
    def test_parse_dword_appswitched_data(self):
        """Test parsing DWORD AppSwitched data"""
        result = self.extractor._parse_dword_appswitched_data("test_app.exe", 5)
        
        # Should return a dictionary with expected fields
        self.assertIsInstance(result, dict)
        self.assertIn("timestamp", result)
        self.assertIn("app_identifier", result)
        self.assertIn("usage_count", result)
        self.assertEqual("test_app.exe", result["app_identifier"])
        self.assertEqual(5, result["usage_count"])
        self.assertEqual("Executable", result["entry_type"])
    
    def test_parse_dword_appswitched_data_uwp(self):
        """Test parsing DWORD AppSwitched data for UWP app"""
        result = self.extractor._parse_dword_appswitched_data("Microsoft.TestApp_123!App", 3)
        
        self.assertEqual("UWP_App", result["entry_type"])
        self.assertEqual("Microsoft.TestApp_123!App", result["app_package"])
    
    def test_parse_dword_appswitched_data_pid(self):
        """Test parsing DWORD AppSwitched data for PID"""
        result = self.extractor._parse_dword_appswitched_data("*PID00001234", 1)
        
        self.assertEqual("Process_ID", result["entry_type"])
        self.assertEqual(0x1234, result["process_id"])
    
    def test_extract_appswitched_data_no_key(self):
        """Test extracting AppSwitched data when key doesn't exist"""
        self.extractor.registry.open_key.return_value = None
        
        result = self.extractor.extract_appswitched_data()
        
        # Should return empty list
        self.assertEqual([], result)
    
    def test_extract_appswitched_data_with_data(self):
        """Test extracting AppSwitched data with registry data"""
        # Mock registry key and values
        mock_key = Mock()
        self.extractor.registry.open_key.return_value = mock_key
        self.extractor.registry.query_info_key.return_value = (1, 0, 0)  # 1 value, 0 subkeys
        self.extractor.registry.enum_value.return_value = ("test_app.exe", 5, 4)  # REG_DWORD
        
        result = self.extractor.extract_appswitched_data()
        
        # Should return list with one entry
        self.assertEqual(1, len(result))
        self.assertEqual("test_app.exe", result[0]["app_identifier"])
        self.assertEqual(5, result[0]["usage_count"])
    
    def test_extract_startmenu_data_no_key(self):
        """Test extracting StartMenu data when key doesn't exist"""
        self.extractor.registry.open_key.return_value = None
        
        result = self.extractor.extract_startmenu_data()
        
        # Should return empty list
        self.assertEqual([], result)
    
    def test_extract_search_data_no_key(self):
        """Test extracting Search data when key doesn't exist"""
        self.extractor.registry.open_key.return_value = None
        
        result = self.extractor.extract_search_data()
        
        # Should return empty list
        self.assertEqual([], result)
    
    def test_extract_showjumpview_data_no_key(self):
        """Test extracting ShowJumpView data when key doesn't exist"""
        self.extractor.registry.open_key.return_value = None
        
        result = self.extractor.extract_showjumpview_data()
        
        # Should return empty list
        self.assertEqual([], result)
    
    def test_extract_appbadgeupdated_data_no_key(self):
        """Test extracting AppBadgeUpdated data when key doesn't exist"""
        self.extractor.registry.open_key.return_value = None
        
        result = self.extractor.extract_appbadgeupdated_data()
        
        # Should return empty list
        self.assertEqual([], result)
    
    def test_extract_applaunch_data_no_key(self):
        """Test extracting AppLaunch data when key doesn't exist"""
        self.extractor.registry.open_key.return_value = None
        
        result = self.extractor.extract_applaunch_data()
        
        # Should return empty list
        self.assertEqual([], result)
    
    def test_resolve_guids_in_data(self):
        """Test resolving GUIDs in data"""
        test_data = [
            {
                "app_identifier": "Microsoft.AutoGenerated.{12345678-1234-1234-1234-123456789012}",
                "usage_count": 5
            },
            {
                "app_identifier": "test_app.exe",
                "usage_count": 3
            }
        ]
        
        # Mock the resolvers
        self.extractor.app_resolver.resolve_app_id.return_value = "Resolved App Name"
        self.extractor.guid_resolver.replace_guid_with_resolved.return_value = "test_app.exe"
        
        result = self.extractor._resolve_guids_in_data(test_data)
        
        # Should return data with resolved identifiers
        self.assertEqual(2, len(result))
        self.assertIn("app_identifier_resolved", result[0])
        self.assertIn("app_identifier_resolved", result[1])
    
    def test_save_results(self):
        """Test saving results to JSON"""
        self.extractor.json_exporter.export_results.return_value = "test_output.json"
        
        result = self.extractor.save_results()
        
        # Should call the JSON exporter
        self.extractor.json_exporter.export_results.assert_called_once()
        self.assertEqual("test_output.json", result)
    
    def test_export_to_html(self):
        """Test exporting to HTML"""
        self.extractor.html_exporter.export_results.return_value = "test_output.html"
        
        result = self.extractor.export_to_html()
        
        # Should call the HTML exporter
        self.extractor.html_exporter.export_results.assert_called_once()
        self.assertEqual("test_output.html", result)
    
    def test_print_summary_no_data(self):
        """Test printing summary with no data"""
        self.extractor.results["featureusage_data"] = []
        
        # Should not raise an exception
        self.extractor.print_summary()
    
    def test_print_summary_with_data(self):
        """Test printing summary with data"""
        self.extractor.results["featureusage_data"] = [
            {
                "source": "AppSwitched",
                "timestamp": "2025-01-01T12:00:00",
                "app_identifier": "test_app.exe",
                "usage_count": 5
            }
        ]
        
        # Should not raise an exception
        self.extractor.print_summary()
    
    def test_check_alternative_appswitched_sources(self):
        """Test checking alternative AppSwitched sources"""
        # Mock registry access to return no sources
        self.extractor.registry.open_key.return_value = None
        
        result = self.extractor.check_alternative_appswitched_sources()
        
        # Should return empty list
        self.assertEqual([], result)
    
    def test_provide_test_data_suggestions(self):
        """Test providing test data suggestions"""
        # Should not raise an exception
        self.extractor.provide_test_data_suggestions()


if __name__ == '__main__':
    unittest.main()


