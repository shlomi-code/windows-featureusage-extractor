#!/usr/bin/env python3
"""
Unit tests for JSON exporter module
"""

import unittest
import sys
import os
import json
import tempfile
from unittest.mock import patch, mock_open

# Add the modules directory to the path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'modules'))

from featureusage.json_exporter import JSONExporter


class TestJSONExporter(unittest.TestCase):
    """Test cases for JSONExporter class"""
    
    def setUp(self):
        """Set up test fixtures"""
        self.exporter = JSONExporter()
        self.sample_results = {
            "extraction_time": "2025-01-01T12:00:00",
            "current_user_sid": "test_user",
            "total_entries": 1,
            "featureusage_data": [
                {
                    "timestamp": "2025-01-01T12:00:00",
                    "app_identifier": "test_app.exe",
                    "usage_count": 5
                }
            ],
            "appswitched_data": [],
            "showjumpview_data": [],
            "appbadgeupdated_data": [],
            "applaunch_data": [],
            "startmenu_data": [],
            "search_data": []
        }
    
    def test_export_results_default_filename(self):
        """Test exporting with default filename"""
        with tempfile.TemporaryDirectory() as temp_dir:
            result_file = self.exporter.export_results(self.sample_results, output_dir=temp_dir)
            
            # Check that file was created
            self.assertTrue(os.path.exists(result_file))
            self.assertTrue(result_file.endswith('.json'))
            
            # Check file contents
            with open(result_file, 'r', encoding='utf-8') as f:
                data = json.load(f)
                self.assertEqual(self.sample_results, data)
    
    def test_export_results_custom_filename(self):
        """Test exporting with custom filename"""
        with tempfile.TemporaryDirectory() as temp_dir:
            custom_filename = "custom_test.json"
            result_file = self.exporter.export_results(self.sample_results, custom_filename, temp_dir)
            
            # Check that file was created with custom name
            expected_path = os.path.join(temp_dir, custom_filename)
            self.assertEqual(expected_path, result_file)
            self.assertTrue(os.path.exists(result_file))
    
    def test_export_results_current_directory(self):
        """Test exporting to current directory"""
        with tempfile.TemporaryDirectory() as temp_dir:
            original_cwd = os.getcwd()
            try:
                os.chdir(temp_dir)
                result_file = self.exporter.export_results(self.sample_results)
                
                # Check that file was created in current directory
                self.assertTrue(os.path.exists(result_file))
                self.assertTrue(result_file.endswith('.json'))
            finally:
                os.chdir(original_cwd)
    
    def test_export_results_file_write_error(self):
        """Test handling of file write errors"""
        with patch('builtins.open', mock_open()) as mock_file:
            mock_file.side_effect = OSError("Permission denied")
            
            result = self.exporter.export_results(self.sample_results)
            
            # Should return empty string on error
            self.assertEqual("", result)
    
    def test_export_to_string(self):
        """Test exporting to JSON string"""
        result = self.exporter.export_to_string(self.sample_results)
        
        # Should return valid JSON string
        self.assertIsInstance(result, str)
        
        # Should be able to parse back to original data
        parsed_data = json.loads(result)
        self.assertEqual(self.sample_results, parsed_data)
    
    def test_export_to_string_error(self):
        """Test handling of JSON serialization errors"""
        # Create data that can't be JSON serialized
        invalid_data = {
            "test": object()  # Objects can't be JSON serialized
        }
        
        result = self.exporter.export_to_string(invalid_data)
        
        # Should return empty string on error
        self.assertEqual("", result)
    
    def test_validate_results_valid(self):
        """Test validation of valid results"""
        result = self.exporter.validate_results(self.sample_results)
        self.assertTrue(result)
    
    def test_validate_results_missing_fields(self):
        """Test validation of results with missing fields"""
        incomplete_results = {
            "extraction_time": "2025-01-01T12:00:00",
            # Missing other required fields
        }
        
        result = self.exporter.validate_results(incomplete_results)
        self.assertFalse(result)
    
    def test_validate_results_empty(self):
        """Test validation of empty results"""
        result = self.exporter.validate_results({})
        self.assertFalse(result)
    
    def test_get_export_summary(self):
        """Test getting export summary"""
        summary = self.exporter.get_export_summary(self.sample_results)
        
        # Check required fields
        self.assertIn("export_time", summary)
        self.assertIn("total_entries", summary)
        self.assertIn("data_sources", summary)
        self.assertIn("extraction_info", summary)
        
        # Check data structure
        self.assertEqual(1, summary["total_entries"])  # From sample_results["total_entries"]
        self.assertIsInstance(summary["data_sources"], dict)
        self.assertIsInstance(summary["extraction_info"], dict)
    
    def test_get_export_summary_empty_data(self):
        """Test getting export summary with empty data"""
        empty_results = {
            "extraction_time": "2025-01-01T12:00:00",
            "current_user_sid": "test_user",
            "featureusage_data": [],
            "appswitched_data": [],
            "showjumpview_data": [],
            "appbadgeupdated_data": [],
            "applaunch_data": [],
            "startmenu_data": [],
            "search_data": []
        }
        
        summary = self.exporter.get_export_summary(empty_results)
        
        # Check that all counts are zero
        self.assertEqual(0, summary["total_entries"])
        for source, count in summary["data_sources"].items():
            self.assertEqual(0, count)


if __name__ == '__main__':
    unittest.main()


