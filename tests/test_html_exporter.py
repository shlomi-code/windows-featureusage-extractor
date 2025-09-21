#!/usr/bin/env python3
"""
Unit tests for HTML exporter module
"""

import unittest
import sys
import os
import tempfile
from unittest.mock import patch, mock_open

# Add the modules directory to the path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'modules'))

from featureusage.html_exporter import HTMLExporter


class TestHTMLExporter(unittest.TestCase):
    """Test cases for HTMLExporter class"""
    
    def setUp(self):
        """Set up test fixtures"""
        self.exporter = HTMLExporter()
        self.sample_results = {
            "extraction_time": "2025-01-01T12:00:00",
            "current_user_sid": "test_user",
            "full_user_sid": "S-1-5-21-1234567890-1234567890-1234567890-1001",
            "total_entries": 2,
            "summary": {
                "appswitched_entries": 1,
                "startmenu_entries": 0,
                "search_entries": 0,
                "showjumpview_entries": 1,
                "appbadgeupdated_entries": 0,
                "applaunch_entries": 0
            },
            "featureusage_data": [
                {
                    "timestamp": "2025-01-01T12:00:00",
                    "app_identifier": "test_app.exe",
                    "usage_count": 5,
                    "source": "AppSwitched"
                }
            ],
            "appswitched_data": [
                {
                    "timestamp": "2025-01-01T12:00:00",
                    "app_identifier": "test_app.exe",
                    "usage_count": 5,
                    "source": "AppSwitched"
                }
            ],
            "showjumpview_data": [
                {
                    "timestamp": "2025-01-01T12:01:00",
                    "app_identifier": "test_app2.exe",
                    "usage_count": 3,
                    "source": "ShowJumpView"
                }
            ],
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
            self.assertTrue(result_file.endswith('.html'))
            
            # Check file contents
            with open(result_file, 'r', encoding='utf-8') as f:
                content = f.read()
                self.assertIn("Windows FeatureUsage Extraction Report", content)
                self.assertIn("test_user", content)
                self.assertIn("test_app.exe", content)
    
    def test_export_results_custom_filename(self):
        """Test exporting with custom filename"""
        with tempfile.TemporaryDirectory() as temp_dir:
            custom_filename = "custom_test.html"
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
                self.assertTrue(result_file.endswith('.html'))
            finally:
                os.chdir(original_cwd)
    
    def test_export_results_file_write_error(self):
        """Test handling of file write errors"""
        with patch('builtins.open', mock_open()) as mock_file:
            mock_file.side_effect = OSError("Permission denied")
            
            result = self.exporter.export_results(self.sample_results)
            
            # Should return empty string on error
            self.assertEqual("", result)
    
    def test_generate_html_content(self):
        """Test HTML content generation"""
        content = self.exporter._generate_html_content(self.sample_results)
        
        # Check for essential HTML elements
        self.assertIn("<!DOCTYPE html>", content)
        self.assertIn("<html lang=\"en\">", content)
        self.assertIn("<head>", content)
        self.assertIn("<body>", content)
        self.assertIn("Windows FeatureUsage Extraction Report", content)
        
        # Check for data content
        self.assertIn("test_user", content)
        self.assertIn("test_app.exe", content)
        self.assertIn("AppSwitched", content)
        self.assertIn("ShowJumpView", content)
    
    def test_generate_chart_html_with_data(self):
        """Test chart generation with data"""
        chart_html = self.exporter._generate_chart_html(self.sample_results)
        
        # Should contain chart elements
        self.assertIn("chart-bar-container", chart_html)
        self.assertIn("AppSwitched", chart_html)
        self.assertIn("ShowJumpView", chart_html)
        self.assertIn("1", chart_html)  # Entry count
    
    def test_generate_chart_html_no_data(self):
        """Test chart generation with no data"""
        empty_results = {
            "appswitched_data": [],
            "showjumpview_data": [],
            "appbadgeupdated_data": [],
            "applaunch_data": [],
            "startmenu_data": [],
            "search_data": []
        }
        
        chart_html = self.exporter._generate_chart_html(empty_results)
        
        # Should contain no data message
        self.assertIn("No data available for chart", chart_html)
    
    def test_generate_table_sections(self):
        """Test table sections generation"""
        table_sections = self.exporter._generate_table_sections(self.sample_results)
        
        # Should contain table sections
        self.assertIn("table-section", table_sections)
        self.assertIn("FeatureUsage Data", table_sections)
        self.assertIn("AppSwitched Data", table_sections)
        self.assertIn("ShowJumpView Data", table_sections)
    
    def test_dicts_to_html_table_with_data(self):
        """Test converting dictionaries to HTML table with data"""
        test_data = [
            {"name": "test1", "value": 123},
            {"name": "test2", "value": 456}
        ]
        
        table_html = self.exporter._dicts_to_html_table(test_data, "Test Table", "test-table")
        
        # Should contain table elements
        self.assertIn("table-section", table_html)
        self.assertIn("Test Table", table_html)
        self.assertIn("test-table", table_html)
        self.assertIn("<table", table_html)
        self.assertIn("test1", table_html)
        self.assertIn("test2", table_html)
    
    def test_dicts_to_html_table_no_data(self):
        """Test converting dictionaries to HTML table with no data"""
        table_html = self.exporter._dicts_to_html_table([], "Empty Table", "empty-table")
        
        # Should contain no data message
        self.assertIn("No data found", table_html)
        self.assertIn("Empty Table", table_html)
    
    def test_get_css_styles(self):
        """Test CSS styles generation"""
        css = self.exporter._get_css_styles()
        
        # Should contain essential CSS
        self.assertIn("<style>", css)
        self.assertIn("body", css)
        self.assertIn("table", css)
        self.assertIn(".header-container", css)
        self.assertIn(".search-container", css)
    
    def test_get_javascript_code(self):
        """Test JavaScript code generation"""
        js = self.exporter._get_javascript_code()
        
        # Should contain essential JavaScript
        self.assertIn("<script>", js)
        self.assertIn("function toggleTable", js)
        self.assertIn("function searchData", js)
        self.assertIn("function clearSearch", js)
    
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
    
    def test_get_export_summary(self):
        """Test getting export summary"""
        summary = self.exporter.get_export_summary(self.sample_results)
        
        # Check required fields
        self.assertIn("export_time", summary)
        self.assertIn("total_entries", summary)
        self.assertIn("data_sources", summary)
        self.assertIn("extraction_info", summary)
        
        # Check data structure
        self.assertEqual(2, summary["total_entries"])
        self.assertIsInstance(summary["data_sources"], dict)
        self.assertIsInstance(summary["extraction_info"], dict)
    
    @patch('os.path.exists')
    @patch('builtins.open', new_callable=mock_open, read_data=b'<svg>test icon</svg>')
    def test_get_embedded_icon_success(self, mock_file, mock_exists):
        """Test successful icon embedding"""
        mock_exists.return_value = True
        
        icon_data = self.exporter._get_embedded_icon()
        
        # Should return base64 data URI
        self.assertTrue(icon_data.startswith("data:image/svg+xml;base64,"))
        # Decode base64 to check content
        import base64
        decoded = base64.b64decode(icon_data.split(',')[1]).decode('utf-8')
        self.assertIn("test icon", decoded)
    
    @patch('os.path.exists')
    def test_get_embedded_icon_not_found(self, mock_exists):
        """Test icon embedding when file not found"""
        mock_exists.return_value = False
        
        icon_data = self.exporter._get_embedded_icon()
        
        # Should return fallback icon
        self.assertTrue(icon_data.startswith("data:image/svg+xml;base64,"))
        # The fallback icon is base64 encoded, so we need to decode it to check for "circle"
        import base64
        decoded = base64.b64decode(icon_data.split(',')[1]).decode('utf-8')
        self.assertIn("circle", decoded)


if __name__ == '__main__':
    unittest.main()


