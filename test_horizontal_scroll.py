#!/usr/bin/env python3
"""
Test script to verify horizontal scrollbar functionality in HTML export.
"""

from featureusage.html_exporter import HTMLExporter
import tempfile
import os

def test_horizontal_scroll():
    """Test the horizontal scrollbar functionality."""
    print("Testing horizontal scrollbar functionality...")
    
    # Create test data with many columns to trigger horizontal scroll
    test_data = {
        "extraction_time": "2024-01-01T12:00:00",
        "current_user_sid": "Test User",
        "featureusage_data": [
            {
                "timestamp": "2024-01-01T12:00:00",
                "app_identifier": "test_app_1.exe",
                "usage_count": 5,
                "source": "AppSwitched",
                "value_name": "test_value_1",
                "value_type": "REG_DWORD",
                "raw_data_size": 4,
                "entry_type": "Executable",
                "executable_path": "C:\\Program Files\\Test App\\test_app_1.exe",
                "app_identifier_resolved": "Test Application 1",
                "additional_column_1": "This is a very long column name that should trigger horizontal scrolling",
                "additional_column_2": "Another long column name to ensure the table is wide enough",
                "additional_column_3": "Third long column for testing purposes",
                "additional_column_4": "Fourth long column to make the table even wider",
                "additional_column_5": "Fifth long column to ensure horizontal scrollbar appears"
            },
            {
                "timestamp": "2024-01-01T12:01:00",
                "app_identifier": "test_app_2.exe",
                "usage_count": 3,
                "source": "AppLaunch",
                "value_name": "test_value_2",
                "value_type": "REG_DWORD",
                "raw_data_size": 4,
                "entry_type": "Executable",
                "executable_path": "C:\\Program Files\\Test App\\test_app_2.exe",
                "app_identifier_resolved": "Test Application 2",
                "additional_column_1": "This is a very long column name that should trigger horizontal scrolling",
                "additional_column_2": "Another long column name to ensure the table is wide enough",
                "additional_column_3": "Third long column for testing purposes",
                "additional_column_4": "Fourth long column to make the table even wider",
                "additional_column_5": "Fifth long column to ensure horizontal scrollbar appears"
            }
        ],
        "appswitched_data": [],
        "showjumpview_data": [],
        "appbadgeupdated_data": [],
        "applaunch_data": [],
        "startmenu_data": [],
        "search_data": [],
        "total_entries": 2,
        "appswitched_entries": 0,
        "summary": {
            "appswitched_entries": 0,
            "startmenu_entries": 0,
            "search_entries": 0,
            "showjumpview_entries": 0,
            "appbadgeupdated_entries": 0,
            "applaunch_entries": 0,
            "total_appswitched_entries": 0
        }
    }
    
    # Create HTML exporter
    exporter = HTMLExporter()
    
    # Export to HTML
    html_file = exporter.export_results(test_data, "test_horizontal_scroll.html")
    
    if html_file and os.path.exists(html_file):
        print(f"✓ HTML file created successfully: {html_file}")
        
        # Check if the file contains the horizontal scrollbar CSS
        with open(html_file, 'r', encoding='utf-8') as f:
            content = f.read()
            
        print("\nVerifying horizontal scrollbar functionality:")
        
        if '.table-wrapper { overflow-x: scroll; max-width: 100%; }' in content:
            print("✓ Horizontal scrollbar CSS found in HTML")
        else:
            print("✗ Horizontal scrollbar CSS not found in HTML")
            
        if '.data-table { min-width: 1200px; }' in content:
            print("✓ Table minimum width CSS found in HTML")
        else:
            print("✗ Table minimum width CSS not found in HTML")
            
        if '<div class="table-wrapper">' in content:
            print("✓ Table wrapper div found in HTML")
        else:
            print("✗ Table wrapper div not found in HTML")
            
        print(f"\nYou can open {html_file} in a web browser to test the horizontal scrollbar functionality.")
        print("The table should have a horizontal scrollbar when the content is wider than the viewport.")
        
        # Keep the file for manual inspection
        print(f"\nHTML file location: {os.path.abspath(html_file)}")
        print("File size:", os.path.getsize(html_file), "bytes")
        
    else:
        print("✗ Failed to create HTML file")

if __name__ == "__main__":
    test_horizontal_scroll() 