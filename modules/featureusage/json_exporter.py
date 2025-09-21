#!/usr/bin/env python3
"""
JSON Exporter for Windows FeatureUsage Data

This module provides functionality to export FeatureUsage extraction results
to JSON format with proper formatting and error handling.
"""

import json
from datetime import datetime
from typing import Dict, Any, Optional


class JSONExporter:
    """Handles JSON export functionality for FeatureUsage extraction results."""
    
    def __init__(self):
        """Initialize the JSON exporter."""
        pass
    
    def export_results(self, results: Dict[str, Any], filename: Optional[str] = None, output_dir: str = ".") -> str:
        """
        Export extraction results to a JSON file.
        
        Args:
            results: Dictionary containing the extraction results
            filename: Optional filename for the output file
            output_dir: Directory to save the file (default: current directory)
            
        Returns:
            Filename of the saved JSON file or empty string if failed
        """
        if filename is None:
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            filename = f"featureusage_extraction_{timestamp}.json"
        
        # Ensure the output directory is used
        import os
        full_path = os.path.join(output_dir, filename)
        
        try:
            with open(full_path, 'w', encoding='utf-8') as f:
                json.dump(results, f, indent=2, ensure_ascii=False)
            
            print(f"\nResults saved to: {full_path}")
            return full_path
            
        except Exception as e:
            print(f"Error saving results: {e}")
            return ""
    
    def export_to_string(self, results: Dict[str, Any]) -> str:
        """
        Export results to a JSON string.
        
        Args:
            results: Dictionary containing the extraction results
            
        Returns:
            JSON string representation of the results
        """
        try:
            return json.dumps(results, indent=2, ensure_ascii=False)
        except Exception as e:
            print(f"Error converting results to JSON string: {e}")
            return ""
    
    def validate_results(self, results: Dict[str, Any]) -> bool:
        """
        Validate that the results dictionary contains required fields.
        
        Args:
            results: Dictionary containing the extraction results
            
        Returns:
            True if results are valid, False otherwise
        """
        required_fields = [
            "extraction_time",
            "current_user_sid",
            "featureusage_data",
            "appswitched_data",
            "showjumpview_data",
            "appbadgeupdated_data",
            "applaunch_data",
            "startmenu_data",
            "search_data"
        ]
        
        for field in required_fields:
            if field not in results:
                print(f"Warning: Missing required field '{field}' in results")
                return False
        
        return True
    
    def get_export_summary(self, results: Dict[str, Any]) -> Dict[str, Any]:
        """
        Generate a summary of the export data.
        
        Args:
            results: Dictionary containing the extraction results
            
        Returns:
            Dictionary containing export summary information
        """
        summary = {
            "export_time": datetime.now().isoformat(),
            "total_entries": results.get("total_entries", 0),
            "data_sources": {
                "appswitched_entries": len(results.get("appswitched_data", [])),
                "showjumpview_entries": len(results.get("showjumpview_data", [])),
                "appbadgeupdated_entries": len(results.get("appbadgeupdated_data", [])),
                "applaunch_entries": len(results.get("applaunch_data", [])),
                "startmenu_entries": len(results.get("startmenu_data", [])),
                "search_entries": len(results.get("search_data", []))
            },
            "extraction_info": {
                "extraction_time": results.get("extraction_time", ""),
                "current_user_sid": results.get("current_user_sid", "")
            }
        }
        
        return summary 