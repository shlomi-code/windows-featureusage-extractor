#!/usr/bin/env python3
"""
Windows FeatureUsage Artifact Extractor

This script extracts FeatureUsage artifacts from the Windows registry
for the currently running user. Based on the information from:
https://medium.com/@boutnaru/the-windows-forensic-journey-featureusage-aed8f14c84ab

"""

import winreg
import json
import os
import sys
from datetime import datetime
from typing import Dict, List, Any, Optional
import struct


class FeatureUsageExtractor:
    """Extracts FeatureUsage artifacts from Windows registry."""
    
    def __init__(self):
        self.current_user_sid = self._get_current_user_sid()
        self.featureusage_path = f"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Explorer\\FeatureUsage\\AppSwitched"
        self.results = {
            "extraction_time": datetime.now().isoformat(),
            "current_user_sid": self.current_user_sid,
            "featureusage_data": []
        }
    
    def _get_current_user_sid(self) -> str:
        """Get the SID of the currently running user."""
        try:
            # Get current user SID from registry
            key = winreg.OpenKey(winreg.HKEY_CURRENT_USER, "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Explorer\\FeatureUsage\\AppSwitched")
            # The key itself contains the SID information
            return "Current User"
        except Exception as e:
            print(f"Warning: Could not determine current user SID: {e}")
            return "Unknown"
    
    def _read_registry_value(self, key_path: str, value_name: str = None) -> Optional[bytes]:
        """Read a registry value and return its data."""
        try:
            key = winreg.OpenKey(winreg.HKEY_CURRENT_USER, key_path)
            if value_name is None:
                # Read default value
                data, reg_type = winreg.QueryValueEx(key, "")
            else:
                data, reg_type = winreg.QueryValueEx(key, value_name)
            winreg.CloseKey(key)
            return data
        except Exception as e:
            print(f"Error reading registry value {key_path}\\{value_name}: {e}")
            return None
    
    def _parse_featureusage_data(self, data: bytes) -> List[Dict[str, Any]]:
        """Parse FeatureUsage binary data structure."""
        entries = []
        
        if not data or len(data) < 8:
            return entries
        
        try:
            # Skip header (first 8 bytes)
            offset = 8
            
            while offset < len(data):
                if offset + 16 > len(data):  # Need at least 16 bytes for entry
                    break
                
                # Parse entry structure (based on typical FeatureUsage format)
                # Each entry typically contains: timestamp, app_id, usage_count
                
                # Read timestamp (8 bytes, FILETIME format)
                if offset + 8 <= len(data):
                    timestamp_bytes = data[offset:offset + 8]
                    timestamp = struct.unpack('<Q', timestamp_bytes)[0]
                    
                    # Convert FILETIME to datetime
                    # FILETIME is number of 100-nanosecond intervals since January 1, 1601
                    windows_tick = timestamp / 10_000_000  # Convert to seconds
                    unix_timestamp = windows_tick - 11644473600  # Convert to Unix timestamp
                    
                    entry_time = datetime.fromtimestamp(unix_timestamp)
                    
                    offset += 8
                    
                    # Read app identifier (variable length, typically 4-8 bytes)
                    if offset + 4 <= len(data):
                        app_id_bytes = data[offset:offset + 4]
                        app_id = struct.unpack('<I', app_id_bytes)[0]
                        offset += 4
                        
                        # Read usage count (4 bytes)
                        if offset + 4 <= len(data):
                            usage_count_bytes = data[offset:offset + 4]
                            usage_count = struct.unpack('<I', usage_count_bytes)[0]
                            offset += 4
                            
                            entries.append({
                                "timestamp": entry_time.isoformat(),
                                "app_id": app_id,
                                "usage_count": usage_count,
                                "raw_timestamp": timestamp
                            })
                        else:
                            break
                    else:
                        break
                else:
                    break
                    
        except Exception as e:
            print(f"Error parsing FeatureUsage data: {e}")
        
        return entries
    
    def extract_appswitched_data(self) -> List[Dict[str, Any]]:
        """Extract AppSwitched FeatureUsage data."""
        print("Extracting AppSwitched FeatureUsage data...")
        
        try:
            # Open the AppSwitched registry key
            key = winreg.OpenKey(winreg.HKEY_CURRENT_USER, self.featureusage_path)
            
            entries = []
            
            # Enumerate all values in the key
            i = 0
            while True:
                try:
                    value_name, value_data, value_type = winreg.EnumValue(key, i)
                    
                    if value_type == winreg.REG_BINARY:
                        parsed_entries = self._parse_featureusage_data(value_data)
                        
                        for entry in parsed_entries:
                            entry["source"] = "AppSwitched"
                            entry["value_name"] = value_name
                            entry["value_type"] = "REG_BINARY"
                            entry["raw_data_size"] = len(value_data)
                        
                        entries.extend(parsed_entries)
                    
                    i += 1
                    
                except WindowsError:
                    # No more values
                    break
            
            winreg.CloseKey(key)
            return entries
            
        except Exception as e:
            print(f"Error extracting AppSwitched data: {e}")
            return []
    
    def extract_startmenu_data(self) -> List[Dict[str, Any]]:
        """Extract StartMenu FeatureUsage data."""
        print("Extracting StartMenu FeatureUsage data...")
        
        startmenu_path = "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Explorer\\FeatureUsage\\StartMenu"
        
        try:
            key = winreg.OpenKey(winreg.HKEY_CURRENT_USER, startmenu_path)
            
            entries = []
            
            # Enumerate all values in the key
            i = 0
            while True:
                try:
                    value_name, value_data, value_type = winreg.EnumValue(key, i)
                    
                    if value_type == winreg.REG_BINARY:
                        parsed_entries = self._parse_featureusage_data(value_data)
                        
                        for entry in parsed_entries:
                            entry["source"] = "StartMenu"
                            entry["value_name"] = value_name
                            entry["value_type"] = "REG_BINARY"
                            entry["raw_data_size"] = len(value_data)
                        
                        entries.extend(parsed_entries)
                    
                    i += 1
                    
                except WindowsError:
                    # No more values
                    break
            
            winreg.CloseKey(key)
            return entries
            
        except Exception as e:
            print(f"Error extracting StartMenu data: {e}")
            return []
    
    def extract_search_data(self) -> List[Dict[str, Any]]:
        """Extract Search FeatureUsage data."""
        print("Extracting Search FeatureUsage data...")
        
        search_path = "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Explorer\\FeatureUsage\\Search"
        
        try:
            key = winreg.OpenKey(winreg.HKEY_CURRENT_USER, search_path)
            
            entries = []
            
            # Enumerate all values in the key
            i = 0
            while True:
                try:
                    value_name, value_data, value_type = winreg.EnumValue(key, i)
                    
                    if value_type == winreg.REG_BINARY:
                        parsed_entries = self._parse_featureusage_data(value_data)
                        
                        for entry in parsed_entries:
                            entry["source"] = "Search"
                            entry["value_name"] = value_name
                            entry["value_type"] = "REG_BINARY"
                            entry["raw_data_size"] = len(value_data)
                        
                        entries.extend(parsed_entries)
                    
                    i += 1
                    
                except WindowsError:
                    # No more values
                    break
            
            winreg.CloseKey(key)
            return entries
            
        except Exception as e:
            print(f"Error extracting Search data: {e}")
            return []
    
    def extract_all_data(self) -> Dict[str, Any]:
        """Extract all FeatureUsage data from registry."""
        print("Starting FeatureUsage artifact extraction...")
        print(f"Current User SID: {self.current_user_sid}")
        print("-" * 50)
        
        # Extract data from different FeatureUsage sources
        appswitched_data = self.extract_appswitched_data()
        startmenu_data = self.extract_startmenu_data()
        search_data = self.extract_search_data()
        
        # Combine all data
        all_data = appswitched_data + startmenu_data + search_data
        
        # Sort by timestamp
        all_data.sort(key=lambda x: x.get("timestamp", ""))
        
        self.results["featureusage_data"] = all_data
        self.results["total_entries"] = len(all_data)
        self.results["summary"] = {
            "appswitched_entries": len(appswitched_data),
            "startmenu_entries": len(startmenu_data),
            "search_entries": len(search_data)
        }
        
        print(f"\nExtraction completed!")
        print(f"Total entries found: {len(all_data)}")
        print(f"AppSwitched entries: {len(appswitched_data)}")
        print(f"StartMenu entries: {len(startmenu_data)}")
        print(f"Search entries: {len(search_data)}")
        
        return self.results
    
    def save_results(self, filename: str = None) -> str:
        """Save extraction results to a JSON file."""
        if filename is None:
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            filename = f"featureusage_extraction_{timestamp}.json"
        
        try:
            with open(filename, 'w', encoding='utf-8') as f:
                json.dump(self.results, f, indent=2, ensure_ascii=False)
            
            print(f"\nResults saved to: {filename}")
            return filename
            
        except Exception as e:
            print(f"Error saving results: {e}")
            return ""
    
    def print_summary(self):
        """Print a summary of the extracted data."""
        if not self.results["featureusage_data"]:
            print("No FeatureUsage data found.")
            return
        
        print("\n" + "=" * 60)
        print("FEATUREUSAGE EXTRACTION SUMMARY")
        print("=" * 60)
        
        # Group by source
        sources = {}
        for entry in self.results["featureusage_data"]:
            source = entry.get("source", "Unknown")
            if source not in sources:
                sources[source] = []
            sources[source].append(entry)
        
        for source, entries in sources.items():
            print(f"\n{source} Entries ({len(entries)}):")
            print("-" * 40)
            
            # Show first few entries
            for i, entry in enumerate(entries[:5]):
                timestamp = entry.get("timestamp", "Unknown")
                app_id = entry.get("app_id", "Unknown")
                usage_count = entry.get("usage_count", "Unknown")
                print(f"  {i+1}. {timestamp} - App ID: {app_id}, Usage: {usage_count}")
            
            if len(entries) > 5:
                print(f"  ... and {len(entries) - 5} more entries")


def main():
    """Main function to run the FeatureUsage extraction."""
    print("Windows FeatureUsage Artifact Extractor")
    print("=" * 50)
    
    try:
        # Create extractor instance
        extractor = FeatureUsageExtractor()
        
        # Extract all data
        results = extractor.extract_all_data()
        
        # Print summary
        extractor.print_summary()
        
        # Save results
        output_file = extractor.save_results()
        
        if output_file:
            print(f"\nExtraction completed successfully!")
            print(f"Results saved to: {output_file}")
        else:
            print("\nExtraction completed but failed to save results.")
            
    except Exception as e:
        print(f"Error during extraction: {e}")
        sys.exit(1)


if __name__ == "__main__":
    main() 