#!/usr/bin/env python3
"""
Windows FeatureUsage Artifact Extractor

This script extracts FeatureUsage artifacts from the Windows registry
for the currently running user. Based on the information from:
https://medium.com/@boutnaru/the-windows-forensic-journey-featureusage-aed8f14c84ab
https://medium.com/@boutnaru/the-windows-forensic-journey-appswitched-55abc690f0f0

Author: Windows FeatureUsage Analyzer
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
            "featureusage_data": [],
            "appswitched_data": [],
            "advanced_appswitched_data": []
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
    
    def _read_registry_value(self, key_path: str, value_name: Optional[str] = None) -> Optional[bytes]:
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
    
    def _parse_appswitched_advanced_data(self, data: bytes, value_name: str) -> List[Dict[str, Any]]:
        """Parse advanced AppSwitched data structure with more detailed information."""
        entries = []
        
        if not data or len(data) < 4:
            return entries
        
        try:
            # AppSwitched data structure may vary, try different parsing approaches
            offset = 0
            
            # Check if data starts with a count or header
            if len(data) >= 4:
                possible_count = struct.unpack('<I', data[offset:offset + 4])[0]
                offset += 4
                
                # If count seems reasonable, use it
                if 0 <= possible_count <= 10000:
                    entry_count = possible_count
                else:
                    # Reset and try different approach
                    offset = 0
                    entry_count = None
            
            # Parse entries
            while offset < len(data):
                if offset + 12 > len(data):  # Minimum entry size
                    break
                
                try:
                    # Read timestamp (8 bytes, FILETIME)
                    if offset + 8 <= len(data):
                        timestamp_bytes = data[offset:offset + 8]
                        timestamp = struct.unpack('<Q', timestamp_bytes)[0]
                        
                        # Convert FILETIME to datetime
                        windows_tick = timestamp / 10_000_000
                        unix_timestamp = windows_tick - 11644473600
                        entry_time = datetime.fromtimestamp(unix_timestamp)
                        
                        offset += 8
                        
                        # Read additional data (4 bytes - could be app ID, flags, etc.)
                        if offset + 4 <= len(data):
                            additional_data = struct.unpack('<I', data[offset:offset + 4])[0]
                            offset += 4
                            
                            entries.append({
                                "timestamp": entry_time.isoformat(),
                                "raw_timestamp": timestamp,
                                "additional_data": additional_data,
                                "value_name": value_name,
                                "data_offset": offset - 12
                            })
                        else:
                            break
                    else:
                        break
                        
                except Exception as e:
                    print(f"Error parsing AppSwitched entry at offset {offset}: {e}")
                    break
                    
        except Exception as e:
            print(f"Error parsing advanced AppSwitched data: {e}")
        
        return entries
    
    def _parse_dword_appswitched_data(self, value_name: str, value_data: int) -> Dict[str, Any]:
        """Parse DWORD AppSwitched data structure."""
        # DWORD values in AppSwitched typically represent usage counts or flags
        # The value name contains the application identifier
        # The value data contains the usage count or timestamp
        
        entry = {
            "timestamp": datetime.now().isoformat(),  # Current time as fallback
            "app_identifier": value_name,
            "usage_count": value_data,
            "raw_value": value_data,
            "value_type": "REG_DWORD"
        }
        
        # Try to extract timestamp from the value name if it contains one
        # Some AppSwitched entries may have timestamps embedded in the name
        if "PID" in value_name:
            # Process ID entry
            entry["entry_type"] = "Process_ID"
            try:
                pid = value_name.replace("*PID", "").replace("0000", "")
                entry["process_id"] = int(pid, 16) if pid else None
            except:
                entry["process_id"] = None
        elif "!" in value_name:
            # UWP app entry
            entry["entry_type"] = "UWP_App"
            entry["app_package"] = value_name
        elif value_name.endswith(".exe"):
            # Traditional executable
            entry["entry_type"] = "Executable"
            entry["executable_path"] = value_name
        else:
            # Other application identifier
            entry["entry_type"] = "Application"
            entry["app_name"] = value_name
        
        return entry
    
    def extract_appswitched_data(self) -> List[Dict[str, Any]]:
        """Extract AppSwitched FeatureUsage data."""
        print("Extracting AppSwitched FeatureUsage data...")
        
        try:
            # Open the AppSwitched registry key
            key = winreg.OpenKey(winreg.HKEY_CURRENT_USER, self.featureusage_path)
            
            entries = []
            
            # Get key information
            try:
                value_count, subkey_count, _ = winreg.QueryInfoKey(key)
                print(f"  Registry key info: {value_count} values, {subkey_count} subkeys")
            except Exception as e:
                print(f"  Warning: Could not get key info: {e}")
                value_count = 0
            
            if value_count == 0:
                print("  ⚠️  No values found in AppSwitched registry key")
                print("  This could be due to:")
                print("    - FeatureUsage being disabled")
                print("    - No recent application switching activity")
                print("    - Windows version differences")
                print("    - Data stored in alternative locations")
            
            # Enumerate all values in the key
            i = 0
            while True:
                try:
                    value_name, value_data, value_type = winreg.EnumValue(key, i)
                    
                    print(f"  Found value: {value_name} (type: {value_type}, size: {len(value_data) if isinstance(value_data, bytes) else len(str(value_data))})")
                    
                    if value_type == winreg.REG_BINARY:
                        parsed_entries = self._parse_featureusage_data(value_data)
                        
                        for entry in parsed_entries:
                            entry["source"] = "AppSwitched"
                            entry["value_name"] = value_name
                            entry["value_type"] = "REG_BINARY"
                            entry["raw_data_size"] = len(value_data)
                        
                        entries.extend(parsed_entries)
                        print(f"    Parsed {len(parsed_entries)} entries from binary data")
                    
                    elif value_type == winreg.REG_DWORD:
                        # Handle DWORD values (this is what we're actually seeing)
                        if isinstance(value_data, int):
                            parsed_entry = self._parse_dword_appswitched_data(value_name, value_data)
                            parsed_entry["source"] = "AppSwitched"
                            parsed_entry["value_name"] = value_name
                            parsed_entry["raw_data_size"] = 4  # DWORD is 4 bytes
                            
                            entries.append(parsed_entry)
                            print(f"    Parsed DWORD entry: {parsed_entry['entry_type']} - {parsed_entry['app_identifier']}")
                        else:
                            print(f"    Warning: DWORD value is not an integer: {type(value_data)}")
                    
                    else:
                        print(f"    Skipping non-binary/non-dword value (type: {value_type})")
                    
                    i += 1
                    
                except WindowsError:
                    # No more values
                    break
            
            winreg.CloseKey(key)
            
            if not entries:
                print("  ℹ️  No AppSwitched data extracted - checking alternative sources...")
            else:
                print(f"  ✓ Successfully extracted {len(entries)} AppSwitched entries")
            
            return entries
            
        except Exception as e:
            print(f"Error extracting AppSwitched data: {e}")
            return []
    
    def extract_appswitched_advanced(self) -> List[Dict[str, Any]]:
        """Extract advanced AppSwitched data with detailed analysis."""
        print("Extracting advanced AppSwitched data...")
        
        advanced_entries = []
        
        # Additional AppSwitched-related registry locations
        appswitched_locations = [
            "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Explorer\\FeatureUsage\\AppSwitched",
            "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Explorer\\Advanced\\People",
            "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Explorer\\Advanced\\TaskbarAl"
        ]
        
        for location in appswitched_locations:
            try:
                key = winreg.OpenKey(winreg.HKEY_CURRENT_USER, location)
                
                # Enumerate all values
                i = 0
                while True:
                    try:
                        value_name, value_data, value_type = winreg.EnumValue(key, i)
                        
                        if value_type == winreg.REG_BINARY:
                            parsed_entries = self._parse_appswitched_advanced_data(value_data, value_name)
                            
                            for entry in parsed_entries:
                                entry["source"] = "AppSwitched_Advanced"
                                entry["registry_location"] = location
                                entry["value_type"] = "REG_BINARY"
                                entry["raw_data_size"] = len(value_data)
                            
                            advanced_entries.extend(parsed_entries)
                        
                        i += 1
                        
                    except WindowsError:
                        break
                
                winreg.CloseKey(key)
                
            except Exception as e:
                print(f"Error accessing {location}: {e}")
        
        return advanced_entries
    
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
    
    def extract_taskbar_data(self) -> List[Dict[str, Any]]:
        """Extract Taskbar-related AppSwitched data."""
        print("Extracting Taskbar AppSwitched data...")
        
        taskbar_locations = [
            "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Explorer\\Advanced\\People",
            "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Explorer\\Advanced\\TaskbarAl"
        ]
        
        entries = []
        
        for location in taskbar_locations:
            try:
                key = winreg.OpenKey(winreg.HKEY_CURRENT_USER, location)
                
                # Enumerate all values
                i = 0
                while True:
                    try:
                        value_name, value_data, value_type = winreg.EnumValue(key, i)
                        
                        if value_type == winreg.REG_BINARY:
                            parsed_entries = self._parse_appswitched_advanced_data(value_data, value_name)
                            
                            for entry in parsed_entries:
                                entry["source"] = "Taskbar_AppSwitched"
                                entry["registry_location"] = location
                                entry["value_type"] = "REG_BINARY"
                                entry["raw_data_size"] = len(value_data)
                            
                            entries.extend(parsed_entries)
                        
                        i += 1
                        
                    except WindowsError:
                        break
                
                winreg.CloseKey(key)
                
            except Exception as e:
                print(f"Error accessing {location}: {e}")
        
        return entries
    
    def extract_all_data(self) -> Dict[str, Any]:
        """Extract all FeatureUsage data from registry."""
        print("Starting FeatureUsage artifact extraction...")
        print(f"Current User SID: {self.current_user_sid}")
        print("-" * 50)
        
        # Extract data from different FeatureUsage sources
        appswitched_data = self.extract_appswitched_data()
        appswitched_advanced_data = self.extract_appswitched_advanced()
        startmenu_data = self.extract_startmenu_data()
        search_data = self.extract_search_data()
        taskbar_data = self.extract_taskbar_data()
        
        # Check for alternative sources if no AppSwitched data found
        if not appswitched_data and not appswitched_advanced_data and not taskbar_data:
            print("\nNo AppSwitched data found - checking alternative sources...")
            alternative_sources = self.check_alternative_appswitched_sources()
            
            if not alternative_sources:
                print("\nNo alternative AppSwitched sources found.")
                self.provide_test_data_suggestions()
        
        # Combine all data
        all_data = appswitched_data + startmenu_data + search_data
        all_appswitched_data = appswitched_data + appswitched_advanced_data + taskbar_data
        
        # Sort by timestamp
        all_data.sort(key=lambda x: x.get("timestamp", ""))
        all_appswitched_data.sort(key=lambda x: x.get("timestamp", ""))
        
        self.results["featureusage_data"] = all_data
        self.results["appswitched_data"] = all_appswitched_data
        self.results["advanced_appswitched_data"] = appswitched_advanced_data + taskbar_data
        self.results["total_entries"] = len(all_data)
        self.results["appswitched_entries"] = len(all_appswitched_data)
        self.results["summary"] = {
            "appswitched_entries": len(appswitched_data),
            "appswitched_advanced_entries": len(appswitched_advanced_data),
            "taskbar_entries": len(taskbar_data),
            "startmenu_entries": len(startmenu_data),
            "search_entries": len(search_data),
            "total_appswitched_entries": len(all_appswitched_data)
        }
        
        print(f"\nExtraction completed!")
        print(f"Total entries found: {len(all_data)}")
        print(f"AppSwitched entries: {len(appswitched_data)}")
        print(f"Advanced AppSwitched entries: {len(appswitched_advanced_data)}")
        print(f"Taskbar AppSwitched entries: {len(taskbar_data)}")
        print(f"StartMenu entries: {len(startmenu_data)}")
        print(f"Search entries: {len(search_data)}")
        print(f"Total AppSwitched-related entries: {len(all_appswitched_data)}")
        
        # Provide additional feedback if no AppSwitched data
        if len(all_appswitched_data) == 0:
            print("\n⚠️  No AppSwitched data was found.")
            print("This is normal if:")
            print("  - FeatureUsage is disabled")
            print("  - No recent application switching has occurred")
            print("  - Windows version differences in data storage")
            print("  - Privacy settings prevent data collection")
        
        return self.results
    
    def save_results(self, filename: Optional[str] = None) -> str:
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
        
        # Special AppSwitched summary
        if self.results["appswitched_data"]:
            print(f"\n" + "=" * 60)
            print("APPSWITCHED DETAILED SUMMARY")
            print("=" * 60)
            
            appswitched_sources = {}
            for entry in self.results["appswitched_data"]:
                source = entry.get("source", "Unknown")
                if source not in appswitched_sources:
                    appswitched_sources[source] = []
                appswitched_sources[source].append(entry)
            
            for source, entries in appswitched_sources.items():
                print(f"\n{source} Entries ({len(entries)}):")
                print("-" * 40)
                
                # Show first few entries
                for i, entry in enumerate(entries[:3]):
                    timestamp = entry.get("timestamp", "Unknown")
                    app_id = entry.get("app_id", "N/A")
                    additional_data = entry.get("additional_data", "N/A")
                    print(f"  {i+1}. {timestamp} - App ID: {app_id}, Additional: {additional_data}")
                
                if len(entries) > 3:
                    print(f"  ... and {len(entries) - 3} more entries")
    
    def check_alternative_appswitched_sources(self) -> List[Dict[str, Any]]:
        """Check for alternative AppSwitched data sources."""
        print("Checking alternative AppSwitched data sources...")
        
        alternative_sources = [
            "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Explorer\\FeatureUsage\\AppSwitched\\Settings",
            "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Explorer\\FeatureUsage\\AppSwitched\\Data",
            "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Explorer\\FeatureUsage\\AppSwitched\\History",
            "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Explorer\\FeatureUsage\\AppSwitched\\Usage",
            "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Explorer\\FeatureUsage\\AppSwitched\\Stats",
            "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Explorer\\FeatureUsage\\AppSwitched\\Log",
            "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Explorer\\FeatureUsage\\AppSwitched\\Cache",
            "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Explorer\\FeatureUsage\\AppSwitched\\*",
            "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Explorer\\FeatureUsage\\AppSwitched\\",
            "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Explorer\\FeatureUsage\\AppSwitched\\Default",
            "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Explorer\\FeatureUsage\\AppSwitched\\Current",
            "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Explorer\\FeatureUsage\\AppSwitched\\Recent",
            "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Explorer\\FeatureUsage\\AppSwitched\\Active",
            "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Explorer\\FeatureUsage\\AppSwitched\\Session",
            "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Explorer\\FeatureUsage\\AppSwitched\\User",
            "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Explorer\\FeatureUsage\\AppSwitched\\System",
            "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Explorer\\FeatureUsage\\AppSwitched\\Process",
            "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Explorer\\FeatureUsage\\AppSwitched\\Window",
            "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Explorer\\FeatureUsage\\AppSwitched\\Focus",
            "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Explorer\\FeatureUsage\\AppSwitched\\Switch"
        ]
        
        found_sources = []
        
        for source in alternative_sources:
            try:
                key = winreg.OpenKey(winreg.HKEY_CURRENT_USER, source)
                
                # Get key information
                try:
                    value_count, subkey_count, _ = winreg.QueryInfoKey(key)
                    if value_count > 0 or subkey_count > 0:
                        print(f"  ✓ Found alternative source: {source}")
                        print(f"    Values: {value_count}, Subkeys: {subkey_count}")
                        found_sources.append({
                            "path": source,
                            "value_count": value_count,
                            "subkey_count": subkey_count
                        })
                except Exception as e:
                    print(f"  Warning: Could not get info for {source}: {e}")
                
                winreg.CloseKey(key)
                
            except Exception:
                # Key doesn't exist or can't be accessed
                pass
        
        if not found_sources:
            print("  ℹ️  No alternative AppSwitched sources found")
        
        return found_sources
    
    def provide_test_data_suggestions(self):
        """Provide suggestions for generating test AppSwitched data."""
        print("\n" + "=" * 60)
        print("SUGGESTIONS FOR GENERATING APPSWITCHED DATA")
        print("=" * 60)
        print("To generate AppSwitched data for testing:")
        print()
        print("1. Enable FeatureUsage (if disabled):")
        print("   - Open Registry Editor (regedit)")
        print("   - Navigate to: HKCU\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Explorer\\Advanced")
        print("   - Look for 'EnableFeatureUsage' or similar keys")
        print("   - Set to 1 if found and set to 0")
        print()
        print("2. Perform application switching activities:")
        print("   - Open multiple applications (Notepad, Calculator, etc.)")
        print("   - Use Alt+Tab to switch between applications")
        print("   - Use Task View (Win+Tab)")
        print("   - Click on different applications in the taskbar")
        print("   - Use Windows key to open Start Menu and launch apps")
        print()
        print("3. Wait for data collection:")
        print("   - Windows may take some time to collect and store the data")
        print("   - Try switching between apps for 5-10 minutes")
        print("   - Restart applications and switch again")
        print()
        print("4. Check for data in other locations:")
        print("   - Some Windows versions store data in different registry paths")
        print("   - Check HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Explorer\\FeatureUsage")
        print("   - Look for user-specific SID subkeys")
        print()
        print("5. Alternative data sources:")
        print("   - Check Event Logs for application switching events")
        print("   - Look in Windows Timeline data")
        print("   - Check UserAssist registry keys")
        print("   - Examine Jump Lists data")
        print()
        print("6. Windows version considerations:")
        print("   - FeatureUsage behavior varies between Windows versions")
        print("   - Windows 10/11 may store data differently than older versions")
        print("   - Some features may be disabled by default in certain editions")
        print()
        print("7. Group Policy settings:")
        print("   - Check if FeatureUsage is disabled by Group Policy")
        print("   - Look for 'Turn off feature usage data collection' setting")
        print("   - May be in: Computer Configuration > Administrative Templates > Windows Components > Data Collection and Preview Builds")
        print()
        print("8. Privacy settings:")
        print("   - Check Windows Privacy settings")
        print("   - Ensure 'Let Windows collect my activities from this PC' is enabled")
        print("   - Check 'Activity history' settings")
        print()
        print("After performing these activities, run the extractor again to see if data appears.")
        print("=" * 60)

    def export_to_html(self, filename: str = None) -> str:
        """Export the extraction results to an HTML file with tables."""
        if filename is None:
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            filename = f"featureusage_extraction_{timestamp}.html"

        def dicts_to_html_table(dicts, title):
            if not dicts:
                return f'<h2>{title}</h2><p>No data found.</p>'
            headers = sorted({k for d in dicts for k in d.keys()})
            html = [f'<h2>{title}</h2>', '<table border="1" cellspacing="0" cellpadding="4">']
            html.append('<tr>' + ''.join(f'<th>{h}</th>' for h in headers) + '</tr>')
            for d in dicts:
                html.append('<tr>' + ''.join(f'<td>{d.get(h, "")}</td>' for h in headers) + '</tr>')
            html.append('</table>')
            return '\n'.join(html)

        html_parts = [
            '<!DOCTYPE html>',
            '<html lang="en">',
            '<head>',
            '<meta charset="UTF-8">',
            '<title>Windows FeatureUsage Extraction Report</title>',
            '<style>body{font-family:sans-serif;}table{border-collapse:collapse;}th,td{padding:4px 8px;}th{background:#eee;}</style>',
            '</head>',
            '<body>',
            f'<h1>Windows FeatureUsage Extraction Report</h1>',
            f'<p>Extraction time: {self.results.get("extraction_time", "")}</p>',
            f'<p>Current User SID: {self.results.get("current_user_sid", "")}</p>',
            f'<p>Total entries: {self.results.get("total_entries", 0)}</p>',
            f'<p>Summary: {self.results.get("summary", {})}</p>',
        ]
        html_parts.append(dicts_to_html_table(self.results.get("featureusage_data", []), "FeatureUsage Data"))
        html_parts.append(dicts_to_html_table(self.results.get("appswitched_data", []), "AppSwitched Data (All)") )
        html_parts.append(dicts_to_html_table(self.results.get("advanced_appswitched_data", []), "Advanced AppSwitched Data"))
        html_parts.append('</body></html>')

        html_content = '\n'.join(html_parts)
        try:
            with open(filename, 'w', encoding='utf-8') as f:
                f.write(html_content)
            print(f"\nHTML report saved to: {filename}")
            return filename
        except Exception as e:
            print(f"Error saving HTML report: {e}")
            return ""


def main():
    """Main function to run the FeatureUsage extraction."""
    print("Windows FeatureUsage Artifact Extractor")
    print("Enhanced with Advanced AppSwitched Support")
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
        
        # Export to HTML
        html_file = extractor.export_to_html()
        
        if output_file:
            print(f"\nExtraction completed successfully!")
            print(f"Results saved to: {output_file}")
        else:
            print("\nExtraction completed but failed to save results.")
        if html_file:
            print(f"HTML report saved to: {html_file}")
        else:
            print("Failed to save HTML report.")
        
    except Exception as e:
        print(f"Error during extraction: {e}")
        sys.exit(1)


if __name__ == "__main__":
    main() 