#!/usr/bin/env python3
"""
Windows FeatureUsage Artifact Extractor

This script extracts FeatureUsage artifacts from the Windows registry
for the currently running user. Based on the information from:
https://medium.com/@boutnaru/the-windows-forensic-journey-featureusage-aed8f14c84ab
https://medium.com/@boutnaru/the-windows-forensic-journey-appswitched-55abc690f0f0
https://medium.com/@boutnaru/the-windows-forensic-journey-showjumpview-ec24a17ecaf0
https://medium.com/@boutnaru/the-windows-forensic-journey-applaunch-617c0635e126

Author: Windows FeatureUsage Analyzer
"""

import winreg
import json
import os
import sys
from datetime import datetime
from typing import Dict, List, Any, Optional
import struct
import argparse

# Import the GUID resolver
from featureusage.guid_resolver import GUIDResolver


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
            "advanced_appswitched_data": [],
            "showjumpview_data": [],
            "appbadgeupdated_data": [],
            "applaunch_data": [],
            "startmenu_data": [],
            "search_data": []
        }
        # Initialize GUID resolver
        self.guid_resolver = GUIDResolver()
    
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
    
    def extract_showjumpview_data(self) -> List[Dict[str, Any]]:
        """Extract ShowJumpView FeatureUsage data."""
        print("Extracting ShowJumpView FeatureUsage data...")
        showjumpview_path = "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Explorer\\FeatureUsage\\ShowJumpView"
        entries = []
        try:
            key = winreg.OpenKey(winreg.HKEY_CURRENT_USER, showjumpview_path)
            try:
                value_count, subkey_count, _ = winreg.QueryInfoKey(key)
                print(f"  Registry key info: {value_count} values, {subkey_count} subkeys")
            except Exception as e:
                print(f"  Warning: Could not get key info: {e}")
                value_count = 0
            if value_count == 0:
                print("  ⚠️  No values found in ShowJumpView registry key")
            i = 0
            while True:
                try:
                    value_name, value_data, value_type = winreg.EnumValue(key, i)
                    print(f"  Found value: {value_name} (type: {value_type}, size: {len(value_data) if isinstance(value_data, bytes) else len(str(value_data))})")
                    if value_type == winreg.REG_DWORD and isinstance(value_data, int):
                        entry = {
                            "timestamp": datetime.now().isoformat(),
                            "app_identifier": value_name,
                            "usage_count": value_data,
                            "raw_value": value_data,
                            "value_type": "REG_DWORD",
                            "source": "ShowJumpView",
                            "value_name": value_name,
                            "raw_data_size": 4
                        }
                        if value_name.endswith(".exe"):
                            entry["entry_type"] = "Executable"
                            entry["executable_path"] = value_name
                        elif "!" in value_name:
                            entry["entry_type"] = "UWP_App"
                            entry["app_package"] = value_name
                        else:
                            entry["entry_type"] = "Application"
                            entry["app_name"] = value_name
                        entries.append(entry)
                        print(f"    Parsed DWORD entry: {entry['entry_type']} - {entry['app_identifier']}")
                    else:
                        print(f"    Skipping non-dword value (type: {value_type})")
                    i += 1
                except WindowsError:
                    break
            winreg.CloseKey(key)
            if not entries:
                print("  ℹ️  No ShowJumpView data extracted.")
            else:
                print(f"  ✓ Successfully extracted {len(entries)} ShowJumpView entries")
            return entries
        except Exception as e:
            print(f"Error extracting ShowJumpView data: {e}")
            return []
    
    def extract_appbadgeupdated_data(self) -> List[Dict[str, Any]]:
        """Extract AppBadgeUpdated FeatureUsage data."""
        print("Extracting AppBadgeUpdated FeatureUsage data...")
        appbadgeupdated_path = "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Explorer\\FeatureUsage\\AppBadgeUpdated"
        entries = []
        try:
            key = winreg.OpenKey(winreg.HKEY_CURRENT_USER, appbadgeupdated_path)
            try:
                value_count, subkey_count, _ = winreg.QueryInfoKey(key)
                print(f"  Registry key info: {value_count} values, {subkey_count} subkeys")
            except Exception as e:
                print(f"  Warning: Could not get key info: {e}")
                value_count = 0
            if value_count == 0:
                print("  ⚠️  No values found in AppBadgeUpdated registry key")
            i = 0
            while True:
                try:
                    value_name, value_data, value_type = winreg.EnumValue(key, i)
                    print(f"  Found value: {value_name} (type: {value_type}, size: {len(value_data) if isinstance(value_data, bytes) else len(str(value_data))})")
                    if value_type == winreg.REG_DWORD and isinstance(value_data, int):
                        entry = {
                            "timestamp": datetime.now().isoformat(),
                            "app_identifier": value_name,
                            "badge_count": value_data,
                            "raw_value": value_data,
                            "value_type": "REG_DWORD",
                            "source": "AppBadgeUpdated",
                            "value_name": value_name,
                            "raw_data_size": 4
                        }
                        if value_name.endswith(".exe"):
                            entry["entry_type"] = "Executable"
                            entry["executable_path"] = value_name
                        elif "!" in value_name:
                            entry["entry_type"] = "UWP_App"
                            entry["app_package"] = value_name
                        elif "PID" in value_name:
                            entry["entry_type"] = "Process_ID"
                            try:
                                pid = value_name.replace("*PID", "").replace("0000", "")
                                entry["process_id"] = int(pid, 16) if pid else None
                            except:
                                entry["process_id"] = None
                        else:
                            entry["entry_type"] = "Application"
                            entry["app_name"] = value_name
                        entries.append(entry)
                        print(f"    Parsed DWORD entry: {entry['entry_type']} - {entry['app_identifier']} (Badge: {entry['badge_count']})")
                    else:
                        print(f"    Skipping non-dword value (type: {value_type})")
                    i += 1
                except WindowsError:
                    break
            winreg.CloseKey(key)
            if not entries:
                print("  ℹ️  No AppBadgeUpdated data extracted.")
            else:
                print(f"  ✓ Successfully extracted {len(entries)} AppBadgeUpdated entries")
            return entries
        except Exception as e:
            print(f"Error extracting AppBadgeUpdated data: {e}")
            return []
    
    def extract_applaunch_data(self) -> List[Dict[str, Any]]:
        """Extract AppLaunch FeatureUsage data."""
        print("Extracting AppLaunch FeatureUsage data...")
        applaunch_path = "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Explorer\\FeatureUsage\\AppLaunch"
        entries = []
        try:
            key = winreg.OpenKey(winreg.HKEY_CURRENT_USER, applaunch_path)
            try:
                value_count, subkey_count, _ = winreg.QueryInfoKey(key)
                print(f"  Registry key info: {value_count} values, {subkey_count} subkeys")
            except Exception as e:
                print(f"  Warning: Could not get key info: {e}")
                value_count = 0
            if value_count == 0:
                print("  ⚠️  No values found in AppLaunch registry key")
            i = 0
            while True:
                try:
                    value_name, value_data, value_type = winreg.EnumValue(key, i)
                    print(f"  Found value: {value_name} (type: {value_type}, size: {len(value_data) if isinstance(value_data, bytes) else len(str(value_data))})")
                    if value_type == winreg.REG_DWORD and isinstance(value_data, int):
                        entry = {
                            "timestamp": datetime.now().isoformat(),
                            "app_identifier": value_name,
                            "launch_count": value_data,
                            "raw_value": value_data,
                            "value_type": "REG_DWORD",
                            "source": "AppLaunch",
                            "value_name": value_name,
                            "raw_data_size": 4
                        }
                        if value_name.endswith(".exe"):
                            entry["entry_type"] = "Executable"
                            entry["executable_path"] = value_name
                        elif "!" in value_name:
                            entry["entry_type"] = "UWP_App"
                            entry["app_package"] = value_name
                        elif "PID" in value_name:
                            entry["entry_type"] = "Process_ID"
                            try:
                                pid = value_name.replace("*PID", "").replace("0000", "")
                                entry["process_id"] = int(pid, 16) if pid else None
                            except:
                                entry["process_id"] = None
                        else:
                            entry["entry_type"] = "Application"
                            entry["app_name"] = value_name
                        entries.append(entry)
                        print(f"    Parsed DWORD entry: {entry['entry_type']} - {entry['app_identifier']} (Launches: {entry['launch_count']})")
                    else:
                        print(f"    Skipping non-dword value (type: {value_type})")
                    i += 1
                except WindowsError:
                    break
            winreg.CloseKey(key)
            if not entries:
                print("  ℹ️  No AppLaunch data extracted.")
            else:
                print(f"  ✓ Successfully extracted {len(entries)} AppLaunch entries")
            return entries
        except Exception as e:
            print(f"Error extracting AppLaunch data: {e}")
            return []
    
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
        showjumpview_data = self.extract_showjumpview_data()
        appbadgeupdated_data = self.extract_appbadgeupdated_data()
        applaunch_data = self.extract_applaunch_data()
        
        # Check for alternative sources if no AppSwitched data found
        if not appswitched_data and not appswitched_advanced_data and not taskbar_data:
            print("\nNo AppSwitched data found - checking alternative sources...")
            alternative_sources = self.check_alternative_appswitched_sources()
            
            if not alternative_sources:
                print("\nNo alternative AppSwitched sources found.")
                self.provide_test_data_suggestions()
        
        # Combine all data
        all_data = appswitched_data + startmenu_data + search_data + showjumpview_data + appbadgeupdated_data + applaunch_data
        all_appswitched_data = appswitched_data + appswitched_advanced_data + taskbar_data
        
        # Sort by timestamp
        all_data.sort(key=lambda x: x.get("timestamp", ""))
        all_appswitched_data.sort(key=lambda x: x.get("timestamp", ""))
        
        # Resolve GUIDs in all extracted data
        print("\nResolving Windows Known Folder GUIDs...")
        resolved_all_data = self._resolve_guids_in_data(all_data)
        resolved_all_appswitched_data = self._resolve_guids_in_data(all_appswitched_data)
        resolved_appswitched_advanced_data = self._resolve_guids_in_data(appswitched_advanced_data + taskbar_data)
        resolved_showjumpview_data = self._resolve_guids_in_data(showjumpview_data)
        resolved_appbadgeupdated_data = self._resolve_guids_in_data(appbadgeupdated_data)
        resolved_applaunch_data = self._resolve_guids_in_data(applaunch_data)
        
        self.results["featureusage_data"] = resolved_all_data
        self.results["appswitched_data"] = resolved_all_appswitched_data
        self.results["advanced_appswitched_data"] = resolved_appswitched_advanced_data
        self.results["showjumpview_data"] = resolved_showjumpview_data
        self.results["appbadgeupdated_data"] = resolved_appbadgeupdated_data
        self.results["applaunch_data"] = resolved_applaunch_data
        self.results["total_entries"] = len(resolved_all_data)
        self.results["appswitched_entries"] = len(resolved_all_appswitched_data)
        self.results["summary"] = {
            "appswitched_entries": len(appswitched_data),
            "appswitched_advanced_entries": len(appswitched_advanced_data),
            "taskbar_entries": len(taskbar_data),
            "startmenu_entries": len(startmenu_data),
            "search_entries": len(search_data),
            "showjumpview_entries": len(showjumpview_data),
            "appbadgeupdated_entries": len(appbadgeupdated_data),
            "applaunch_entries": len(applaunch_data),
            "total_appswitched_entries": len(resolved_all_appswitched_data)
        }
        
        print(f"\nExtraction completed!")
        print(f"Total entries found: {len(resolved_all_data)}")
        print(f"AppSwitched entries: {len(appswitched_data)}")
        print(f"Advanced AppSwitched entries: {len(appswitched_advanced_data)}")
        print(f"Taskbar AppSwitched entries: {len(taskbar_data)}")
        print(f"StartMenu entries: {len(startmenu_data)}")
        print(f"Search entries: {len(search_data)}")
        print(f"ShowJumpView entries: {len(showjumpview_data)}")
        print(f"AppBadgeUpdated entries: {len(appbadgeupdated_data)}")
        print(f"AppLaunch entries: {len(applaunch_data)}")
        print(f"Total AppSwitched-related entries: {len(resolved_all_appswitched_data)}")
        
        # Provide additional feedback if no AppSwitched data
        if len(resolved_all_appswitched_data) == 0:
            print("\n⚠️  No AppSwitched data was found.")
            print("This is normal if:")
            print("  - FeatureUsage is disabled")
            print("  - No recent application switching has occurred")
            print("  - Windows version differences in data storage")
            print("  - Privacy settings prevent data collection")
        
        return self.results
    
    def _resolve_guids_in_data(self, data_list: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """
        Resolve Windows Known Folder GUIDs in the extracted data.
        Creates app_identifier_resolved column while keeping app_identifier unchanged.
        
        Args:
            data_list: List of dictionaries containing extracted data
            
        Returns:
            List of dictionaries with resolved GUIDs in new app_identifier_resolved column
        """
        resolved_data = []
        
        for entry in data_list:
            resolved_entry = entry.copy()  # Copy all original data
            
            # Check if app_identifier exists and create app_identifier_resolved
            if "app_identifier" in entry:
                original_app_identifier = entry["app_identifier"]
                
                # Check if the app_identifier contains a GUID pattern
                if isinstance(original_app_identifier, str) and "{" in original_app_identifier and "}" in original_app_identifier:
                    # Replace GUIDs in the app_identifier with their resolved values
                    resolved_app_identifier = self.guid_resolver.replace_guid_with_resolved(original_app_identifier)
                    resolved_entry["app_identifier_resolved"] = resolved_app_identifier
                else:
                    # No GUID pattern found, keep the same value
                    resolved_entry["app_identifier_resolved"] = original_app_identifier
            
            resolved_data.append(resolved_entry)
        
        return resolved_data
    
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
                app_id = entry.get("app_identifier", "Unknown")
                # Handle different field names for different sources
                if source == "AppLaunch":
                    usage_count = entry.get("launch_count", "Unknown")
                elif source == "AppBadgeUpdated":
                    usage_count = entry.get("badge_count", "Unknown")
                else:
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

    def export_to_html(self, filename: Optional[str] = None) -> str:
        """Export the extraction results to an HTML file with tables and search functionality."""
        if filename is None:
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            filename = f"featureusage_extraction_{timestamp}.html"

        def dicts_to_html_table(dicts, title, table_id):
            if not dicts:
                return f'''
                <div class="table-section">
                    <div class="table-header" onclick="toggleTable('{table_id}')">
                        <span class="toggle-icon">▶</span> {title} <span class="entry-count">(No data found)</span>
                    </div>
                    <div id="{table_id}-content" class="table-content collapsed">
                        <p>No data found.</p>
                    </div>
                </div>'''
            
            headers = sorted({k for d in dicts for k in d.keys()})
            table_html = f'''
                <div class="table-section">
                    <div class="table-header" onclick="toggleTable('{table_id}')">
                        <span class="toggle-icon">▶</span> {title} <span class="entry-count">({len(dicts)} entries)</span>
                    </div>
                    <div id="{table_id}-content" class="table-content collapsed">
                        <table id="{table_id}" border="1" cellspacing="0" cellpadding="4" class="data-table">
                            <tr>'''
            
            for h in headers:
                table_html += f'<th>{h}</th>'
            table_html += '</tr>'
            
            for d in dicts:
                table_html += '<tr>'
                for h in headers:
                    value = d.get(h, "")
                    table_html += f'<td>{value}</td>'
                table_html += '</tr>'
            
            table_html += '''
                        </table>
                    </div>
                </div>'''
            return table_html

        # Prepare chart data
        chart_data = [
            ("AppSwitched", len(self.results.get("appswitched_data", []))),
            ("Advanced AppSwitched", len(self.results.get("advanced_appswitched_data", []))),
            ("ShowJumpView", len(self.results.get("showjumpview_data", []))),
            ("AppBadgeUpdated", len(self.results.get("appbadgeupdated_data", []))),
            ("AppLaunch", len(self.results.get("applaunch_data", []))),
            ("StartMenu", len(self.results.get("startmenu_data", []))),
            ("Search", len(self.results.get("search_data", [])))
        ]
        
        # Filter out zero counts and sort by count
        chart_data = [(name, count) for name, count in chart_data if count > 0]
        chart_data.sort(key=lambda x: x[1], reverse=True)
        
        # Generate chart HTML
        chart_html = ""
        if chart_data:
            max_count = max(count for _, count in chart_data)
            for name, count in chart_data:
                percentage = (count / max_count) * 100 if max_count > 0 else 0
                chart_html += f'''
                <div class="chart-bar-container">
                    <div class="chart-label">{name}</div>
                    <div class="chart-bar-wrapper">
                        <div class="chart-bar" style="width: {percentage}%;">
                            <span class="chart-value">{count}</span>
                        </div>
                    </div>
                    <div class="chart-max-label">{max_count}</div>
                </div>'''
        else:
            chart_html = '<p style="text-align:center;color:#6c757d;font-style:italic;">No data available for chart</p>'

        html_content = f'''<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>Windows FeatureUsage Extraction Report</title>
    <style>
        body {{ font-family: sans-serif; margin: 20px; }}
        table {{ border-collapse: collapse; margin: 20px 0; }}
        th, td {{ padding: 8px 12px; text-align: left; border: 1px solid #ddd; }}
        th {{ background: #f2f2f2; font-weight: bold; }}
        tr:nth-child(even) {{ background-color: #f9f9f9; }}
        tr:hover {{ background-color: #f5f5f5; }}
        
        .search-container {{ margin: 20px 0; padding: 15px; background: #f8f9fa; border-radius: 5px; }}
        .search-input {{ width: 300px; padding: 8px; border: 1px solid #ddd; border-radius: 4px; font-size: 14px; }}
        .search-button {{ padding: 8px 16px; background: #007bff; color: white; border: none; border-radius: 4px; cursor: pointer; margin-left: 10px; }}
        .search-button:hover {{ background: #0056b3; }}
        .clear-button {{ padding: 8px 16px; background: #6c757d; color: white; border: none; border-radius: 4px; cursor: pointer; margin-left: 10px; }}
        .clear-button:hover {{ background: #545b62; }}
        .stats {{ margin: 10px 0; font-size: 14px; color: #666; }}
        .hidden {{ display: none; }}
        .highlight {{ background-color: #fff3cd; font-weight: bold; }}
        .no-results {{ color: #dc3545; font-style: italic; padding: 10px; background: #f8d7da; border: 1px solid #f5c6cb; border-radius: 4px; margin: 10px 0; }}
        
        .table-section {{ margin: 15px 0; border: 1px solid #ddd; border-radius: 5px; overflow: hidden; }}
        .table-header {{ background: #e9ecef; padding: 12px 15px; cursor: pointer; font-weight: bold; font-size: 16px; border-bottom: 1px solid #ddd; transition: background-color 0.2s; }}
        .table-header:hover {{ background: #d1ecf1; }}
        .toggle-icon {{ display: inline-block; margin-right: 10px; font-size: 12px; transition: transform 0.2s; }}
        .entry-count {{ float: right; font-size: 14px; color: #6c757d; font-weight: normal; }}
        .table-content {{ padding: 15px; background: white; transition: all 0.3s ease-out; overflow: hidden; }}
        .table-content.collapsed {{ max-height: 0; padding: 0 15px; opacity: 0; }}
        .table-content.expanded {{ max-height: 2000px; opacity: 1; }}
        
        .chart-container {{ margin: 20px 0; padding: 20px; background: #f8f9fa; border-radius: 8px; border: 1px solid #dee2e6; }}
        .chart-title {{ font-size: 18px; font-weight: bold; margin-bottom: 15px; color: #495057; }}
        .chart-bar-container {{ margin: 10px 0; display: flex; align-items: center; }}
        .chart-label {{ width: 200px; font-weight: bold; color: #495057; margin-right: 15px; }}
        .chart-bar-wrapper {{ flex: 1; background: #e9ecef; border-radius: 4px; height: 25px; position: relative; overflow: hidden; }}
        .chart-bar {{ height: 100%; background: linear-gradient(90deg, #007bff, #0056b3); border-radius: 4px; transition: width 0.5s ease-in-out; position: relative; }}
        .chart-value {{ position: absolute; right: 8px; top: 50%; transform: translateY(-50%); color: white; font-weight: bold; font-size: 12px; }}
        .chart-max-label {{ width: 60px; text-align: right; font-size: 12px; color: #6c757d; margin-left: 10px; }}
    </style>
</head>
<body>
    <h1>Windows FeatureUsage Extraction Report</h1>
    <p><strong>Extraction time:</strong> {self.results.get("extraction_time", "")}</p>
    <p><strong>Current User SID:</strong> {self.results.get("current_user_sid", "")}</p>
    <p><strong>Total entries:</strong> {self.results.get("total_entries", 0)}</p>
    <p><strong>Summary:</strong> {self.results.get("summary", {})}</p>
    
    <!-- Chart container -->
    <div class="chart-container">
        <div class="chart-title">📊 Artifact Distribution</div>
        {chart_html}
    </div>
    
    <!-- Search functionality -->
    <div class="search-container">
        <h3>🔍 Search Data</h3>
        <input type="text" id="searchInput" class="search-input" placeholder="Search for applications, timestamps, or any data...">
        <button onclick="searchData()" class="search-button">Search</button>
        <button onclick="clearSearch()" class="clear-button">Clear</button>
        <div class="stats" id="searchStats"></div>
        <div id="noResultsMessage" class="no-results" style="display:none;">No results found for your search. Try a shorter or different search term.</div>
    </div>
    
    <script>
        function toggleTable(tableId) {{
            const content = document.getElementById(tableId + "-content");
            const header = content.previousElementSibling;
            const icon = header.querySelector(".toggle-icon");
            
            if (content.classList.contains("collapsed")) {{
                content.classList.remove("collapsed");
                content.classList.add("expanded");
                icon.textContent = "▼";
            }} else {{
                content.classList.remove("expanded");
                content.classList.add("collapsed");
                icon.textContent = "▶";
            }}
        }}
        
        function searchData() {{
            const searchTerm = document.getElementById("searchInput").value.toLowerCase().trim();
            const tables = document.querySelectorAll(".data-table");
            const noResultsDiv = document.getElementById("noResultsMessage");
            let totalMatches = 0;
            let totalRows = 0;
            let tablesWithMatches = 0;
            
            noResultsDiv.style.display = "none";
            
            if (!searchTerm) {{
                clearSearch();
                return;
            }}
            
            tables.forEach(table => {{
                const rows = table.querySelectorAll("tr");
                let tableMatches = 0;
                
                rows.forEach((row, index) => {{
                    if (index === 0) {{
                        row.style.display = "";
                        return;
                    }}
                    totalRows++;
                    const cells = row.querySelectorAll("td");
                    let rowMatch = false;
                    
                    cells.forEach(cell => {{
                        const cellText = cell.textContent.toLowerCase();
                        if (cellText.includes(searchTerm)) {{
                            rowMatch = true;
                            cell.classList.add("highlight");
                        }} else {{
                            cell.classList.remove("highlight");
                        }}
                    }});
                    
                    if (rowMatch) {{
                        row.style.display = "";
                        tableMatches++;
                        totalMatches++;
                    }} else {{
                        row.style.display = "none";
                    }}
                }});
                
                const tableSection = table.closest(".table-section");
                const tableContent = tableSection.querySelector(".table-content");
                
                if (tableMatches > 0) {{
                    tablesWithMatches++;
                    tableSection.style.display = "block";
                    if (tableContent.classList.contains("collapsed")) {{
                        toggleTable(table.id);
                    }}
                }} else {{
                    tableSection.style.display = "none";
                }}
            }});
            
            const statsDiv = document.getElementById("searchStats");
            if (searchTerm) {{
                if (totalMatches > 0) {{
                    statsDiv.innerHTML = `Found ${{totalMatches}} matches out of ${{totalRows}} total entries in ${{tablesWithMatches}} table(s)`;
                }} else {{
                    statsDiv.innerHTML = `No matches found in any table`;
                    noResultsDiv.style.display = "block";
                }}
            }} else {{
                statsDiv.innerHTML = "";
            }}
        }}
        
        function clearSearch() {{
            document.getElementById("searchInput").value = "";
            document.getElementById("searchStats").innerHTML = "";
            document.getElementById("noResultsMessage").style.display = "none";
            const tables = document.querySelectorAll(".data-table");
            tables.forEach(table => {{
                const rows = table.querySelectorAll("tr");
                rows.forEach(row => {{
                    row.style.display = "";
                    const cells = row.querySelectorAll("td");
                    cells.forEach(cell => cell.classList.remove("highlight"));
                }});
                const tableSection = table.closest(".table-section");
                tableSection.style.display = "block";
            }});
        }}
        
        document.getElementById("searchInput").addEventListener("keypress", function(event) {{
            if (event.key === "Enter") {{
                searchData();
            }}
        }});
        
        let searchTimeout;
        document.getElementById("searchInput").addEventListener("input", function() {{
            clearTimeout(searchTimeout);
            searchTimeout = setTimeout(searchData, 300);
        }});
    </script>
    
    {dicts_to_html_table(self.results.get("featureusage_data", []), "FeatureUsage Data", "featureusage-table")}
    {dicts_to_html_table(self.results.get("appswitched_data", []), "AppSwitched Data (All)", "appswitched-table")}
    {dicts_to_html_table(self.results.get("advanced_appswitched_data", []), "Advanced AppSwitched Data", "advanced-appswitched-table")}
    {dicts_to_html_table(self.results.get("showjumpview_data", []), "ShowJumpView Data", "showjumpview-table")}
    {dicts_to_html_table(self.results.get("appbadgeupdated_data", []), "AppBadgeUpdated Data", "appbadgeupdated-table")}
    {dicts_to_html_table(self.results.get("applaunch_data", []), "AppLaunch Data", "applaunch-table")}
    
</body>
</html>'''

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
    # Set up command line argument parsing
    parser = argparse.ArgumentParser(
        description="Windows FeatureUsage Artifact Extractor - Enhanced with Advanced AppSwitched Support",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python featureusage_extractor.py                    # Generate HTML report only (default)
  python featureusage_extractor.py --json             # Generate both HTML and JSON reports
  python featureusage_extractor.py -j                 # Short form for JSON export
        """
    )
    parser.add_argument(
        '--json', '-j',
        action='store_true',
        help='Also export results to JSON format'
    )
    
    args = parser.parse_args()
    
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
        
        # Export to HTML (always done)
        html_file = extractor.export_to_html()
        if html_file:
            print(f"\nHTML report saved to: {html_file}")
        else:
            print("Failed to save HTML report.")
        
        # Export to JSON (only if requested)
        if args.json:
            output_file = extractor.save_results()
            if output_file:
                print(f"JSON results saved to: {output_file}")
            else:
                print("Failed to save JSON results.")
        else:
            print("JSON export skipped (use --json to enable)")
        
        print(f"\nExtraction completed successfully!")
        
    except Exception as e:
        print(f"Error during extraction: {e}")
        sys.exit(1)


if __name__ == "__main__":
    main() 