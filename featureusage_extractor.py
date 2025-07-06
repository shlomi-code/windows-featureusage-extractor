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
import os
import sys
from datetime import datetime
from typing import Dict, List, Any, Optional
import struct
import argparse

# Import the GUID resolver
from featureusage.guid_resolver import GUIDResolver
# Import the app resolver
from featureusage.app_resolver import AppResolver
# Import the registry access class
from featureusage.registry_access import RegistryAccess
# Import the export classes
from featureusage.json_exporter import JSONExporter
from featureusage.html_exporter import HTMLExporter


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
            "showjumpview_data": [],
            "appbadgeupdated_data": [],
            "applaunch_data": [],
            "startmenu_data": [],
            "search_data": []
        }
        # Initialize GUID resolver
        self.guid_resolver = GUIDResolver()
        # Initialize app resolver
        self.app_resolver = AppResolver()
        # Initialize registry access
        self.registry = RegistryAccess()
        # Now that self.registry is available, get the full SID
        self.full_user_sid = self._get_full_user_sid()
        # Initialize exporters
        self.json_exporter = JSONExporter()
        self.html_exporter = HTMLExporter()
    
    def _get_current_user_sid(self) -> str:
        """Get the SID of the currently running user."""
        try:
            # Method 1: Try to get SID from HKEY_CURRENT_USER path
            # The HKEY_CURRENT_USER key path contains the SID
            import winreg
            
            # Get the actual path of HKEY_CURRENT_USER which contains the SID
            # This is a more reliable method than trying to parse registry paths
            try:
                # Try to get user info from registry
                key = self.registry.open_key(winreg.HKEY_CURRENT_USER, "Software\\Microsoft\\Windows\\CurrentVersion\\Explorer")
                if key:
                    self.registry.close_key(key)
                    
                    # Get username from environment variables
                    username = os.environ.get('USERNAME', '')
                    domain = os.environ.get('USERDOMAIN', '')
                    
                    if username:
                        if domain and domain != os.environ.get('COMPUTERNAME', ''):
                            return f"{domain}\\{username}"
                        else:
                            return username
                    else:
                        return "Current User"
                        
            except Exception:
                pass
            
            # Method 2: Try to extract SID from registry path
            try:
                # Look for SID in common registry locations
                sid_locations = [
                    "Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\FeatureUsage\\AppSwitched",
                    "Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\FeatureUsage\\AppLaunch",
                    "Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\FeatureUsage\\ShowJumpView"
                ]
                
                for location in sid_locations:
                    try:
                        key = self.registry.open_key(winreg.HKEY_CURRENT_USER, location)
                        if key:
                            self.registry.close_key(key)
                            # If we can access HKEY_CURRENT_USER, we're the current user
                            username = os.environ.get('USERNAME', 'Current User')
                            return username
                    except Exception:
                        continue
                        
            except Exception:
                pass
            
            # Method 3: Fallback to environment variables
            username = os.environ.get('USERNAME', '')
            if username:
                return username
            
            # Method 4: Final fallback
            return "Current User"
            
        except Exception as e:
            print(f"Warning: Could not determine current user SID: {e}")
            return "Current User"
    
    def _get_full_user_sid(self) -> str:
        """Get the full Windows SID of the current user (optional method)."""
        try:
            import winreg
            key = self.registry.open_key(winreg.HKEY_LOCAL_MACHINE, "SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\ProfileList")
            if key:
                current_profile = os.environ.get('USERPROFILE', '')
                if current_profile:
                    i = 0
                    while True:
                        subkey_name = self.registry.enum_key(key, i)
                        if subkey_name is None:
                            break
                        try:
                            subkey = self.registry.open_key(winreg.HKEY_LOCAL_MACHINE, f"SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\ProfileList\\{subkey_name}")
                            if subkey:
                                profile_path = self.registry.read_registry_value(winreg.HKEY_LOCAL_MACHINE, f"SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\ProfileList\\{subkey_name}", "ProfileImagePath")
                                if profile_path and isinstance(profile_path, str):
                                    expanded_path = os.path.expandvars(profile_path)
                                    if current_profile.lower() == expanded_path.lower():
                                        self.registry.close_key(subkey)
                                        self.registry.close_key(key)
                                        return subkey_name
                                self.registry.close_key(subkey)
                        except Exception:
                            pass
                        i += 1
                self.registry.close_key(key)
            return "SID not found"
        except Exception as e:
            print(f"Warning: Could not determine full user SID: {e}")
            return "SID not found"
    
    def _read_registry_value(self, key_path: str, value_name: Optional[str] = None) -> Optional[bytes]:
        """Read a registry value and return its data."""
        return self.registry.read_registry_value(winreg.HKEY_CURRENT_USER, key_path, value_name)
    
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
            key = self.registry.open_key(winreg.HKEY_CURRENT_USER, self.featureusage_path)
            if key is None:
                print(f"  Error: Could not open registry key {self.featureusage_path}")
                return []
            
            entries = []
            
            # Get key information
            key_info = self.registry.query_info_key(key)
            if key_info is not None:
                value_count, subkey_count, _ = key_info
                print(f"  Registry key info: {value_count} values, {subkey_count} subkeys")
            else:
                value_count = 0
                print(f"  Warning: Could not get key info")
            
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
                value_info = self.registry.enum_value(key, i)
                if value_info is None:
                    break
                
                value_name, value_data, value_type = value_info
                
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
            
            self.registry.close_key(key)
            
            if not entries:
                print("  ℹ️  No AppSwitched data extracted - checking alternative sources...")
            else:
                print(f"  ✓ Successfully extracted {len(entries)} AppSwitched entries")
            
            return entries
            
        except Exception as e:
            print(f"Error extracting AppSwitched data: {e}")
            return []
    

    
    def extract_startmenu_data(self) -> List[Dict[str, Any]]:
        """Extract StartMenu FeatureUsage data."""
        print("Extracting StartMenu FeatureUsage data...")
        
        startmenu_path = "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Explorer\\FeatureUsage\\StartMenu"
        
        try:
            key = self.registry.open_key(winreg.HKEY_CURRENT_USER, startmenu_path)
            if key is None:
                return []
            
            entries = []
            
            # Enumerate all values in the key
            i = 0
            while True:
                value_info = self.registry.enum_value(key, i)
                if value_info is None:
                    break
                
                value_name, value_data, value_type = value_info
                
                if value_type == winreg.REG_BINARY:
                    parsed_entries = self._parse_featureusage_data(value_data)
                    
                    for entry in parsed_entries:
                        entry["source"] = "StartMenu"
                        entry["value_name"] = value_name
                        entry["value_type"] = "REG_BINARY"
                        entry["raw_data_size"] = len(value_data)
                    
                    entries.extend(parsed_entries)
                
                i += 1
            
            self.registry.close_key(key)
            return entries
            
        except Exception as e:
            print(f"Error extracting StartMenu data: {e}")
            return []
    
    def extract_search_data(self) -> List[Dict[str, Any]]:
        """Extract Search FeatureUsage data."""
        print("Extracting Search FeatureUsage data...")
        
        search_path = "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Explorer\\FeatureUsage\\Search"
        
        try:
            key = self.registry.open_key(winreg.HKEY_CURRENT_USER, search_path)
            if key is None:
                return []
            
            entries = []
            
            # Enumerate all values in the key
            i = 0
            while True:
                value_info = self.registry.enum_value(key, i)
                if value_info is None:
                    break
                
                value_name, value_data, value_type = value_info
                
                if value_type == winreg.REG_BINARY:
                    parsed_entries = self._parse_featureusage_data(value_data)
                    
                    for entry in parsed_entries:
                        entry["source"] = "Search"
                        entry["value_name"] = value_name
                        entry["value_type"] = "REG_BINARY"
                        entry["raw_data_size"] = len(value_data)
                    
                    entries.extend(parsed_entries)
                
                i += 1
            
            self.registry.close_key(key)
            return entries
            
        except Exception as e:
            print(f"Error extracting Search data: {e}")
            return []
    

    
    def extract_showjumpview_data(self) -> List[Dict[str, Any]]:
        """Extract ShowJumpView FeatureUsage data."""
        print("Extracting ShowJumpView FeatureUsage data...")
        showjumpview_path = "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Explorer\\FeatureUsage\\ShowJumpView"
        entries = []
        try:
            key = self.registry.open_key(winreg.HKEY_CURRENT_USER, showjumpview_path)
            if key is None:
                return []
            
            key_info = self.registry.query_info_key(key)
            if key_info is not None:
                value_count, subkey_count, _ = key_info
                print(f"  Registry key info: {value_count} values, {subkey_count} subkeys")
            else:
                value_count = 0
                print(f"  Warning: Could not get key info")
            
            if value_count == 0:
                print("  ⚠️  No values found in ShowJumpView registry key")
            
            i = 0
            while True:
                value_info = self.registry.enum_value(key, i)
                if value_info is None:
                    break
                
                value_name, value_data, value_type = value_info
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
            
            self.registry.close_key(key)
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
            key = self.registry.open_key(winreg.HKEY_CURRENT_USER, appbadgeupdated_path)
            if key is None:
                return []
            
            key_info = self.registry.query_info_key(key)
            if key_info is not None:
                value_count, subkey_count, _ = key_info
                print(f"  Registry key info: {value_count} values, {subkey_count} subkeys")
            else:
                value_count = 0
                print(f"  Warning: Could not get key info")
            
            if value_count == 0:
                print("  ⚠️  No values found in AppBadgeUpdated registry key")
            
            i = 0
            while True:
                value_info = self.registry.enum_value(key, i)
                if value_info is None:
                    break
                
                value_name, value_data, value_type = value_info
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
            
            self.registry.close_key(key)
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
            key = self.registry.open_key(winreg.HKEY_CURRENT_USER, applaunch_path)
            if key is None:
                return []
            
            key_info = self.registry.query_info_key(key)
            if key_info is not None:
                value_count, subkey_count, _ = key_info
                print(f"  Registry key info: {value_count} values, {subkey_count} subkeys")
            else:
                value_count = 0
                print(f"  Warning: Could not get key info")
            
            if value_count == 0:
                print("  ⚠️  No values found in AppLaunch registry key")
            
            i = 0
            while True:
                value_info = self.registry.enum_value(key, i)
                if value_info is None:
                    break
                
                value_name, value_data, value_type = value_info
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
            
            self.registry.close_key(key)
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
        print(f"Current User: {self.current_user_sid}")
        print(f"Full User SID: {self.full_user_sid}")
        print("-" * 50)
        
        # Extract data from different FeatureUsage sources
        appswitched_data = self.extract_appswitched_data()
        startmenu_data = self.extract_startmenu_data()
        search_data = self.extract_search_data()
        showjumpview_data = self.extract_showjumpview_data()
        appbadgeupdated_data = self.extract_appbadgeupdated_data()
        applaunch_data = self.extract_applaunch_data()
        
        # Check for alternative sources if no AppSwitched data found
        if not appswitched_data:
            print("\nNo AppSwitched data found - checking alternative sources...")
            alternative_sources = self.check_alternative_appswitched_sources()
            
            if not alternative_sources:
                print("\nNo alternative AppSwitched sources found.")
                self.provide_test_data_suggestions()
        
        # Combine all data
        all_data = appswitched_data + startmenu_data + search_data + showjumpview_data + appbadgeupdated_data + applaunch_data
        all_appswitched_data = appswitched_data
        
        # Sort by timestamp
        all_data.sort(key=lambda x: x.get("timestamp", ""))
        all_appswitched_data.sort(key=lambda x: x.get("timestamp", ""))
        
        # Resolve GUIDs in all extracted data
        print("\nResolving Windows Known Folder GUIDs and AutoGenerated App IDs...")
        resolved_all_data = self._resolve_guids_in_data(all_data)
        resolved_all_appswitched_data = self._resolve_guids_in_data(all_appswitched_data)
        resolved_showjumpview_data = self._resolve_guids_in_data(showjumpview_data)
        resolved_appbadgeupdated_data = self._resolve_guids_in_data(appbadgeupdated_data)
        resolved_applaunch_data = self._resolve_guids_in_data(applaunch_data)
        
        self.results["featureusage_data"] = resolved_all_data
        self.results["appswitched_data"] = resolved_all_appswitched_data
        self.results["showjumpview_data"] = resolved_showjumpview_data
        self.results["appbadgeupdated_data"] = resolved_appbadgeupdated_data
        self.results["applaunch_data"] = resolved_applaunch_data
        self.results["total_entries"] = len(resolved_all_data)
        self.results["appswitched_entries"] = len(resolved_all_appswitched_data)
        self.results["summary"] = {
            "appswitched_entries": len(appswitched_data),
            "startmenu_entries": len(startmenu_data),
            "search_entries": len(search_data),
            "showjumpview_entries": len(showjumpview_data),
            "appbadgeupdated_entries": len(appbadgeupdated_data),
            "applaunch_entries": len(applaunch_data),
            "total_appswitched_entries": len(resolved_all_appswitched_data)
        }
        self.results["full_user_sid"] = self.full_user_sid
        
        print(f"\nExtraction completed!")
        print(f"Total entries found: {len(resolved_all_data)}")
        print(f"AppSwitched entries: {len(appswitched_data)}")
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
        Resolve Windows Known Folder GUIDs and AutoGenerated App IDs in the extracted data.
        Creates app_identifier_resolved column while keeping app_identifier unchanged.
        
        Args:
            data_list: List of dictionaries containing extracted data
            
        Returns:
            List of dictionaries with resolved GUIDs and App IDs in new app_identifier_resolved column
        """
        resolved_data = []
        
        for entry in data_list:
            resolved_entry = entry.copy()  # Copy all original data
            
            # Check if app_identifier exists and create app_identifier_resolved
            if "app_identifier" in entry:
                original_app_identifier = entry["app_identifier"]
                
                if isinstance(original_app_identifier, str):
                    # First, try to resolve as an AutoGenerated app ID
                    if original_app_identifier.startswith("Microsoft.AutoGenerated."):
                        resolved_app_name = self.app_resolver.resolve_app_id(original_app_identifier)
                        if resolved_app_name:
                            resolved_entry["app_identifier_resolved"] = resolved_app_name
                        else:
                            # If app resolver couldn't resolve it, keep the original
                            resolved_entry["app_identifier_resolved"] = original_app_identifier
                    # Then check if it contains a GUID pattern (for known folder GUIDs)
                    elif "{" in original_app_identifier and "}" in original_app_identifier:
                        # Replace GUIDs in the app_identifier with their resolved values
                        resolved_app_identifier = self.guid_resolver.replace_guid_with_resolved(original_app_identifier)
                        resolved_entry["app_identifier_resolved"] = resolved_app_identifier
                    else:
                        # No special pattern found, keep the same value
                        resolved_entry["app_identifier_resolved"] = original_app_identifier
                else:
                    # Not a string, keep the same value
                    resolved_entry["app_identifier_resolved"] = original_app_identifier
            
            resolved_data.append(resolved_entry)
        
        return resolved_data
    
    def save_results(self, filename: Optional[str] = None) -> str:
        """Save extraction results to a JSON file."""
        return self.json_exporter.export_results(self.results, filename)
    
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
                key = self.registry.open_key(winreg.HKEY_CURRENT_USER, source)
                if key is None:
                    continue
                
                # Get key information
                key_info = self.registry.query_info_key(key)
                if key_info is not None:
                    value_count, subkey_count, _ = key_info
                    if value_count > 0 or subkey_count > 0:
                        print(f"  ✓ Found alternative source: {source}")
                        print(f"    Values: {value_count}, Subkeys: {subkey_count}")
                        found_sources.append({
                            "path": source,
                            "value_count": value_count,
                            "subkey_count": subkey_count
                        })
                else:
                    print(f"  Warning: Could not get info for {source}")
                
                self.registry.close_key(key)
                
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
        return self.html_exporter.export_results(self.results, filename)


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