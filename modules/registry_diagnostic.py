#!/usr/bin/env python3
"""
Registry Diagnostic Tool for AppSwitched Investigation

This script helps diagnose issues with the AppSwitched registry location
and provides detailed information about what's actually stored there.
"""

import winreg
import sys
from datetime import datetime
from typing import Dict, List, Any, Optional


def check_registry_key_exists(key_path: str) -> bool:
    """Check if a registry key exists."""
    try:
        key = winreg.OpenKey(winreg.HKEY_CURRENT_USER, key_path)
        winreg.CloseKey(key)
        return True
    except Exception:
        return False


def list_registry_values(key_path: str) -> List[Dict[str, Any]]:
    """List all values in a registry key with detailed information."""
    values = []
    
    try:
        key = winreg.OpenKey(winreg.HKEY_CURRENT_USER, key_path)
        
        # Get the number of values
        try:
            value_count, _, _ = winreg.QueryInfoKey(key)
        except Exception as e:
            print(f"Error getting value count: {e}")
            value_count = 0
        
        print(f"Found {value_count} values in {key_path}")
        
        # Enumerate all values
        i = 0
        while True:
            try:
                value_name, value_data, value_type = winreg.EnumValue(key, i)
                
                value_info = {
                    "name": value_name,
                    "type": value_type,
                    "type_name": get_registry_type_name(value_type),
                    "size": len(value_data) if isinstance(value_data, bytes) else len(str(value_data)),
                    "data_preview": get_data_preview(value_data, value_type)
                }
                
                values.append(value_info)
                i += 1
                
            except WindowsError:
                # No more values
                break
        
        winreg.CloseKey(key)
        
    except Exception as e:
        print(f"Error accessing registry key {key_path}: {e}")
    
    return values


def get_registry_type_name(reg_type: int) -> str:
    """Convert registry type to human-readable name."""
    type_names = {
        winreg.REG_BINARY: "REG_BINARY",
        winreg.REG_DWORD: "REG_DWORD",
        winreg.REG_DWORD_LITTLE_ENDIAN: "REG_DWORD_LITTLE_ENDIAN",
        winreg.REG_DWORD_BIG_ENDIAN: "REG_DWORD_BIG_ENDIAN",
        winreg.REG_EXPAND_SZ: "REG_EXPAND_SZ",
        winreg.REG_LINK: "REG_LINK",
        winreg.REG_MULTI_SZ: "REG_MULTI_SZ",
        winreg.REG_NONE: "REG_NONE",
        winreg.REG_QWORD: "REG_QWORD",
        winreg.REG_QWORD_LITTLE_ENDIAN: "REG_QWORD_LITTLE_ENDIAN",
        winreg.REG_SZ: "REG_SZ"
    }
    return type_names.get(reg_type, f"UNKNOWN_TYPE_{reg_type}")


def get_data_preview(data: Any, reg_type: int) -> str:
    """Get a preview of registry data."""
    if reg_type == winreg.REG_BINARY:
        if len(data) <= 32:
            return f"Binary: {data.hex()}"
        else:
            return f"Binary: {data[:16].hex()}... (truncated, total {len(data)} bytes)"
    elif reg_type in [winreg.REG_DWORD, winreg.REG_DWORD_LITTLE_ENDIAN, winreg.REG_DWORD_BIG_ENDIAN]:
        return f"DWORD: {data} (0x{data:08x})"
    elif reg_type in [winreg.REG_QWORD, winreg.REG_QWORD_LITTLE_ENDIAN]:
        return f"QWORD: {data} (0x{data:016x})"
    elif reg_type == winreg.REG_SZ:
        return f"String: {data}"
    elif reg_type == winreg.REG_MULTI_SZ:
        return f"Multi-String: {data}"
    else:
        return f"Data: {str(data)[:50]}..."


def check_featureusage_locations():
    """Check all FeatureUsage-related registry locations."""
    locations = [
        "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Explorer\\FeatureUsage\\AppSwitched",
        "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Explorer\\FeatureUsage\\StartMenu",
        "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Explorer\\FeatureUsage\\Search",
        "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Explorer\\Advanced\\People",
        "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Explorer\\Advanced\\TaskbarAl"
    ]
    
    print("=" * 80)
    print("FEATUREUSAGE REGISTRY DIAGNOSTIC")
    print("=" * 80)
    print(f"Diagnostic time: {datetime.now().isoformat()}")
    print()
    
    for location in locations:
        print(f"Checking: HKCU\\{location}")
        print("-" * 60)
        
        if check_registry_key_exists(location):
            print("✓ Key exists")
            values = list_registry_values(location)
            
            if values:
                print(f"Found {len(values)} values:")
                for i, value in enumerate(values, 1):
                    print(f"  {i}. {value['name']} ({value['type_name']}) - {value['data_preview']}")
            else:
                print("✗ No values found in key")
        else:
            print("✗ Key does not exist")
        
        print()


def check_parent_keys():
    """Check if parent keys exist."""
    print("=" * 80)
    print("PARENT KEY CHECK")
    print("=" * 80)
    
    parent_keys = [
        "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Explorer\\FeatureUsage",
        "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Explorer\\Advanced",
        "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Explorer",
        "SOFTWARE\\Microsoft\\Windows\\CurrentVersion",
        "SOFTWARE\\Microsoft\\Windows",
        "SOFTWARE\\Microsoft",
        "SOFTWARE"
    ]
    
    for key in parent_keys:
        exists = check_registry_key_exists(key)
        status = "✓" if exists else "✗"
        print(f"{status} HKCU\\{key}")


def check_alternative_locations():
    """Check for alternative AppSwitched locations."""
    print("=" * 80)
    print("ALTERNATIVE LOCATIONS CHECK")
    print("=" * 80)
    
    alternative_locations = [
        "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Explorer\\FeatureUsage\\AppSwitched",
        "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Explorer\\FeatureUsage\\AppSwitched\\",
        "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Explorer\\FeatureUsage\\AppSwitched\\*",
        "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Explorer\\FeatureUsage\\AppSwitched\\Settings",
        "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Explorer\\FeatureUsage\\AppSwitched\\Data",
        "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Explorer\\FeatureUsage\\AppSwitched\\History",
        "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Explorer\\FeatureUsage\\AppSwitched\\Usage",
        "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Explorer\\FeatureUsage\\AppSwitched\\Stats",
        "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Explorer\\FeatureUsage\\AppSwitched\\Log",
        "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Explorer\\FeatureUsage\\AppSwitched\\Cache"
    ]
    
    for location in alternative_locations:
        exists = check_registry_key_exists(location)
        if exists:
            print(f"✓ Found: HKCU\\{location}")
            values = list_registry_values(location)
            if values:
                print(f"  Contains {len(values)} values")
            else:
                print("  Empty key")


def main():
    """Main diagnostic function."""
    print("Windows Registry Diagnostic Tool")
    print("Investigating AppSwitched Registry Issues")
    print()
    
    try:
        # Check parent keys first
        check_parent_keys()
        print()
        
        # Check main FeatureUsage locations
        check_featureusage_locations()
        
        # Check alternative locations
        check_alternative_locations()
        
        print("=" * 80)
        print("DIAGNOSTIC COMPLETE")
        print("=" * 80)
        
    except Exception as e:
        print(f"Error during diagnostic: {e}")
        sys.exit(1)


if __name__ == "__main__":
    main() 