#!/usr/bin/env python3
"""
Demonstration script for the new app_identifier_resolved column functionality
"""

from featureusage.guid_resolver import GUIDResolver

def demo_guid_resolution():
    """Demonstrate the new GUID resolution functionality."""
    resolver = GUIDResolver()
    
    print("Windows FeatureUsage Analyzer - GUID Resolution Demo")
    print("=" * 60)
    print()
    
    # Example data that might be extracted from registry
    example_data = [
        {
            "timestamp": "2024-01-15T10:30:00",
            "app_identifier": "{F38BF404-1D43-42F2-9305-67DE0B28FC23}\\regedit.exe",
            "usage_count": 3,
            "source": "AppSwitched"
        },
        {
            "timestamp": "2024-01-15T11:15:00", 
            "app_identifier": "{7C5A40EF-A0FB-4BFC-874A-C0F2E0B9FA8E}\\notepad.exe",
            "usage_count": 5,
            "source": "AppLaunch"
        },
        {
            "timestamp": "2024-01-15T12:00:00",
            "app_identifier": "{B4BFCC3A-DB2C-424C-B029-7FE99A87C641}\\document.docx",
            "usage_count": 1,
            "source": "ShowJumpView"
        },
        {
            "timestamp": "2024-01-15T13:45:00",
            "app_identifier": "C:\\Windows\\System32\\cmd.exe",
            "usage_count": 2,
            "source": "AppSwitched"
        },
        {
            "timestamp": "2024-01-15T14:20:00",
            "app_identifier": "{4C5C32FF-BB9D-43B0-B5B4-2D72E54EAAA4}\\report.pdf",
            "usage_count": 4,
            "source": "AppLaunch"
        }
    ]
    
    print("Original extracted data from registry:")
    print("-" * 40)
    for i, entry in enumerate(example_data, 1):
        print(f"{i}. {entry['app_identifier']}")
    
    print("\nAfter GUID resolution (new app_identifier_resolved column):")
    print("-" * 40)
    
    for i, entry in enumerate(example_data, 1):
        original = entry['app_identifier']
        
        # Check if it contains a GUID pattern
        if "{" in original and "}" in original:
            resolved = resolver.replace_guid_with_resolved(original)
            print(f"{i}. Original: {original}")
            print(f"   Resolved: {resolved}")
        else:
            print(f"{i}. {original} (no GUID to resolve)")
        print()
    
    print("GUID Resolution Examples:")
    print("-" * 40)
    print("• {F38BF404-1D43-42F2-9305-67DE0B28FC23} → %windir%")
    print("• {7C5A40EF-A0FB-4BFC-874A-C0F2E0B9FA8E} → %ProgramFiles%")
    print("• {B4BFCC3A-DB2C-424C-B029-7FE99A87C641} → %USERPROFILE%\\Desktop")
    print("• {4C5C32FF-BB9D-43B0-B5B4-2D72E54EAAA4} → %USERPROFILE%\\Documents")
    print()
    print("Note: The original app_identifier column is preserved unchanged.")
    print("The new app_identifier_resolved column contains the resolved paths.")

if __name__ == "__main__":
    demo_guid_resolution() 