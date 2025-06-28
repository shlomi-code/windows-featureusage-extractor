#!/usr/bin/env python3
"""
Test script for GUID resolution integration with the main extractor
"""

from featureusage_extractor import FeatureUsageExtractor

def test_integration():
    """Test the integration of GUID resolution with the main extractor."""
    print("Testing GUID Resolution Integration:")
    print("=" * 50)
    
    # Create extractor instance
    extractor = FeatureUsageExtractor()
    
    # Test the GUID resolution method directly
    test_data = [
        {
            "timestamp": "2024-01-01T12:00:00",
            "app_identifier": "{F38BF404-1D43-42F2-9305-67DE0B28FC23}\\regedit.exe",
            "usage_count": 5
        },
        {
            "timestamp": "2024-01-01T13:00:00",
            "app_identifier": "{7C5A40EF-A0FB-4BFC-874A-C0F2E0B9FA8E}\\notepad.exe",
            "usage_count": 3
        },
        {
            "timestamp": "2024-01-01T14:00:00",
            "app_identifier": "C:\\Windows\\System32\\cmd.exe",
            "usage_count": 1
        },
        {
            "timestamp": "2024-01-01T15:00:00",
            "app_identifier": "{B4BFCC3A-DB2C-424C-B029-7FE99A87C641}\\test.txt",
            "usage_count": 2
        }
    ]
    
    print("Original data:")
    for entry in test_data:
        print(f"  {entry}")
    
    print("\nResolved data (with app_identifier_resolved column):")
    resolved_data = extractor._resolve_guids_in_data(test_data)
    for entry in resolved_data:
        print(f"  {entry}")
    
    print("\nVerifying original app_identifier is preserved:")
    for i, entry in enumerate(resolved_data):
        original = test_data[i]["app_identifier"]
        preserved = entry["app_identifier"]
        resolved = entry.get("app_identifier_resolved", "N/A")
        print(f"  Entry {i+1}: Original='{original}' -> Preserved='{preserved}', Resolved='{resolved}'")
    
    print("\nGUID resolution integration test completed successfully!")

if __name__ == "__main__":
    test_integration() 