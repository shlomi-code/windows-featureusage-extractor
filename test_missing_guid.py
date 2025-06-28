#!/usr/bin/env python3
"""
Test script to verify the missing GUID is now resolved
"""

from featureusage.guid_resolver import GUIDResolver

def test_missing_guid():
    """Test that the previously missing GUID is now resolved."""
    resolver = GUIDResolver()
    
    # Test the specific GUID that was missing
    test_guid = "{6D809377-6AF0-444B-8957-A3773F02200E}"
    test_path = f"{test_guid}\\some_application.exe"
    
    print("Testing the previously missing GUID:")
    print("=" * 50)
    
    # Test individual GUID resolution
    result = resolver.resolve_guid(test_guid)
    if result:
        display_name, path = result
        print(f"GUID: {test_guid}")
        print(f"Resolved to: {display_name}: {path}")
    else:
        print(f"GUID: {test_guid}")
        print("Still not found!")
    
    print()
    
    # Test path resolution
    resolved_path = resolver.replace_guid_with_resolved(test_path)
    print(f"Original path: {test_path}")
    print(f"Resolved path: {resolved_path}")
    
    print()
    
    # Test with parentheses method for comparison
    resolved_with_parentheses = resolver.resolve_path_with_guid(test_path)
    print(f"With parentheses: {resolved_with_parentheses}")

if __name__ == "__main__":
    test_missing_guid() 