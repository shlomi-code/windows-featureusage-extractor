#!/usr/bin/env python3
"""
Unit tests for GUID resolver module
"""

import unittest
import sys
import os

# Add the modules directory to the path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'modules'))

from featureusage.guid_resolver import GUIDResolver


class TestGUIDResolver(unittest.TestCase):
    """Test cases for GUIDResolver class"""
    
    def setUp(self):
        """Set up test fixtures"""
        self.resolver = GUIDResolver()
    
    def test_known_folder_guids(self):
        """Test that known folder GUIDs are properly resolved"""
        # Test some common Windows known folder GUIDs
        test_cases = [
            ("{F38BF404-1D43-42F2-9305-67DE0B28FC23}", "Windows"),
            ("{1AC14E77-02E7-4E5D-B744-2EB1AE5198B7}", "System"),
            ("{D65231B0-B2F1-4857-A4CE-A8E7C6EA7D27}", "System32"),
            ("{F1B32785-6FBA-4FCF-9D55-7B8E7F157091}", "Local AppData Low"),
            ("{A52BBA46-E9E1-435F-B3D9-1D1C9C3E4B5A}", None),  # Non-existent GUID
        ]
        
        for guid, expected in test_cases:
            result = self.resolver.resolve_guid(guid)
            if expected is None:
                self.assertIsNone(result)
            else:
                self.assertIsNotNone(result)
                self.assertEqual(expected, result[0])  # Check display name
    
    def test_replace_guid_with_resolved(self):
        """Test GUID replacement in strings"""
        test_string = "Path: {F38BF404-1D43-42F2-9305-67DE0B28FC23}\\somefile.exe"
        result = self.resolver.replace_guid_with_resolved(test_string)
        
        # Should contain resolved GUID information
        self.assertNotIn("{F38BF404-1D43-42F2-9305-67DE0B28FC23}", result)
        self.assertIn("%windir%", result)
    
    def test_no_guid_in_string(self):
        """Test string without GUIDs"""
        test_string = "This is a normal string without any GUIDs"
        result = self.resolver.replace_guid_with_resolved(test_string)
        
        # Should return the original string unchanged
        self.assertEqual(test_string, result)
    
    def test_multiple_guids_in_string(self):
        """Test string with multiple GUIDs"""
        test_string = "Path1: {F38BF404-1D43-42F2-9305-67DE0B28FC23} Path2: {1AC14E77-02E7-4E5D-B744-2EB1AE5198B7}"
        result = self.resolver.replace_guid_with_resolved(test_string)
        
        # Should resolve both GUIDs
        self.assertNotIn("{F38BF404-1D43-42F2-9305-67DE0B28FC23}", result)
        self.assertNotIn("{1AC14E77-02E7-4E5D-B744-2EB1AE5198B7}", result)
        self.assertIn("%windir%", result)
    
    def test_invalid_guid_format(self):
        """Test handling of invalid GUID formats"""
        invalid_guids = [
            "not-a-guid",
            "{invalid-guid}",
            "12345678-1234-1234-1234-123456789012",  # Missing braces
            "{12345678-1234-1234-1234-12345678901}",  # Too short
        ]
        
        for invalid_guid in invalid_guids:
            result = self.resolver.resolve_guid(invalid_guid)
            self.assertIsNone(result)


if __name__ == '__main__':
    unittest.main()


