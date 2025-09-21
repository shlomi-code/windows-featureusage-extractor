"""
Pytest configuration and fixtures for Windows Feature Usage Analyzer tests
"""

import pytest
import sys
import os
from unittest.mock import Mock, patch

# Add the project root to the path
project_root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, project_root)
sys.path.insert(0, os.path.join(project_root, 'modules'))


@pytest.fixture
def mock_registry():
    """Mock registry access for testing"""
    with patch('featureusage_extractor.RegistryAccess') as mock_registry_class:
        mock_registry = Mock()
        mock_registry_class.return_value = mock_registry
        yield mock_registry


@pytest.fixture
def mock_guid_resolver():
    """Mock GUID resolver for testing"""
    with patch('featureusage_extractor.GUIDResolver') as mock_guid_class:
        mock_resolver = Mock()
        mock_guid_class.return_value = mock_resolver
        yield mock_resolver


@pytest.fixture
def mock_app_resolver():
    """Mock app resolver for testing"""
    with patch('featureusage_extractor.AppResolver') as mock_app_class:
        mock_resolver = Mock()
        mock_app_class.return_value = mock_resolver
        yield mock_resolver


@pytest.fixture
def sample_featureusage_data():
    """Sample FeatureUsage data for testing"""
    return {
        "extraction_time": "2025-01-01T12:00:00",
        "current_user_sid": "test_user",
        "full_user_sid": "S-1-5-21-1234567890-1234567890-1234567890-1001",
        "total_entries": 2,
        "summary": {
            "appswitched_entries": 1,
            "startmenu_entries": 0,
            "search_entries": 0,
            "showjumpview_entries": 1,
            "appbadgeupdated_entries": 0,
            "applaunch_entries": 0
        },
        "featureusage_data": [
            {
                "timestamp": "2025-01-01T12:00:00",
                "app_identifier": "test_app.exe",
                "usage_count": 5,
                "source": "AppSwitched"
            }
        ],
        "appswitched_data": [
            {
                "timestamp": "2025-01-01T12:00:00",
                "app_identifier": "test_app.exe",
                "usage_count": 5,
                "source": "AppSwitched"
            }
        ],
        "showjumpview_data": [
            {
                "timestamp": "2025-01-01T12:01:00",
                "app_identifier": "test_app2.exe",
                "usage_count": 3,
                "source": "ShowJumpView"
            }
        ],
        "appbadgeupdated_data": [],
        "applaunch_data": [],
        "startmenu_data": [],
        "search_data": []
    }


@pytest.fixture
def temp_directory():
    """Temporary directory for testing file operations"""
    import tempfile
    with tempfile.TemporaryDirectory() as temp_dir:
        yield temp_dir


