#!/usr/bin/env python3
"""
Windows Registry Access Module

This module provides a centralized interface for accessing Windows registry
operations used by the FeatureUsage extractor.
"""

import winreg
from typing import Dict, List, Any, Optional, Tuple, Union
from datetime import datetime

# Type alias for registry key objects
RegistryKey = Any  # winreg.HKEYType is not available in all Python versions


class RegistryAccess:
    """Centralized registry access operations for Windows FeatureUsage extraction."""
    
    def __init__(self):
        """Initialize the registry access class."""
        pass
    
    def open_key(self, hkey: int, subkey: str) -> Optional[RegistryKey]:
        """
        Open a registry key.
        
        Args:
            hkey: Registry hive (e.g., winreg.HKEY_CURRENT_USER)
            subkey: Registry subkey path
            
        Returns:
            Registry key object or None if failed
        """
        try:
            return winreg.OpenKey(hkey, subkey)
        except Exception as e:
            print(f"Error opening registry key {hkey}\\{subkey}: {e}")
            return None
    
    def close_key(self, key: RegistryKey) -> None:
        """
        Close a registry key.
        
        Args:
            key: Registry key object to close
        """
        try:
            winreg.CloseKey(key)
        except Exception as e:
            print(f"Error closing registry key: {e}")
    
    def query_info_key(self, key: RegistryKey) -> Optional[Tuple[int, int, int]]:
        """
        Get information about a registry key.
        
        Args:
            key: Registry key object
            
        Returns:
            Tuple of (value_count, subkey_count, last_modified_time) or None if failed
        """
        try:
            return winreg.QueryInfoKey(key)
        except Exception as e:
            print(f"Error querying registry key info: {e}")
            return None
    
    def enum_value(self, key: RegistryKey, index: int) -> Optional[Tuple[str, Any, int]]:
        """
        Enumerate a registry value by index.
        
        Args:
            key: Registry key object
            index: Index of the value to enumerate
            
        Returns:
            Tuple of (value_name, value_data, value_type) or None if failed
        """
        try:
            return winreg.EnumValue(key, index)
        except WindowsError:
            # No more values
            return None
        except Exception as e:
            print(f"Error enumerating registry value at index {index}: {e}")
            return None
    
    def enum_key(self, key: RegistryKey, index: int) -> Optional[str]:
        """
        Enumerate a registry subkey by index.
        
        Args:
            key: Registry key object
            index: Index of the subkey to enumerate
            
        Returns:
            Subkey name or None if failed
        """
        try:
            return winreg.EnumKey(key, index)
        except WindowsError:
            # No more subkeys
            return None
        except Exception as e:
            print(f"Error enumerating registry subkey at index {index}: {e}")
            return None
    
    def query_value_ex(self, key: RegistryKey, value_name: Optional[str] = None) -> Optional[Tuple[Any, int]]:
        """
        Query a registry value.
        
        Args:
            key: Registry key object
            value_name: Name of the value to query (None for default value)
            
        Returns:
            Tuple of (value_data, value_type) or None if failed
        """
        try:
            if value_name is None:
                return winreg.QueryValueEx(key, "")
            else:
                return winreg.QueryValueEx(key, value_name)
        except Exception as e:
            print(f"Error querying registry value {value_name}: {e}")
            return None
    
    def read_registry_value(self, hkey: int, key_path: str, value_name: Optional[str] = None) -> Optional[Any]:
        """
        Read a registry value and return its data.
        
        Args:
            hkey: Registry hive (e.g., winreg.HKEY_CURRENT_USER)
            key_path: Registry key path
            value_name: Name of the value to read (None for default value)
            
        Returns:
            Registry value data or None if failed
        """
        try:
            key = self.open_key(hkey, key_path)
            if key is None:
                return None
            
            result = self.query_value_ex(key, value_name)
            self.close_key(key)
            
            if result is not None:
                return result[0]  # Return just the data, not the type
            return None
            
        except Exception as e:
            print(f"Error reading registry value {hkey}\\{key_path}\\{value_name}: {e}")
            return None
    
    def enumerate_registry_values(self, hkey: int, key_path: str) -> List[Dict[str, Any]]:
        """
        Enumerate all values in a registry key.
        
        Args:
            hkey: Registry hive (e.g., winreg.HKEY_CURRENT_USER)
            key_path: Registry key path
            
        Returns:
            List of dictionaries containing value information
        """
        values = []
        
        try:
            key = self.open_key(hkey, key_path)
            if key is None:
                return values
            
            # Get key information
            key_info = self.query_info_key(key)
            if key_info is not None:
                value_count, subkey_count, _ = key_info
                print(f"  Registry key info: {value_count} values, {subkey_count} subkeys")
            else:
                value_count = 0
                print(f"  Warning: Could not get key info for {key_path}")
            
            if value_count == 0:
                print(f"  ⚠️  No values found in registry key {key_path}")
            
            # Enumerate all values
            i = 0
            while True:
                value_info = self.enum_value(key, i)
                if value_info is None:
                    break
                
                value_name, value_data, value_type = value_info
                
                value_dict = {
                    "name": value_name,
                    "data": value_data,
                    "type": value_type,
                    "type_name": self.get_registry_type_name(value_type),
                    "size": len(value_data) if isinstance(value_data, bytes) else len(str(value_data))
                }
                
                values.append(value_dict)
                print(f"  Found value: {value_name} (type: {value_type}, size: {value_dict['size']})")
                
                i += 1
            
            self.close_key(key)
            
        except Exception as e:
            print(f"Error enumerating registry values in {hkey}\\{key_path}: {e}")
        
        return values
    
    def check_key_exists(self, hkey: int, key_path: str) -> bool:
        """
        Check if a registry key exists.
        
        Args:
            hkey: Registry hive (e.g., winreg.HKEY_CURRENT_USER)
            key_path: Registry key path
            
        Returns:
            True if key exists, False otherwise
        """
        try:
            key = self.open_key(hkey, key_path)
            if key is not None:
                self.close_key(key)
                return True
            return False
        except Exception:
            return False
    
    def get_registry_type_name(self, reg_type: int) -> str:
        """
        Convert registry type to human-readable name.
        
        Args:
            reg_type: Registry type integer
            
        Returns:
            Human-readable registry type name
        """
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
    
    def get_data_preview(self, data: Any, reg_type: int) -> str:
        """
        Get a preview of registry data.
        
        Args:
            data: Registry value data
            reg_type: Registry type
            
        Returns:
            String preview of the data
        """
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
    
    def search_registry_key_recursive(self, key: RegistryKey, search_term: str) -> Optional[str]:
        """
        Recursively search a registry key for a specific term.
        
        Args:
            key: Registry key object
            search_term: Term to search for
            
        Returns:
            Found value or None
        """
        try:
            i = 0
            while True:
                try:
                    subkey_name = self.enum_key(key, i)
                    if subkey_name is None:
                        break
                    
                    # Check if this subkey matches the search term
                    if search_term.lower() in subkey_name.lower():
                        try:
                            subkey = self.open_key(winreg.HKEY_CURRENT_USER, subkey_name)
                            if subkey:
                                result = self._get_value_from_subkey(subkey)
                                self.close_key(subkey)
                                if result:
                                    return result
                        except Exception:
                            continue
                    
                    # Recursively search subkeys
                    try:
                        subkey = self.open_key(winreg.HKEY_CURRENT_USER, subkey_name)
                        if subkey:
                            result = self.search_registry_key_recursive(subkey, search_term)
                            self.close_key(subkey)
                            if result:
                                return result
                    except Exception:
                        continue
                    
                    i += 1
                        
                except WindowsError:
                    break
        except Exception:
            pass
        
        return None
    
    def _get_value_from_subkey(self, subkey: RegistryKey) -> Optional[str]:
        """
        Extract value from a registry subkey.
        
        Args:
            subkey: Registry subkey object
            
        Returns:
            Extracted value or None
        """
        try:
            # Try common display name fields
            display_name_fields = [
                "DisplayName",
                "FriendlyName", 
                "AppName",
                "Name",
                "Title"
            ]
            
            for field in display_name_fields:
                try:
                    result = self.query_value_ex(subkey, field)
                    if result is not None:
                        value, _ = result
                        if value and isinstance(value, str):
                            return value.strip()
                except Exception:
                    continue
            
            # Try default value
            try:
                result = self.query_value_ex(subkey, None)
                if result is not None:
                    value, _ = result
                    if value and isinstance(value, str):
                        return value.strip()
            except Exception:
                pass
                
        except Exception:
            pass
        
        return None 