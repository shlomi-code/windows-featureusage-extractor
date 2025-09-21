"""
Windows Known Folder GUID Resolver

This module provides functionality to resolve Windows Known Folder GUIDs
to their display names and paths based on Microsoft's documentation.
"""

from typing import Dict, Optional, Tuple


class GUIDResolver:
    """Resolves Windows Known Folder GUIDs to their display names and paths."""
    
    # Known Folder GUIDs mapping based on Microsoft documentation
    # Source: https://learn.microsoft.com/en-us/windows/win32/shell/knownfolderid
    KNOWN_FOLDERS = {
        # System folders
        "{F38BF404-1D43-42F2-9305-67DE0B28FC23}": ("Windows", "%windir%"),
        "{D65231B0-B2F1-4857-A4CE-A8E7C6EA7D27}": ("System32", "%windir%\\system32"),
        "{6D809377-6AF0-444B-8957-A3773F02200E}": ("Program Files", "%ProgramFiles%"),
        "{7C5A40EF-A0FB-4BFC-874A-C0F2E0B9FA8E}": ("Program Files", "%ProgramFiles%"),
        "{905E63B6-C1BF-494E-B29C-65B732D3D21A}": ("Program Files (x86)", "%ProgramFiles(x86)%"),
        "{FDD39AD0-238F-46AF-ADB4-6C85480369C7}": ("Program Files Common", "%ProgramFiles%\\Common Files"),
        "{DE974D24-D9C6-4D3E-BF91-F4455120B917}": ("Program Files Common (x86)", "%ProgramFiles(x86)%\\Common Files"),
        
        # User folders
        "{59031A47-3F72-44A7-89C5-5595FE6B30EE}": ("User Profile", "%USERPROFILE%"),
        "{F3CE0F7C-4901-4ACC-8648-D5D44B04EF8F}": ("User Files", "%USERPROFILE%"),
        "{A520A1A4-1780-4FF6-BD18-167340C94916}": ("AppData Local", "%LOCALAPPDATA%"),
        "{3EB685DB-65F9-4CF6-A03A-E3EF65729F3D}": ("AppData Roaming", "%APPDATA%"),
        "{B4BFCC3A-DB2C-424C-B029-7FE99A87C641}": ("Desktop", "%USERPROFILE%\\Desktop"),
        "{4C5C32FF-BB9D-43B0-B5B4-2D72E54EAAA4}": ("Documents", "%USERPROFILE%\\Documents"),
        "{18989B1D-99B5-455B-841C-AB7C74E4DDFC}": ("Videos", "%USERPROFILE%\\Videos"),
        "{3ADD1653-EB32-4CB0-BBD7-DFA0ABB5ACCA}": ("Pictures", "%USERPROFILE%\\Pictures"),
        "{4BD8D571-6D19-48D3-BE97-422220080E43}": ("Music", "%USERPROFILE%\\Music"),
        "{374DE290-123F-4565-9164-39C4925E467B}": ("Downloads", "%USERPROFILE%\\Downloads"),
        "{1777F761-68AD-4D8A-87BD-30B759FA33DD}": ("Favorites", "%USERPROFILE%\\Favorites"),
        "{BFB9D5E0-C6A9-404C-B2B2-AE6DB6AF4968}": ("Links", "%USERPROFILE%\\Links"),
        "{A75D362E-50FC-4FB7-AC2C-A8BEAA314493}": ("Contacts", "%USERPROFILE%\\Contacts"),
        "{56784854-C6CB-462B-8169-88E350ACB882}": ("Searches", "%USERPROFILE%\\Searches"),
        "{625B53C3-AB48-4EC1-BA1F-A1EF4146FC19}": ("Saved Games", "%USERPROFILE%\\Saved Games"),
        "{B97D20BB-F46A-4C97-BA10-5E3608430854}": ("Start Menu", "%APPDATA%\\Microsoft\\Windows\\Start Menu"),
        "{A77F5D77-2E2B-44C3-A6A2-ABA601054A51}": ("Programs", "%APPDATA%\\Microsoft\\Windows\\Start Menu\\Programs"),
        "{724EF170-A42D-4FEF-9F26-B60E846FBA4F}": ("Administrative Tools", "%APPDATA%\\Microsoft\\Windows\\Start Menu\\Programs\\Administrative Tools"),
        
        # System special folders
        "{C4AA340D-F20F-4863-AFEF-F87EF2E6BA25}": ("Public Desktop", "%PUBLIC%\\Desktop"),
        "{ED4824AF-DCE4-45A8-81E2-FC7965083634}": ("Public Documents", "%PUBLIC%\\Documents"),
        "{3214FAB5-9757-4298-BB61-92A9DEAA44FF}": ("Public Music", "%PUBLIC%\\Music"),
        "{B6EBFB86-6907-413C-9AF7-4FC2ABF07CC5}": ("Public Pictures", "%PUBLIC%\\Pictures"),
        "{E555AB60-153B-4D17-9F04-A5FE249FC951}": ("Public Videos", "%PUBLIC%\\Videos"),
        "{62AB5D82-FDC1-4DC3-A9DD-070D1D495D97}": ("ProgramData", "%ProgramData%"),
        "{D0384E7D-BAC3-4797-8F14-CBA229B392B5}": ("Common Administrative Tools", "%ProgramData%\\Microsoft\\Windows\\Start Menu\\Programs\\Administrative Tools"),
        "{0139D44E-6AFE-49F2-8690-3DAFCAE6FFB8}": ("Common Programs", "%ProgramData%\\Microsoft\\Windows\\Start Menu\\Programs"),
        "{A4115719-D62E-491D-AA7C-E74B8BE3B067}": ("Common Start Menu", "%ProgramData%\\Microsoft\\Windows\\Start Menu"),
        "{82A5EA35-D9CD-47C5-9629-E15D2F714E6E}": ("Common Startup", "%ProgramData%\\Microsoft\\Windows\\Start Menu\\Programs\\Startup"),
        "{942A7AC1-5A8D-4A2C-9E4A-9C8E7AE3C51B}": ("Common Templates", "%ProgramData%\\Microsoft\\Windows\\Templates"),
        
        # Windows specific folders
        "{1AC14E77-02E7-4E5D-B744-2EB1AE5198B7}": ("System", "%windir%\\system32"),
        "{D9DC8A3B-B784-432E-A781-5A1130A75963}": ("System (x86)", "%windir%\\syswow64"),
        "{F1B32785-6FBA-4FCF-9D55-7B8E7F157091}": ("Local AppData Low", "%USERPROFILE%\\AppData\\LocalLow"),
        "{A520A1A4-1780-4FF6-BD18-167340C94916}": ("Local AppData", "%LOCALAPPDATA%"),
        "{3EB685DB-65F9-4CF6-A03A-E3EF65729F3D}": ("Roaming AppData", "%APPDATA%"),
        "{B2C5E279-7ADD-439F-B28C-C41FE1BBF672}": ("AppData Desktop", "%LOCALAPPDATA%\\Desktop"),
        "{7BE16610-1F7F-44AC-BFF0-83E15F2FFCA1}": ("AppData Documents", "%LOCALAPPDATA%\\Documents"),
        "{7CFBEFBC-DE1F-45AA-B843-A542AC536CC9}": ("AppData Favorites", "%LOCALAPPDATA%\\Favorites"),
        "{559D40A3-A036-40FA-AF61-84CB430A4D34}": ("AppData ProgramData", "%LOCALAPPDATA%\\ProgramData"),
        "{A3918781-E5F2-4890-B3D9-A7E54332328C}": ("Application Shortcuts", "%LOCALAPPDATA%\\Microsoft\\Windows\\Application Shortcuts"),
        
        # Windows 10+ specific folders
        "{008CA0B1-55B4-4C56-B8A8-4DE4B299D3BE}": ("Account Pictures", "%APPDATA%\\Microsoft\\Windows\\AccountPictures"),
        "{AB5FB87B-7CE2-4F83-915D-550846C9537B}": ("Camera Roll", "%USERPROFILE%\\Pictures\\Camera Roll"),
        "{9E52AB10-F80D-49DF-ACB8-4330F5687855}": ("CD Burning", "%LOCALAPPDATA%\\Microsoft\\Windows\\Burn\\Burn"),
        "{DF7266AC-9274-4867-8D55-3BD661DE872D}": ("Programs and Features", "Control Panel\\Programs and Features"),
        "{A302545D-DEFF-464B-ABE8-61C8648D939B}": ("Libraries", "%APPDATA%\\Microsoft\\Windows\\Libraries"),
        
        # Virtual folders
        "{DE61D971-5EBC-4F02-A3A9-6C82895E5C04}": ("Add New Programs", "Virtual Folder"),
        "{1E87508D-89C2-42F0-8A7E-645A0F50CA58}": ("Applications", "Virtual Folder"),
        "{A305CE99-F527-492B-8B1A-7E76FA98D6E4}": ("Installed Updates", "Virtual Folder"),
        "{F3CE0F7C-4901-4ACC-8648-D5D44B04EF8F}": ("User Files", "Virtual Folder"),
    }
    
    def __init__(self):
        """Initialize the GUID resolver."""
        pass
    
    def resolve_guid(self, guid: str) -> Optional[Tuple[str, str]]:
        """
        Resolve a GUID to its display name and path.
        
        Args:
            guid: The GUID string (with or without braces)
            
        Returns:
            Tuple of (display_name, path) or None if not found
        """
        # Remove braces if present
        clean_guid = guid.strip('{}')
        
        # Add braces back for lookup
        lookup_guid = f"{{{clean_guid}}}"
        
        return self.KNOWN_FOLDERS.get(lookup_guid)
    
    def resolve_path_with_guid(self, path: str) -> str:
        """
        Resolve GUIDs in a path string to their display names and paths.
        
        Args:
            path: Path string that may contain GUIDs
            
        Returns:
            Path string with resolved GUIDs in parentheses
        """
        import re
        
        # Pattern to match GUIDs in paths
        guid_pattern = r'\{[0-9A-Fa-f]{8}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{12}\}'
        
        def replace_guid(match):
            guid = match.group(0)
            resolved = self.resolve_guid(guid)
            if resolved:
                display_name, path_template = resolved
                return f"{guid} ({display_name}: {path_template})"
            return guid
        
        return re.sub(guid_pattern, replace_guid, path)
    
    def replace_guid_with_resolved(self, path: str) -> str:
        """
        Replace GUIDs in a path string with their resolved values.
        
        Args:
            path: Path string that may contain GUIDs
            
        Returns:
            Path string with GUIDs replaced by their resolved values
        """
        import re
        
        # Pattern to match GUIDs in paths
        guid_pattern = r'\{[0-9A-Fa-f]{8}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{12}\}'
        
        def replace_guid(match):
            guid = match.group(0)
            resolved = self.resolve_guid(guid)
            if resolved:
                display_name, path_template = resolved
                # Replace the GUID with the resolved path template
                return path_template
            return guid
        
        return re.sub(guid_pattern, replace_guid, path)
    
    def get_all_known_folders(self) -> Dict[str, Tuple[str, str]]:
        """
        Get all known folder mappings.
        
        Returns:
            Dictionary of GUID to (display_name, path) mappings
        """
        return self.KNOWN_FOLDERS.copy() 