# Windows FeatureUsage Analyzer

<div align="center">
  <img src="icon.svg" alt="Windows FeatureUsage Analyzer Icon" width="128" height="128">
</div>

*The icon represents the tool's core functionality: Windows registry analysis (blue background with Windows squares), forensic investigation (magnifying glass), and data extraction (golden registry bars with scanning lines and flow arrows).*

A Python script to extract FeatureUsage artifacts from the Windows registry for forensic analysis and user behavior tracking.

## Overview

This tool extracts FeatureUsage data from the Windows registry, which tracks user interactions with various Windows features including:

- **AppSwitched**: Tracks application switching behavior
- **StartMenu**: Records Start Menu usage patterns
- **Search**: Monitors search functionality usage

## Features

- Extracts FeatureUsage data for the currently running user
- Parses binary registry data structures
- Converts Windows FILETIME timestamps to readable format
- Generates detailed JSON reports with separate AppSwitched sections
- Provides summary statistics
- No external dependencies required

## Requirements

- Windows operating system
- Python 3.6 or higher
- Administrative privileges (recommended for full access)

## Installation

1. Clone or download this repository
2. Ensure Python 3.6+ is installed
3. No additional dependencies required (uses only Python standard library)

## Usage

### Basic Usage

```bash
python featureusage_extractor.py
```

### Output

The script generates:
- Console output with extraction progress and detailed summary
- JSON file with detailed extraction results (timestamped filename)
- Separate sections for general FeatureUsage and AppSwitched-specific data

### Example Output

```
Windows FeatureUsage Artifact Extractor
==================================================
Starting FeatureUsage artifact extraction...
Current User SID: Current User
--------------------------------------------------
Extracting AppSwitched FeatureUsage data...
Extracting StartMenu FeatureUsage data...
Extracting Search FeatureUsage data...

Extraction completed!
Total entries found: 150
AppSwitched entries: 45
StartMenu entries: 67
Search entries: 38
Total AppSwitched-related entries: 45

Results saved to: featureusage_extraction_20231201_143022.json
```

## Registry Locations

The script extracts data from the following registry paths:

### Standard FeatureUsage
- `HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\FeatureUsage\AppSwitched`
- `HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\FeatureUsage\StartMenu`
- `HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\FeatureUsage\Search`



## Data Structure

Each extracted entry contains:

- **timestamp**: ISO format timestamp of the activity
- **app_id**: Application identifier (for standard entries)
- **usage_count**: Number of times the feature was used (for standard entries)
- **additional_data**: Additional binary data
- **source**: Data source (AppSwitched, StartMenu, or Search)
- **value_name**: Registry value name
- **raw_timestamp**: Original Windows FILETIME value



## Forensic Value

FeatureUsage data provides valuable forensic information:

- User behavior patterns and application usage
- Application switching timeline reconstruction
- Feature interaction history and frequency
- Evidence of user activity and system usage
- Start Menu interaction patterns
- Search functionality usage patterns

## Limitations

- Only extracts data for the currently running user
- Requires appropriate permissions to access registry
- Binary data parsing may vary between Windows versions
- Some entries may be encrypted or compressed
- Binary data structure may vary by Windows version

## Security Considerations

- Run with appropriate permissions
- Be aware of privacy implications
- Handle extracted data securely
- Consider legal requirements for data collection

## Troubleshooting

### Common Issues

1. **Permission Denied**: Run as administrator
2. **No Data Found**: Check if FeatureUsage is enabled
3. **Parsing Errors**: May indicate different data format
4. **Parsing Errors**: May indicate different Windows version

### Debug Mode

For troubleshooting, the script provides detailed error messages and progress information.

## Contributing

Contributions are welcome! Please consider:

- Adding support for additional registry locations
- Improving binary data parsing for different Windows versions
- Adding data visualization features
- Enhancing error handling and recovery
- Adding support for other Windows artifacts

## License

This project is licensed under the MIT License - see the LICENSE file for details.

## References

- [The Windows Forensic Journey: FeatureUsage](https://medium.com/@boutnaru/the-windows-forensic-journey-featureusage-aed8f14c84ab)
- [The Windows Forensic Journey: AppSwitched](https://medium.com/@boutnaru/the-windows-forensic-journey-appswitched-55abc690f0f0)
- [The Windows Forensic Journey: ShowJumpView](https://medium.com/@boutnaru/the-windows-forensic-journey-showjumpview-ec24a17ecaf0)
- [The Windows Forensic Journey: AppLaunch](https://medium.com/@boutnaru/the-windows-forensic-journey-applaunch-617c0635e126)

## Disclaimer

This tool is for educational and forensic purposes only. Always ensure you have proper authorization before extracting data from systems you don't own. 