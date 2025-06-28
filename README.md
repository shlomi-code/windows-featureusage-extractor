# Windows FeatureUsage Analyzer

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
- Generates detailed JSON reports
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
- Console output with extraction progress and summary
- JSON file with detailed extraction results (timestamped filename)

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

Results saved to: featureusage_extraction_20231201_143022.json
```

## Registry Locations

The script extracts data from the following registry paths:

- `HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\FeatureUsage\AppSwitched`
- `HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\FeatureUsage\StartMenu`
- `HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\FeatureUsage\Search`

## Data Structure

Each extracted entry contains:

- **timestamp**: ISO format timestamp of the activity
- **app_id**: Application identifier
- **usage_count**: Number of times the feature was used
- **source**: Data source (AppSwitched, StartMenu, or Search)
- **value_name**: Registry value name
- **raw_timestamp**: Original Windows FILETIME value

## Forensic Value

FeatureUsage data provides valuable forensic information:

- User behavior patterns
- Application usage timeline
- Feature interaction history
- Evidence of user activity
- Timeline reconstruction

## Limitations

- Only extracts data for the currently running user
- Requires appropriate permissions to access registry
- Binary data parsing may vary between Windows versions
- Some entries may be encrypted or compressed

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

### Debug Mode

For troubleshooting, the script provides detailed error messages and progress information.

## Contributing

Contributions are welcome! Please consider:

- Adding support for additional registry locations
- Improving binary data parsing
- Adding data visualization features
- Enhancing error handling

## License

This project is licensed under the MIT License - see the LICENSE file for details.

## References

- [The Windows Forensic Journey: FeatureUsage](https://medium.com/@boutnaru/the-windows-forensic-journey-featureusage-aed8f14c84ab)
- Windows Registry Forensics documentation
- Microsoft Windows Internals

## Disclaimer

This tool is for educational and forensic purposes only. Always ensure you have proper authorization before extracting data from systems you don't own. 