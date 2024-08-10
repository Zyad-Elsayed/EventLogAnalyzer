# EventLogAnalyzer

## Overview

`EventLogAnalyzer` is a PowerShell script designed to search Windows Event Logs for important events, detect sensitive information, and identify SMB share details. It provides a comprehensive way to analyze event logs, exporting results in either JSON or CSV formats, and includes options to mask sensitive data.

## Description

`EventLogAnalyzer` is a powerful tool tailored for IT professionals and security analysts. It efficiently scans and analyzes Windows Event Logs to detect and report critical events, sensitive information such as passwords or API keys, and SMB share details. With support for exporting results in JSON or CSV formats and options to mask sensitive data, `EventLogAnalyzer` is perfect for auditing, security assessments, and forensic investigations. It simplifies the process of extracting valuable insights from event logs.

## Features

- **Search Across Logs**: Analyze specific event logs or all logs (`*`).
- **Sensitive Data Detection**: Identifies sensitive information such as passwords, API keys, and tokens.
- **SMB Share Information**: Detects and reports SMB share details from logs.
- **Error Logging**: Logs errors encountered during the process to `error_log.txt`.
- **Data Masking**: Optionally masks sensitive data before exporting.
- **Export Options**: Export results in JSON or CSV format.
- **Customization**: Supports custom patterns for both sensitive information and SMB share detection.

## Usage

```powershell
Search-EventLogs [-logName <string>] [-maxRecords <int>] [-daysBack <int>] [-dumpImportant] [-dumpSensitive] [-dumpSmb] [-Verbose] [-Debug] [-json] [-outputDir <path>] [-MaskSensitive] [-help]
```

## Parameters

- **`-logName <string>`**: The name of the event log to search (use `*` to search all logs, default is `Security`).
- **`-maxRecords <int>`**: The maximum number of log records to retrieve per log (default is 10,000).
- **`-daysBack <int>`**: The number of days to look back in the logs (default is 7).
- **`-dumpImportant`**: Export the most important events.
- **`-dumpSensitive`**: Export events with sensitive information.
- **`-dumpSmb`**: Export SMB share information.
- **`-Verbose`**: Display detailed output for debugging.
- **`-Debug`**: Display debug information.
- **`-json`**: Export results in JSON format (default is CSV).
- **`-outputDir <path>`**: Specify the output directory for exported files.
- **`-MaskSensitive`**: Mask sensitive data before exporting.
- **`-help`**: Display this help message.

## Examples

### Example 1: Analyze Security Logs
```powershell
Search-EventLogs -logName 'Security' -maxRecords 5000 -daysBack 14 -dumpImportant -dumpSensitive -json -outputDir 'C:\Logs' -MaskSensitive
```

### Example 2: Search All Logs for Sensitive Information
```powershell
Search-EventLogs -logName '*' -maxRecords 10000 -daysBack 7 -dumpSensitive -dumpSmb -Verbose
```

## Error Logging

Errors encountered during processing are logged in `error_log.txt` in the script's directory.

## Installation

Clone the repository:

```bash
git clone https://github.com/yourusername/EventLogAnalyzer.git
```

Navigate to the directory:

```powershell
Set-Location EventLogAnalyzer
```

Run the script in PowerShell:

```powershell
. .\EventLogAnalyzer.ps1
```

## Contributing

Contributions are welcome! Please submit a pull request or open an issue to discuss your ideas.

## License

This project is licensed under the MIT License.
