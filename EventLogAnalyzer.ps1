# Example usage:
# Search-EventLogs -logName 'Security' -maxRecords 10000 -daysBack 7 -dumpImportant -dumpSensitive -dumpSmb -Verbose -json -outputDir 'C:\Logs' -MaskSensitive
# Search-EventLogs -logName '*' -maxRecords 10000 -daysBack 7 -dumpSensitive -dumpSmb -Verbose
# To view the help menu, use: Search-EventLogs -help
# Author: Zyad-Elsayed
# GitHub Repository: https://github.com/Zyad-Elsayed/EventLogAnalyzer.git


# Define default sensitive information patterns
$defaultPatterns = @(
    'password\s*[:=]\s*\S+',    # Matches "password: <value>" or "password = <value>"
    'username\s*[:=]\s*\S+',    # Matches "username: <value>" or "username = <value>"
    '\bapi\s*key\b',           # Matches "api key"
    '\baccess\s*token\b',      # Matches "access token"
    '\bsecret\s*key\b',        # Matches "secret key"
    '\bAuthorization\s*[:=]\s*\S+', # Matches "Authorization: <token>" or "Authorization = <token>"
    'Bearer\s+\S+'             # Matches "Bearer <token>"
)

# Define default SMB share detection patterns
$defaultSmbPatterns = @(
    'SMB\s*share\s*name\s*:\s*\S+',  # Matches "SMB share name: <name>"
    'SMB\s*share\s*access\s*:\s*\S+', # Matches "SMB share access: <access>"
    'Account\s*Name\s*:\s*\S+',      # Matches "Account Name: <name>"
    'Share\s*Name\s*:\s*\S+'         # Matches "Share Name: <name>"
)

# Function to handle error logging
function Log-Error {
    param (
        [string]$message
    )
    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    Add-Content -Path "error_log.txt" -Value "$timestamp - ERROR: $message"
}

# Function to mask sensitive data partially
function Mask-SensitiveData {
    param (
        [string]$data
    )
    # Example: Mask all but last 4 characters of any sensitive string
    return ($data -replace '\S{5,}', {'*' * ($args[0].Length - 4) + $args[0][-4..-1]})
}

# Function to export results to JSON or CSV
function Export-Results {
    param (
        [string]$type,
        [array]$data,
        [string]$filename,
        [string]$outputDir = (Get-Location).Path,
        [switch]$json
    )

    $fullPath = Join-Path -Path $outputDir -ChildPath "$filename"

    if ($json) {
        $data | ConvertTo-Json | Out-File -FilePath "$fullPath.json" -Force
        Write-Host "$type exported to $fullPath.json" -ForegroundColor Cyan
    } else {
        $data | Export-Csv -Path "$fullPath.csv" -NoTypeInformation -Force
        Write-Host "$type exported to $fullPath.csv" -ForegroundColor Cyan
    }
}

# Function to process each log entry
function Process-LogEntry {
    param (
        [System.Diagnostics.EventLogEntry]$entry,
        [System.Diagnostics.EventLog]$log,
        [System.Collections.Generic.List[PSObject]]$importantEvents,
        [System.Collections.Generic.List[PSObject]]$sensitiveMatches,
        [System.Collections.Generic.List[PSObject]]$smbShareInfo,
        [array]$patterns,
        [array]$smbPatterns,
        [switch]$Verbose,
        [switch]$Debug,
        [switch]$MaskSensitive
    )

    $message = $entry.Message

    # Add to important events list
    if ($entry.EntryType -eq 'Error' -or $entry.EntryType -eq 'Warning') {
        $importantEvents.Add([PSCustomObject]@{
            LogName = $log.Log
            TimeGenerated = $entry.TimeGenerated
            EventID = $entry.EventID
            EntryType = $entry.EntryType
            Source = $entry.Source
            Message = $message
        })
        if ($Verbose) {
            Write-Host "Important Event Found: $message" -ForegroundColor Yellow
        }
    }

    # Check for sensitive information and add to sensitive matches list
    foreach ($pattern in $patterns) {
        if ($message -match $pattern) {
            $maskedMessage = $message
            if ($MaskSensitive) {
                $maskedMessage = Mask-SensitiveData -data $message
            }
            $sensitiveMatches.Add([PSCustomObject]@{
                LogName = $log.Log
                TimeGenerated = $entry.TimeGenerated
                EventID = $entry.EventID
                Source = $entry.Source
                Message = $maskedMessage
                MatchedPattern = $pattern
            })
            if ($Verbose) {
                Write-Host "Sensitive Information Found: $maskedMessage" -ForegroundColor Red
            }
        }
    }

    # Check for SMB share information
    foreach ($smbPattern in $smbPatterns) {
        if ($message -match $smbPattern) {
            $smbShareInfo.Add([PSCustomObject]@{
                LogName = $log.Log
                TimeGenerated = $entry.TimeGenerated
                EventID = $entry.EventID
                Source = $entry.Source
                Message = $message
                MatchedPattern = $smbPattern
            })
            if ($Verbose) {
                Write-Host "SMB Share Information Found: $message" -ForegroundColor Cyan
            }
        }
    }

    if ($Debug) {
        Write-Host "Processed entry from $($log.Log): $message" -ForegroundColor Magenta
    }
}

# Function to display help information
function Show-Help {
    Write-Host "Usage: Search-EventLogs [-logName <string>] [-maxRecords <int>] [-daysBack <int>] [-dumpImportant] [-dumpSensitive] [-dumpSmb] [-Verbose] [-Debug] [-json] [-outputDir <path>] [-MaskSensitive]" -ForegroundColor Cyan
    Write-Host " "
    Write-Host "Parameters:" -ForegroundColor Yellow
    Write-Host "  -logName        : The name of the event log to search (use '*' to search all logs, default is 'Security')." -ForegroundColor Green
    Write-Host "  -maxRecords     : The maximum number of log records to retrieve per log (default is 10000)." -ForegroundColor Green
    Write-Host "  -daysBack       : The number of days to look back in the logs (default is 7)." -ForegroundColor Green
    Write-Host "  -dumpImportant  : Export the most important events." -ForegroundColor Green
    Write-Host "  -dumpSensitive  : Export events with sensitive information." -ForegroundColor Green
    Write-Host "  -dumpSmb        : Export SMB share information." -ForegroundColor Green
    Write-Host "  -Verbose        : Display detailed output for debugging." -ForegroundColor Green
    Write-Host "  -Debug          : Display debug information." -ForegroundColor Green
    Write-Host "  -json           : Export results in JSON format (default is CSV)." -ForegroundColor Green
    Write-Host "  -outputDir      : Specify the output directory for exported files." -ForegroundColor Green
    Write-Host "  -MaskSensitive  : Mask sensitive data before exporting." -ForegroundColor Green
    Write-Host "  -help           : Display this help message." -ForegroundColor Green
    Write-Host " "
    Write-Host "Example usage:" -ForegroundColor Yellow
    Write-Host "  Search-EventLogs -logName 'Security' -maxRecords 5000 -daysBack 14 -dumpImportant -dumpSensitive -json -outputDir 'C:\Logs' -MaskSensitive -Verbose" -ForegroundColor Cyan
    Write-Host "  Search-EventLogs -logName '*' -maxRecords 10000 -daysBack 7 -dumpSensitive -dumpSmb -Verbose" -ForegroundColor Cyan
    Write-Host " "
}

# Main function to search event logs
function Search-EventLogs {
    param(
        [string]$logName = 'Security',
        [int]$maxRecords = 10000,
        [int]$daysBack = 7,
        [switch]$dumpImportant, # Dump important events
        [switch]$dumpSensitive, # Dump sensitive events
        [switch]$dumpSmb,       # Dump SMB share information
        [switch]$help,          # Help switch parameter
        [switch]$Verbose,       # Verbose switch parameter
        [switch]$Debug,         # Debug switch parameter
        [switch]$json,          # Export as JSON
        [string]$outputDir,     # Output directory
        [array]$customPatterns, # User-defined patterns
        [array]$customSmbPatterns, # User-defined SMB patterns
        [switch]$MaskSensitive  # Mask sensitive information
    )

    # Display help menu if the help switch is used
    if ($help) {
        Show-Help
        return
    }

    # Set output directory
    if (-not $outputDir) {
        $outputDir = (Get-Location).Path
    }

    # Use default patterns if custom ones are not provided
    $patterns = if ($customPatterns) { $customPatterns } else { $defaultPatterns }
    $smbPatterns = if ($customSmbPatterns) { $customSmbPatterns } else { $defaultSmbPatterns }

    # Initialize the error action preference to stop on errors
    $ErrorActionPreference = 'Stop'

    # Initialize lists to hold matching log entries as strongly-typed lists
    $importantEvents = New-Object System.Collections.Generic.List[PSObject]
    $sensitiveMatches = New-Object System.Collections.Generic.List[PSObject]
    $smbShareInfo = New-Object System.Collections.Generic.List[PSObject]

    try {
        # Handle case where logName is '*'
        if ($logName -eq '*') {
            # Get all event logs on the system
            $eventLogs = [System.Diagnostics.EventLog]::GetEventLogs()

            foreach ($log in $eventLogs) {
                try {
                    Write-Host "Processing log: $($log.Log)" -ForegroundColor Yellow
                    $entries = $log.Entries | Where-Object { $_.TimeGenerated -gt (Get-Date).AddDays(-$daysBack) } | Select-Object -Last $maxRecords
                    foreach ($entry in $entries) {
                        Process-LogEntry -entry $entry -log $log -importantEvents $importantEvents -sensitiveMatches $sensitiveMatches -smbShareInfo $smbShareInfo -patterns $patterns -smbPatterns $smbPatterns -Verbose:$Verbose -Debug:$Debug -MaskSensitive:$MaskSensitive
                    }
                } catch {
                    Log-Error "Unable to process log '$($log.Log)': $_"
                }
            }
        } else {
            # Process a single specified event log
            $log = New-Object System.Diagnostics.EventLog($logName)
            Write-Host "Processing log: $logName" -ForegroundColor Yellow
            try {
                $entries = $log.Entries | Where-Object { $_.TimeGenerated -gt (Get-Date).AddDays(-$daysBack) } | Select-Object -Last $maxRecords
                foreach ($entry in $entries) {
                    Process-LogEntry -entry $entry -log $log -importantEvents $importantEvents -sensitiveMatches $sensitiveMatches -smbShareInfo $smbShareInfo -patterns $patterns -smbPatterns $smbPatterns -Verbose:$Verbose -Debug:$Debug -MaskSensitive:$MaskSensitive
                }
            } catch {
                Log-Error "Error processing event log '$logName': $_"
            }
        }

        # Generate timestamp for output files
        $timestamp = (Get-Date).ToString("yyyyMMdd-HHmmss")

        # Export important events if the option is selected
        if ($dumpImportant -and $importantEvents.Count -gt 0) {
            Export-Results -type "Important events" -data $importantEvents -filename "important_events_$timestamp" -outputDir $outputDir -json:$json
        }

        # Export sensitive matches if the option is selected
        if ($dumpSensitive -and $sensitiveMatches.Count -gt 0) {
            Export-Results -type "Sensitive information" -data $sensitiveMatches -filename "sensitive_information_$timestamp" -outputDir $outputDir -json:$json
        }

        # Export SMB share information if the option is selected
        if ($dumpSmb -and $smbShareInfo.Count -gt 0) {
            Export-Results -type "SMB share information" -data $smbShareInfo -filename "smb_share_information_$timestamp" -outputDir $outputDir -json:$json
        }

        # Summary Report
        Write-Host "Summary Report" -ForegroundColor Green
        Write-Host "------------------------------------" -ForegroundColor Green
        Write-Host "Total Logs Processed: $($importantEvents.Count + $sensitiveMatches.Count + $smbShareInfo.Count)" -ForegroundColor Green
        Write-Host "Important Events Found: $($importantEvents.Count)" -ForegroundColor Green
        Write-Host "Sensitive Information Found: $($sensitiveMatches.Count)" -ForegroundColor Green
        Write-Host "SMB Share Information Found: $($smbShareInfo.Count)" -ForegroundColor Green
        Write-Host "Output Directory: $outputDir" -ForegroundColor Green
        Write-Host "------------------------------------" -ForegroundColor Green

        if ($dumpImportant -and $importantEvents.Count -eq 0) {
            Write-Host "No important events found." -ForegroundColor Yellow
        }

        if ($dumpSensitive -and $sensitiveMatches.Count -eq 0) {
            Write-Host "No events with sensitive information found." -ForegroundColor Red
        }

        if ($dumpSmb -and $smbShareInfo.Count -eq 0) {
            Write-Host "No SMB share information found." -ForegroundColor Red
        }

    } catch {
        Log-Error "Error processing event logs: $_"
    }
}

