
A PowerShell-based tool to collect forensic artifacts from Windows systems.  
It generates an HTML forensic report including processes, services, network info, registry hives, autoruns, event logs, and more.

## Features
- Collects processes, services, network connections, event logs
- Extracts autoruns and scheduled tasks
- Gathers browser history (Chrome, Edge) using `sqlite3.exe`
- Lists recent files, prefetch data, USB history
- Exports registry hives
- Generates HTML report with all findings

## Requirements
- Windows 10/11 with PowerShell 5.1+ or PowerShell 7+
- `sqlite3.exe` available in PATH (needed for browser history extraction)
- Run as Administrator for full access

## Usage
1. Clone the repository:
   ```powershell
   git clone https://github.com/yourusername/windows-forensic-toolkit.git
   cd windows-forensic-toolkit
2.Run the script (preferably as Administrator):

.\ForensicToolkit.ps1


3.The report will be generated under:

C:\ForensicReport_YYYYMMDD_HHMMSS\ForensicReport.html
