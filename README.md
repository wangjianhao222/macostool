# macostool
macOS System Information Tool
Overview
The macOS System Information Tool (macos.py) is an advanced Python script designed to collect and display comprehensive system information for macOS systems. Leveraging Python's standard libraries and macOS-specific commands, this tool provides a detailed overview of system configuration, hardware resources, network status, running processes, logged-in users, system logs, and macOS-specific features like Time Machine and kernel extensions. It is tailored for system administrators, developers, and macOS enthusiasts who need a unified, programmatic, and human-readable summary of system metrics for diagnostics, monitoring, or automation.
The script is optimized for macOS, utilizing commands like system_profiler, sw_vers, sysctl, diskutil, and tmutil to extract detailed information. It incorporates robust error handling, UTF-8 encoding for compatibility, and structured data output (via dictionaries and optional JSON) for flexibility in both interactive and automated use cases.
Features
System Overview

OS Details: Retrieves macOS name, version, and build number using sw_vers.
System Metadata: Displays hostname (hostname), kernel information (uname -a), architecture (uname -m), uptime, and load averages (sysctl kern.boottime and vm.loadavg).
Uptime Parsing: Converts boot time to a human-readable uptime string (days, hours, minutes, seconds).

CPU Details

CPU Information: Extracts CPU model, physical core count, and logical processor count using sysctl machdep.cpu.brand_string, hw.physicalcpu, and hw.logicalcpu.

Memory Usage

Memory Metrics: Reports total, used, free, available, and cached memory using sysctl hw.memsize and vm_stat.
Unit Conversion: Converts memory values from bytes or pages to GB for clarity.
Swap Usage: Parses swap total, used, and free space from sysctl vm.swapusage.

Disk Usage

Disk Information: Displays filesystem details, size, used space, available space, capacity percentage, and mount points using df -h.
Structured Output: Returns disk data as a list of dictionaries for programmatic use.

Disk I/O Statistics

I/O Metrics: Captures disk transfer rates, transfers per second, and MB/s using iostat -d -w 1 1.
Device-Specific Data: Organizes metrics by disk device (e.g., disk0, disk1).

Network Information

Interface Details: Collects interface names, IP addresses (IPv4/IPv6), MAC addresses, and status using ifconfig.
Traffic Statistics: Retrieves received and transmitted bytes using netstat -ib.
Network Connections: Lists active connections with protocol, local/remote addresses, and state using netstat -an.

Process List

Top Processes: Displays up to 20 processes sorted by CPU or memory usage using ps aux.
Detailed Output: Includes user, PID, CPU/memory usage, virtual/resident memory, terminal, status, start time, and command.

Logged-in Users

User Sessions: Shows active user sessions with username, terminal, and login time using who.

System Logs

Log Retrieval: Fetches the latest 15 log entries using log show --last 1h, with optional filtering by search term.
Compact Format: Uses log show --style compact for concise output.

Installed Applications

Application List: Scans /Applications for .app bundles and lists their names and paths.

Hardware Overview

Hardware Details: Retrieves model name, identifier, serial number, and other hardware specs using system_profiler SPHardwareDataType.

Battery Information

Battery Status: Reports battery health, cycle count, and capacity for laptops using system_profiler SPPowerDataType.

Sharing Services

Service Status: Lists enabled/disabled sharing services (e.g., Screen Sharing, File Sharing) using system_profiler SPSharingDataType.

Software Updates

Update Check: Simulates checking for macOS software updates (note: softwareupdate -l requires sudo, so simulation is used for demonstration).

Kernel Extensions

Kext List: Displays loaded kernel extensions with index, references, UUID, name, and version using kextstat.

Launch Items

Daemons and Agents: Lists system daemons and user agents with PID, status, and label using launchctl list.

Firewall Status

Packet Filter (pf): Checks the status and loaded rules of the macOS firewall using pfctl -s info and pfctl -s rules (requires sudo).

USB Devices

Connected Devices: Lists USB devices with detailed attributes (e.g., vendor, product) using system_profiler SPUSBDataType.

Bluetooth Devices

Paired Devices: Retrieves paired Bluetooth devices with connection status and attributes using system_profiler SPBluetoothDataType.

Time Machine Status

Backup Status: Reports Time Machine status, progress, and destination using tmutil status.

S.M.A.R.T. Status

Disk Health: Checks S.M.A.R.T. status for specified disks (e.g., disk0, disk1) using diskutil info.

Technical Details
Core Components

Command Execution: Uses a reusable run_command function with subprocess.run to execute macOS commands, capturing stdout/stderr with UTF-8 encoding.
Error Handling:
Handles subprocess.CalledProcessError for command failures, FileNotFoundError for missing commands, and general exceptions.
Provides detailed error messages with return codes and outputs.


Output Parsing:
Employs re module for parsing complex outputs (e.g., uptime, swap usage, network stats).
Structures data into dictionaries for programmatic use.


Dependencies: Relies on standard Python libraries (subprocess, re, platform, json, time, random) and macOS commands (sw_vers, sysctl, vm_stat, df, ifconfig, netstat, ps, who, log, system_profiler, tmutil, diskutil, kextstat, launchctl, pfctl, iostat).

Design Principles

Modularity: Organized into functions for each information category (get_system_overview, get_cpu_details, etc.).
Flexibility: Returns structured data (dictionaries) for integration with other tools or JSON output.
Robustness: Implements comprehensive error handling and fallback mechanisms.
macOS-Specific: Tailored to macOS commands and system structures, ensuring compatibility with macOS Ventura, Monterey, and later.

Requirements

Python: Version 3.6 or higher (uses subprocess.run with text and capture_output).
Operating System: macOS (e.g., Ventura, Monterey, Big Sur).
System Commands: Requires sw_vers, sysctl, vm_stat, df, ifconfig, netstat, ps, who, log, system_profiler, tmutil, diskutil, kextstat, launchctl, pfctl, iostat in the system PATH.
Permissions: Some commands (e.g., pfctl, tmutil) may require sudo or appropriate permissions.

Installation
Prerequisites

Verify Python:python3 --version

macOS typically includes Python 3. Install if needed via Homebrew:brew install python3


Check System Commands:which sw_vers sysctl df ifconfig netstat ps who log system_profiler tmutil diskutil kextstat launchctl pfctl iostat

Most commands are built into macOS. Install Homebrew for missing tools (e.g., iostat may require additional packages).

Setup

Download the Script:curl -O <script_url>/macos.py

Or clone the repository:git clone <repository_url>


Set Permissions:chmod +x macos.py


Run the Script:python3 macos.py



Usage
Basic Execution
Run the script to display system information in the terminal:
python3 macos.py

The output is organized into sections with headers, covering system overview, CPU, memory, disk, network, processes, users, logs, and macOS-specific features.
Example Output
🚀 Collecting macOS System Information... 🚀

--- System Overview ---
--------------------
Os Name: macOS
Os Version: 13.4
Os Build: 22F66
Hostname: MacBook-Pro.local
Kernel Info: Darwin MacBook-Pro.local 22.5.0 Darwin Kernel Version 22.5.0
Architecture: arm64
Uptime: 2 days, 3 hours, 45 minutes, 12 seconds
Boot Time: Mon Mar 15 10:00:00 2023
Load Average: 0.50 0.45 0.40

--- CPU Information ---
--------------------
Model Name: Apple M2
Physical Cores: 8
Logical Processors: 8

--- Memory Usage ---
--------------------
Total Memory Gb: 16.00
Used Memory Gb: 10.23
Free Memory Gb: 2.45
Available Memory Gb: 5.67
Cached Files Gb: 3.22
Swap Total: 8192.00M
Swap Used: 1200.00M
Swap Free: 6992.00M

--- Disk Usage ---
--------------------
Filesystem    Size   Used  Avail Capacity Mounted on
/dev/disk1s1  500G   200G  250G    45%    /

--- Disk I/O Statistics (Snapshot) ---
-----------------------------------
Device           KB/t  xfrs   MB/s
disk0           19.34    23   0.43
disk1           10.00     0   0.00

--- Network Information ---
--------------------
Interface: en0
  Status: active
  MAC Address: 00:1a:2b:3c:4d:5e
  IP Address: IPv4: 192.168.1.100
  Received Bytes: 123456789
  Sent Bytes: 987654321

--- Running Processes ---
--------------------
USER       PID %CPU %MEM    VSZ   RSS TT       STAT START   TIME COMMAND
user      1234  5.2  3.1 123456 78901 ??       S    08:00   0:15 python3

--- Logged-in Users ---
--------------------
user   console  2023-08-14 08:00
admin  ttys000  2023-08-14 09:15

--- System Logs (Recent 15 entries) ---
------------------------------
Aug 14 09:15:01 MacBook-Pro com.apple.xpc.launchd[1]: Starting user manager...

--- Installed Applications ---
-------------------------
- Safari
- Xcode

--- Hardware Overview ---
--------------------
Model Name: MacBook Pro
Model Identifier: MacBookPro18,2
Serial Number: ABC123XYZ

--- Kernel Extensions (kexts) ---
------------------------------
Index Refs Address            Size       Wired      Name (Version) UUID <Linked Against>
1     0   0xffffff8000000000 0x1d4e000  0x1d4e000  com.apple.kpi.libkern (22.5.0) UUID123

--- Launch Items (Daemons & Agents) ---
---------------------------------
--- System Daemons (launchctl list | grep 'com.apple.' for brevity) ---
1234 0 com.apple.locationd
--- User Agents (launchctl list for current user) ---
5678 0 com.example.useragent

--- Firewall (pf) Status ---
-------------------------
Status: Enabled
Rules: 5 active / 10 total

--- USB Devices ---
----------------
Device: USB 3.0 Bus
  Product ID: 0x1234
  Vendor ID: 0x5678

--- Bluetooth Devices ---
-------------------
Device: Magic Keyboard
  Connected: Yes

--- Time Machine Status ---
-------------------------
Time Machine Status: Not Running

--- S.M.A.R.T. Status for disk0 ---
------------------------------
S.M.A.R.T. Status: Verified

✨ Information Collection Complete! ✨

Advanced Usage

Selective Execution: Call specific functions:from macos import get_cpu_details, get_memory_usage
get_cpu_details()
get_memory_usage()


JSON Output: Enable JSON output in main():print(json.dumps(all_info, indent=2))


Automation: Schedule with launchd:launchctl load /path/to/script.plist

Example script.plist:<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>Label</key>
    <string>com.user.systeminfo</string>
    <key>ProgramArguments</key>
    <array>
        <string>python3</string>
        <string>/path/to/macos.py</string>
    </array>
    <key>StartInterval</key>
    <integer>3600</integer>
    <key>StandardOutPath</key>
    <string>/path/to/system_info.log</string>
</dict>
</plist>


Custom Filters: Modify get_system_logs with a search_term:python3 -c "from macos import get_system_logs; get_system_logs(search_term='kernel')"


Output Logging: Save output to a file:python3 macos.py > system_info.txt



Troubleshooting
Common Issues

Command Not Found:
Ensure macOS commands are available. Most are built-in, but tools like iostat may require Homebrew:brew install iostat




Permission Errors:
Run with sudo for commands like pfctl:sudo python3 macos.py




Empty Output:
Verify system services (e.g., launchd, tmutil) are operational.
Check command availability (e.g., log show requires macOS 10.12+).


Parsing Errors:
Inspect raw command outputs for unexpected formats.
Add debug prints in parsing loops.



Debugging Tips

Enable check=True in run_command for specific commands to raise exceptions.
Test individual functions:python3 -c "from macos import get_network_info; get_network_info()"


Log raw outputs for inspection:print(run_command("system_profiler SPUSBDataType", check=False))



Future Enhancements

GUI Interface: Integrate with Tkinter or Flask for interactive visualization.
Real-Time Monitoring: Add continuous updates for metrics like CPU load or network traffic.
Extended Hardware Data: Include GPU, thermal, or fan speed data using powermetrics.
Customizable Output: Support CSV or YAML output formats.
Cross-Version Compatibility: Enhance parsing for older macOS versions (e.g., macOS 10.11).

Contributing
To contribute:

Fork the repository.
Create a feature branch:git checkout -b feature/new-feature


Commit changes:git commit -m "Add new feature"


Push to the branch:git push origin feature/new-feature


Open a pull request with a detailed description.

License
This project is licensed under the MIT License. See the LICENSE file for details.
Acknowledgments

Built with Python standard libraries and macOS utilities.
Inspired by the need for a comprehensive macOS system information tool.
Compatible with macOS Ventura, Monterey, and later.
