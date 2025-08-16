import subprocess
import re
import platform
import json # For structured output where applicable
import time # Ensure time is imported

def run_command(command, shell=True, check=False, **kwargs):
    """
    Runs a shell command and returns its standard output.
    Prints an error message and returns None if the command fails.
    """
    try:
        # Use subprocess.run to execute the command and capture output
        result = subprocess.run(
            command,
            shell=shell,
            check=check,  # If check=True, a non-zero exit code will raise CalledProcessError
            text=True,    # Decode stdout and stderr as text
            capture_output=True, # Capture standard output and standard error
            encoding='utf-8', # Explicitly specify encoding to avoid decoding errors
            errors='replace', # Replace undecodable characters
            **kwargs
        )
        if result.returncode != 0 and check:
            print(f"Error: Command '{' '.join(command) if isinstance(command, list) else command}' failed with return code {result.returncode}:")
            print(f"Stdout:\n{result.stdout}")
            print(f"Stderr:\n{result.stderr}")
            return None
        return result.stdout.strip()
    except subprocess.CalledProcessError as e:
        print(f"Error: Command '{' '.join(command) if isinstance(command, list) else command}' failed with return code {e.returncode}:")
        print(f"Stdout:\n{e.stdout}")
        print(f"Stderr:\n{e.stderr}")
        return None
    except FileNotFoundError:
        print(f"Error: Command '{command.split()[0] if isinstance(command, str) else command[0]}' not found. Please ensure it's installed and in your PATH.")
        return None
    except Exception as e:
        print(f"An unexpected error occurred while running command '{command}': {e}")
        return None

def get_system_overview():
    """
    Retrieves and returns basic macOS system information.
    """
    info = {}
    print("\n--- System Overview ---")
    print("-" * 20)

    # macOS Version
    sw_vers_output = run_command("sw_vers")
    if sw_vers_output:
        for line in sw_vers_output.splitlines():
            if "ProductName:" in line:
                info['os_name'] = line.split(":")[1].strip()
            elif "ProductVersion:" in line:
                info['os_version'] = line.split(":")[1].strip()
            elif "BuildVersion:" in line:
                info['os_build'] = line.split(":")[1].strip()

    # Hostname
    hostname_output = run_command("hostname")
    if hostname_output:
        info['hostname'] = hostname_output

    # Kernel Info (uname -a for detailed kernel info)
    kernel_output = run_command("uname -a")
    if kernel_output:
        info['kernel_info'] = kernel_output

    # Architecture
    arch_output = run_command("uname -m")
    if arch_output:
        info['architecture'] = arch_output

    # Uptime and Load Average (using sysctl for more precise info)
    uptime_output = run_command("sysctl -n kern.boottime")
    if uptime_output:
        # kern.boottime: { sec = 1678886400, usec = 0 } Mon Mar 15 10:00:00 2023
        match = re.search(r'\{ sec = (\d+), usec = \d+ \}(.*)', uptime_output)
        if match:
            boot_timestamp = int(match.group(1))
            boot_time_str = match.group(2).strip()
            current_time = int(time.time())
            uptime_seconds = current_time - boot_timestamp
            
            days = uptime_seconds // (24 * 3600)
            uptime_seconds %= (24 * 3600)
            hours = uptime_seconds // 3600
            uptime_seconds %= 3600
            minutes = uptime_seconds // 60
            seconds = uptime_seconds % 60
            
            info['uptime'] = f"{days} days, {hours} hours, {minutes} minutes, {seconds} seconds"
            info['boot_time'] = boot_time_str
    
    load_avg_output = run_command("sysctl -n vm.loadavg")
    if load_avg_output:
        # vm.loadavg: { 0.50 0.45 0.40 }
        match = re.search(r'\{ (.*) \}', load_avg_output)
        if match:
            info['load_average'] = match.group(1)

    for k, v in info.items():
        print(f"{k.replace('_', ' ').title()}: {v}")
    return info

def get_cpu_details():
    """
    Retrieves and returns CPU information for macOS.
    """
    cpu_info = {}
    print("\n--- CPU Information ---")
    print("-" * 20)

    # CPU Model
    model_output = run_command("sysctl -n machdep.cpu.brand_string")
    if model_output:
        cpu_info['model_name'] = model_output

    # Number of physical cores
    cores_output = run_command("sysctl -n hw.physicalcpu")
    if cores_output:
        cpu_info['physical_cores'] = int(cores_output)

    # Number of logical processors (threads)
    logical_output = run_command("sysctl -n hw.logicalcpu")
    if logical_output:
        cpu_info['logical_processors'] = int(logical_output)

    for k, v in cpu_info.items():
        print(f"{k.replace('_', ' ').title()}: {v}")
    return cpu_info

def get_memory_usage():
    """
    Retrieves and returns memory usage information for macOS.
    """
    mem_info = {}
    print("\n--- Memory Usage ---")
    print("-" * 20)

    # Using 'sysctl' for total memory and 'vm_stat' for detailed usage
    total_mem_kb = int(run_command("sysctl -n hw.memsize")) / 1024 # Bytes to KB
    mem_info['total_memory_gb'] = f"{total_mem_kb / (1024 * 1024):.2f}"

    vm_stat_output = run_command("vm_stat")
    if vm_stat_output:
        pagesize = 4096 # Most common page size on macOS

        # Parse vm_stat output
        active_pages = 0
        inactive_pages = 0
        wired_pages = 0
        free_pages = 0
        speculative_pages = 0

        for line in vm_stat_output.splitlines():
            if "Pages active:" in line:
                active_pages = int(re.search(r'\d+', line).group())
            elif "Pages inactive:" in line:
                inactive_pages = int(re.search(r'\d+', line).group())
            elif "Pages wired down:" in line:
                wired_pages = int(re.search(r'\d+', line).group())
            elif "Pages free:" in line:
                free_pages = int(re.search(r'\d+', line).group())
            elif "Pages speculative:" in line:
                speculative_pages = int(re.search(r'\d+', line).group())
        
        # Calculate memory in GB
        total_active_inactive_gb = (active_pages + inactive_pages) * pagesize / (1024**3)
        wired_gb = wired_pages * pagesize / (1024**3)
        free_gb = free_pages * pagesize / (1024**3)
        
        # Simplified calculation for used and available (approximate)
        used_mem_gb = total_active_inactive_gb + wired_gb
        available_mem_gb = free_gb + (inactive_pages * pagesize / (1024**3)) # Inactive can be freed

        mem_info['used_memory_gb'] = f"{used_mem_gb:.2f}"
        mem_info['free_memory_gb'] = f"{free_gb:.2f}"
        mem_info['available_memory_gb'] = f"{available_mem_gb:.2f}" # More user-friendly
        mem_info['cached_files_gb'] = f"{(inactive_pages + speculative_pages) * pagesize / (1024**3):.2f}" # Approximation

    # Swap usage (from sysctl)
    swap_info_output = run_command("sysctl -n vm.swapusage")
    if swap_info_output:
        # vm.swapusage: total = 8192.00M  used = 1200.00M  free = 6992.00M  (encrypted)
        match = re.search(r'total = ([\d.]+[MGT])\s+used = ([\d.]+[MGT])\s+free = ([\d.]+[MGT])', swap_info_output)
        if match:
            mem_info['swap_total'] = match.group(1)
            mem_info['swap_used'] = match.group(2)
            mem_info['swap_free'] = match.group(3)

    for k, v in mem_info.items():
        print(f"{k.replace('_', ' ').title()}: {v}")
    return mem_info

def get_disk_usage():
    """
    Retrieves and returns disk usage information for macOS.
    """
    disk_info_list = []
    print("\n--- Disk Usage ---")
    print("-" * 20)

    df_output = run_command("df -h")
    if df_output:
        lines = df_output.splitlines()
        if len(lines) > 1:
            header = lines[0].split()
            # Adjust header for macOS specific columns if needed, e.g., 'iused', 'ifree', '%iuse'
            # For simplicity, we'll assume standard df -h output for now
            print(lines[0]) # Print header line
            for line in lines[1:]:
                parts = line.split()
                if len(parts) >= 9: # Filesystem, Size, Used, Avail, Capacity, iused, ifree, %iused, Mounted on
                    disk_entry = {
                        "filesystem": parts[0],
                        "size": parts[1],
                        "used": parts[2],
                        "avail": parts[3],
                        "capacity_percent": parts[4],
                        "mounted_on": parts[8]
                    }
                    disk_info_list.append(disk_entry)
                    print(line)
        else:
            print("No disk partition information found.")
    else:
        print("Could not retrieve disk information.")
    return disk_info_list

def get_network_info():
    """
    Retrieves and returns network interface information and statistics for macOS.
    """
    network_interfaces = []
    print("\n--- Network Information ---")
    print("-" * 20)

    # Get basic interface list and IP addresses using ifconfig or ipconfig
    ifconfig_output = run_command("ifconfig")
    if ifconfig_output:
        # Split by interface blocks
        interfaces_raw = re.split(r'^\w+:', ifconfig_output, flags=re.MULTILINE)[1:] # Skip first empty split

        for iface_block in interfaces_raw:
            iface_name_match = re.match(r'^\s*(\w+):', iface_block)
            if not iface_name_match: continue
            iface_name = iface_name_match.group(1).strip()
            
            interface_info = {"name": iface_name, "ips": [], "mac_address": "N/A", "rx_bytes": "N/A", "tx_bytes": "N/A", "status": "Unknown"}

            # IP Addresses
            ipv4_match = re.search(r'inet (\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})', iface_block)
            if ipv4_match:
                interface_info["ips"].append(f"IPv4: {ipv4_match.group(1)}")
            ipv6_match = re.search(r'inet6 ([\da-fA-F:]+)(?:%[\w\d]+)?', iface_block)
            if ipv6_match:
                interface_info["ips"].append(f"IPv6: {ipv6_match.group(1)}")
            
            # MAC Address
            mac_match = re.search(r'ether ([\da-fA-F:]{17})', iface_block)
            if mac_match:
                interface_info["mac_address"] = mac_match.group(1)

            # Status (e.g., UP, DOWN)
            status_match = re.search(r'status: (\w+)', iface_block)
            if status_match:
                interface_info["status"] = status_match.group(1)

            network_interfaces.append(interface_info)

    # Get traffic statistics using netstat -ib for bytes, not just packets
    netstat_output = run_command("netstat -ib")
    if netstat_output:
        lines = netstat_output.splitlines()
        # Header for netstat -ib: Name       Mtu   Network       Address            Ibytes     Obytes
        for line in lines[1:]: # Skip header
            parts = line.split()
            if len(parts) >= 6:
                iface_name = parts[0]
                rx_bytes = parts[4]
                tx_bytes = parts[5]

                for iface in network_interfaces:
                    if iface['name'] == iface_name:
                        iface['rx_bytes'] = rx_bytes
                        iface['tx_bytes'] = tx_bytes
                        break
    
    for iface in network_interfaces:
        print(f"\nInterface: {iface['name']}")
        print(f"  Status: {iface['status']}")
        print(f"  MAC Address: {iface['mac_address']}")
        if iface['ips']:
            for ip in iface['ips']:
                print(f"  IP Address: {ip}")
        else:
            print("  No IP Address")
        print(f"  Received Bytes: {iface['rx_bytes']}")
        print(f"  Sent Bytes: {iface['tx_bytes']}")
    
    if not network_interfaces:
        print("Could not retrieve network information.")

    return network_interfaces

def get_process_list(sort_by='cpu', limit=20):
    """
    Retrieves and returns a list of running processes for macOS.
    Sorts by CPU or memory usage.
    """
    processes = []
    print("\n--- Running Processes ---")
    print("-" * 20)

    # ps aux -c for command basename, sort by %cpu or %mem
    # We'll fetch more than limit and sort in Python for flexibility
    command = "ps aux"
    ps_output = run_command(command)
    if ps_output:
        lines = ps_output.splitlines()
        if not lines: return []

        # Parse header
        # USER PID %CPU %MEM VSZ RSS TT STAT STARTED TIME COMMAND
        
        # Adjusting the command parsing logic for ps aux output
        process_data = []
        for line in lines[1:]:
            parts = line.split(None, 10) # Split by any whitespace, max 10 times
            if len(parts) >= 11:
                try: # Robustness against unexpected output
                    proc = {
                        'USER': parts[0],
                        'PID': int(parts[1]),
                        '%CPU': float(parts[2]),
                        '%MEM': float(parts[3]),
                        'VSZ': parts[4],
                        'RSS': parts[5],
                        'TT': parts[6],
                        'STAT': parts[7],
                        'STARTED': parts[8],
                        'TIME': parts[9],
                        'COMMAND': parts[10]
                    }
                    process_data.append(proc)
                except ValueError as ve:
                    print(f"Warning: Could not parse process line (ValueError): {line} - {ve}")
                    continue
        
        # Sort processes
        if sort_by == 'cpu':
            process_data.sort(key=lambda x: x['%CPU'], reverse=True)
        elif sort_by == 'mem':
            process_data.sort(key=lambda x: x['%MEM'], reverse=True)
        
        # Apply limit
        processes = process_data[:limit]

        # Print formatted output
        print("USER       PID %CPU %MEM    VSZ   RSS TT       STAT START   TIME COMMAND")
        for p in processes:
            print(f"{p['USER']:<9} {p['PID']:<5} {p['%CPU']:<5.1f} {p['%MEM']:<5.1f} {p['VSZ']:<6} {p['RSS']:<6} {p['TT']:<7} {p['STAT']:<7} {p['STARTED']:<6} {p['TIME']:<6} {p['COMMAND']}")
    else:
        print("Could not retrieve process information.")
    return processes

def get_logged_in_users():
    """
    Retrieves and returns currently logged-in users.
    """
    users = []
    print("\n--- Logged-in Users ---")
    print("-" * 20)

    who_output = run_command("who")
    if who_output:
        for line in who_output.splitlines():
            parts = line.split(None, 4) # user tt YYYY-MM-DD HH:MM
            if len(parts) >= 2:
                users.append({"user": parts[0], "tty": parts[1], "login_time": ' '.join(parts[2:])})
            print(line)
    else:
        print("Could not retrieve logged-in user information.")
    return users

def get_system_logs(limit=15, search_term=None):
    """
    Retrieves and returns recent system log entries using the 'log' command.
    """
    logs = []
    print(f"\n--- System Logs (Recent {limit} entries) ---")
    print("-" * 30)

    # macOS uses 'log stream' or 'log show' for system logs
    # 'log stream' is real-time, 'log show' is for historical.
    # We'll use 'log show' for a snapshot.
    # Note: log show can be slow for large time ranges. --last 1h is a good balance.
    command = f"log show --predicate 'processID != 0' --last 1h --style compact | tail -n {limit}"
    if search_term:
        command = f"log show --predicate 'processID != 0' --last 1h --style compact | grep -i '{search_term}' | tail -n {limit}"

    log_output = run_command(command)
    if log_output:
        for line in log_output.splitlines():
            logs.append(line)
            print(line)
    else:
        print("Could not retrieve system logs. Ensure 'log' command is available and you have permissions.")
    return logs

def get_installed_applications():
    """
    Scans the /Applications directory and returns a list of installed applications.
    """
    applications = []
    print("\n--- Installed Applications ---")
    print("-" * 25)

    # Use 'ls -1 /Applications' and filter for .app bundles
    app_list_output = run_command("ls -1 /Applications")
    if app_list_output:
        for line in app_list_output.splitlines():
            if line.endswith(".app"):
                app_name = line.replace(".app", "")
                applications.append({"name": app_name, "path": f"/Applications/{line}"})
                print(f"- {app_name}")
    else:
        print("Could not retrieve installed applications.")
    return applications

def get_hardware_overview():
    """
    Retrieves and returns a brief hardware overview using system_profiler.
    """
    hardware_info = {}
    print("\n--- Hardware Overview ---")
    print("-" * 20)

    # system_profiler SPHardwareDataType
    hw_output = run_command("system_profiler SPHardwareDataType")
    if hw_output:
        for line in hw_output.splitlines():
            line = line.strip()
            if ":" in line:
                key, value = line.split(":", 1)
                hardware_info[key.strip()] = value.strip()
                print(f"{key.strip()}: {value.strip()}")
    else:
        print("Could not retrieve hardware overview.")
    return hardware_info

def get_network_connections():
    """
    Lists active network connections using 'lsof -i'.
    Note: lsof requires root privileges to see all connections.
    """
    connections = []
    print("\n--- Active Network Connections ---")
    print("-" * 30)

    # Using 'lsof -i' to list open network files (connections)
    # This command often requires sudo to see all connections, so a warning is given.
    lsof_output = run_command("lsof -i", check=False) # Don't check=True as it might fail without sudo
    
    if lsof_output:
        print(lsof_output.splitlines()[0]) # Print header
        for line in lsof_output.splitlines()[1:]:
            parts = line.split()
            if len(parts) >= 9:
                conn_info = {
                    "command": parts[0],
                    "pid": parts[1],
                    "user": parts[2],
                    "fd": parts[3],
                    "type": parts[4],
                    "device": parts[5],
                    "size_off": parts[6],
                    "node": parts[7],
                    "name": parts[8] # This contains the IP:Port or domain:service
                }
                connections.append(conn_info)
            print(line)
    else:
        print("Could not retrieve network connections. 'lsof' might require root privileges (sudo).")
    return connections

def get_battery_info():
    """
    Retrieves and returns battery status information for laptops.
    """
    battery_status = {}
    print("\n--- Battery Information ---")
    print("-" * 20)

    # Check if it's a laptop
    if platform.system() == "Darwin" and run_command("sysctl -n hw.laptop") == "1":
        pmset_output = run_command("pmset -g batt")
        if pmset_output:
            for line in pmset_output.splitlines():
                line = line.strip()
                if "Now drawing from" in line:
                    battery_status['power_source'] = line.split(': ')[1]
                elif "charged at" in line:
                    match = re.search(r'(\d+)\% remaining present: (\w+)', line)
                    if match:
                        battery_status['charge_percent'] = match.group(1) + "%"
                        battery_status['is_charging'] = "Yes" if "charging" in line else "No"
                        battery_status['status'] = "Charging" if "charging" in line else "Discharging"
                    
                    # Estimate time remaining if discharging
                    time_remaining_match = re.search(r'\;\s*(\w+)\s+remaining', line)
                    if time_remaining_match:
                        battery_status['time_remaining'] = time_remaining_match.group(1).replace(';', '')
                elif "Battery is charging" in line:
                    battery_status['status'] = "Charging"
                elif "Battery is charged" in line:
                    battery_status['status'] = "Charged"
            
            for k, v in battery_status.items():
                print(f"{k.replace('_', ' ').title()}: {v}")
        else:
            print("Could not retrieve battery information.")
    else:
        print("Not a laptop or battery information not available.")
    return battery_status

def get_sharing_services():
    """
    Retrieves and returns enabled sharing services on macOS.
    This often requires parsing system settings or plist files, which is complex.
    Using 'launchctl list' for common services might give some clues.
    A more direct way is through `defaults read com.apple.Sharing <service_name>` or `scutil`.
    For simplicity, we'll list common services states via system_profiler for now.
    """
    sharing_services = []
    print("\n--- Sharing Services ---")
    print("-" * 20)

    # System Profiler is the most reliable way without elevated privileges.
    # system_profiler SPSharingDataType
    sp_sharing_output = run_command("system_profiler SPSharingDataType")
    if sp_sharing_output:
        current_service = None
        for line in sp_sharing_output.splitlines():
            line = line.strip()
            if line.endswith("Sharing:"): # Start of a new service block
                current_service = line.replace("Sharing:", "").strip()
                sharing_services.append({"name": current_service, "status": "Unknown"})
            elif current_service and "Active:" in line:
                status = "Enabled" if "Yes" in line else "Disabled"
                for s in sharing_services:
                    if s["name"] == current_service:
                        s["status"] = status
                        break
        
        for s in sharing_services:
            print(f"- {s['name']}: {s['status']}")
    else:
        print("Could not retrieve sharing services information.")
    return sharing_services

def check_software_updates():
    """
    Checks for pending macOS software updates.
    """
    update_info = {"status": "Unknown", "updates": []}
    print("\n--- Software Updates ---")
    print("-" * 20)

    # softwareupdate command requires sudo to check/install, but can be run without for list
    # However, 'softwareupdate -l' often prompts for password.
    # We will simulate for demonstration.
    print("Simulating software update check...")
    
    # In a real scenario, you'd run:
    # update_output = run_command("softwareupdate -l", check=False) 
    # if update_output and "No new software available." in update_output:
    #     update_info["status"] = "No updates available"
    # elif update_output:
    #     update_info["status"] = "Updates available"
    #     update_info["updates"] = [line.strip() for line in update_output.splitlines() if not line.startswith("Software Update found") and line.strip()]

    # Simulated data:
    import random # Ensure random is imported for simulation
    if random.random() < 0.7: # 70% chance of no updates
        update_info["status"] = "No new software available."
        print("No new software available.")
    else:
        update_info["status"] = "Updates available"
        update_info["updates"] = [
            "macOS Monterey 12.6.8 Update",
            "Safari 16.5.1 Update",
            "Xcode 14.3.1"
        ]
        print("Updates available:")
        for update in update_info["updates"]:
            print(f"- {update}")
    
    return update_info

# --- NEW FUNCTIONS ---

def get_disk_io_stats():
    """
    Retrieves and returns disk I/O statistics using iostat.
    """
    io_stats = {}
    print("\n--- Disk I/O Statistics (Snapshot) ---")
    print("-" * 35)

    # iostat -d -w 1 output disk transfer rates
    # Using 'iostat -d -w 1 1' to get one snapshot after 1 second
    iostat_output = run_command("iostat -d -w 1 1")
    if iostat_output:
        lines = iostat_output.splitlines()
        if len(lines) >= 3:
            # The last line usually contains the relevant data for the interval
            header = lines[1].split() # Device header line
            data_line = lines[-1].split() # Last data line
            
            # Match header to data. Example:
            # disk0   disk1
            #  KB/t  xfrs   MB/s   KB/t  xfrs   MB/s
            # 19.34    23   0.43  10.00     0   0.00
            
            # This parsing is tricky because 'iostat' output format varies slightly.
            # A simpler approach is to capture the whole block or a specific line.
            # For demonstration, we'll just print the relevant part.
            print("Device           KB/t  xfrs   MB/s")
            # Extracting just the device lines
            device_data_lines = [line for line in lines if not line.startswith(('  tin', '  Tout', 'avg', 'cpu')) and len(line.split()) > 0]
            if len(device_data_lines) >= 3: # Header + 2 lines of device data minimum for -w 1 1
                 # The lines for actual disk stats start from the third line in the -w 1 1 output
                for i in range(2, len(device_data_lines)):
                    parts = device_data_lines[i].split()
                    if len(parts) >= 4: # Should have device name and at least KB/t, xfrs, MB/s
                        device_name = parts[0]
                        kb_per_transfer = parts[1]
                        transfers_per_sec = parts[2]
                        mb_per_sec = parts[3]
                        io_stats[device_name] = {
                            "KB/transfer": kb_per_transfer,
                            "transfers/sec": transfers_per_sec,
                            "MB/sec": mb_per_sec
                        }
                        print(f"{device_name:<15} {kb_per_transfer:<5} {transfers_per_sec:<5} {mb_per_sec:<5}")
        else:
            print("iostat output not in expected format.")
    else:
        print("Could not retrieve disk I/O statistics.")
    return io_stats

def get_kernel_extensions():
    """
    Retrieves and returns a list of loaded kernel extensions (kexts).
    """
    kexts = []
    print("\n--- Kernel Extensions (kexts) ---")
    print("-" * 30)

    kextstat_output = run_command("kextstat")
    if kextstat_output:
        lines = kextstat_output.splitlines()
        if len(lines) > 1:
            print(lines[0]) # Print header
            for line in lines[1:]:
                parts = line.split()
                if len(parts) >= 6: # Index, Refs, Name, Version, UUID, <Linked Against>
                    kext_info = {
                        "index": parts[0],
                        "refs": parts[1],
                        "load_addr_size": parts[2], # Often combined Load Address and Size
                        "uuid": parts[3],
                        "name": parts[4], # This is the bundle ID e.g., com.apple.kpi.libkern
                        "version": parts[5].strip('()'),
                        # The rest might be linked against
                    }
                    kexts.append(kext_info)
                print(line)
        else:
            print("No kernel extensions found or kextstat output is empty.")
    else:
        print("Could not retrieve kernel extension information.")
    return kexts

def get_launch_items():
    """
    Retrieves and returns a list of user and system launch agents/daemons.
    This can be very verbose. We'll show a sample of common system-wide and user-specific.
    """
    launch_items = {"system_daemons": [], "user_agents": []}
    print("\n--- Launch Items (Daemons & Agents) ---")
    print("-" * 35)

    # System Daemons (often requires sudo or runs from a specific user)
    # This lists the system daemons loaded by launchd.
    print("\n--- System Daemons (launchctl list | grep 'com.apple.' for brevity) ---")
    system_launch_output = run_command("launchctl list | grep 'com.apple.'")
    if system_launch_output:
        for line in system_launch_output.splitlines():
            # Example format: PID       Status  Label
            parts = line.split()
            if len(parts) >= 3:
                launch_items['system_daemons'].append({
                    "pid": parts[0],
                    "status": parts[1],
                    "label": parts[2]
                })
                print(line)
    else:
        print("Could not retrieve system daemons.")

    # User Agents (specific to the logged-in user)
    print("\n--- User Agents (launchctl list for current user) ---")
    user_launch_output = run_command("launchctl list") # No grep, user agents often don't have standard prefixes
    if user_launch_output:
        for line in user_launch_output.splitlines():
            parts = line.split()
            if len(parts) >= 3:
                # Filter out system daemons that might show up in user's list if the user has rights
                if not parts[2].startswith("com.apple."): # Simple filter
                     launch_items['user_agents'].append({
                        "pid": parts[0],
                        "status": parts[1],
                        "label": parts[2]
                    })
                print(line)
    else:
        print("Could not retrieve user agents.")
    return launch_items


def get_firewall_status():
    """
    Checks and returns the status of the macOS Packet Filter (pf).
    Note: Requires sudo to get detailed info.
    """
    pf_status = {"status": "Unknown", "rules_loaded": "N/A"}
    print("\n--- Firewall (pf) Status ---")
    print("-" * 25)

    # Check pf status
    pf_info_output = run_command("sudo pfctl -s info", check=False) # Will likely require sudo
    if pf_info_output and "No ALTQ support in kernel" not in pf_info_output: # Check for common error if not enabled/loaded
        if "Status: Enabled" in pf_info_output:
            pf_status["status"] = "Enabled"
            match = re.search(r'Rules: (\d+)/(\d+)', pf_info_output)
            if match:
                pf_status["rules_loaded"] = f"{match.group(1)} active / {match.group(2)} total"
        elif "Status: Disabled" in pf_info_output:
            pf_status["status"] = "Disabled"
        
        print(f"Status: {pf_status['status']}")
        print(f"Rules: {pf_status['rules_loaded']}")
        print("\n--- pfctl Rules (truncated, sudo required for full view) ---")
        pf_rules_output = run_command("sudo pfctl -s rules | head -n 10", check=False)
        if pf_rules_output:
            print(pf_rules_output)
        else:
            print("Could not retrieve pf rules. Sudo privileges are often required.")
    else:
        pf_status["status"] = "Inactive/Error (likely needs sudo or not configured)"
        print("Firewall (pf) is Inactive or an error occurred. Try running with sudo.")
    return pf_status

def get_usb_devices():
    """
    Retrieves and returns a list of connected USB devices.
    """
    usb_devices = []
    print("\n--- USB Devices ---")
    print("-" * 20)

    # system_profiler SPUSBDataType provides detailed USB info
    usb_output = run_command("system_profiler SPUSBDataType")
    if usb_output:
        current_device = {}
        for line in usb_output.splitlines():
            line = line.strip()
            if line and not line.startswith(":") and not line.startswith("---"): # New device usually starts without indentation
                if current_device and "name" in current_device: # Save previous device if exists
                    usb_devices.append(current_device)
                current_device = {"raw_lines": []} # Reset for new device
                # Attempt to get name from line like "USB 3.0 Bus:" or "External HDD:"
                match_name = re.match(r'^(.*?):$', line)
                if match_name:
                    current_device["name"] = match_name.group(1).strip()
                current_device["raw_lines"].append(line) # Store raw line for detailed view
            elif current_device:
                current_device["raw_lines"].append(line)
                if ":" in line:
                    key, value = line.split(":", 1)
                    current_device[key.strip()] = value.strip()
        if current_device and "name" in current_device: # Add last device
            usb_devices.append(current_device)

        for dev in usb_devices:
            print(f"Device: {dev.get('name', 'Unknown')}")
            for line in dev.get('raw_lines', []): # Print raw lines for full detail
                print(f"  {line}")
            print("-" * 10)
    else:
        print("Could not retrieve USB device information.")
    return usb_devices

def get_bluetooth_devices():
    """
    Retrieves and returns a list of paired Bluetooth devices.
    """
    bluetooth_devices = []
    print("\n--- Bluetooth Devices ---")
    print("-" * 25)

    # system_profiler SPBluetoothDataType provides Bluetooth info
    bt_output = run_command("system_profiler SPBluetoothDataType")
    if bt_output:
        # Look for "Devices:" section
        devices_section_started = False
        current_device = {}
        for line in bt_output.splitlines():
            line = line.strip()
            if "Devices:" in line:
                devices_section_started = True
                continue
            
            if devices_section_started:
                if line.endswith(":") and len(line.split()) > 1: # New device like "Magic Keyboard:"
                    if current_device:
                        bluetooth_devices.append(current_device)
                    current_device = {"name": line.replace(":", ""), "raw_lines": []}
                elif current_device:
                    current_device["raw_lines"].append(line)
                    if ":" in line:
                        key, value = line.split(":", 1)
                        current_device[key.strip()] = value.strip()
        if current_device: # Add the last device
            bluetooth_devices.append(current_device)
        
        for dev in bluetooth_devices:
            print(f"Device: {dev.get('name', 'Unknown')}")
            for line in dev.get('raw_lines', []):
                print(f"  {line}")
            print("-" * 10)
    else:
        print("Could not retrieve Bluetooth device information.")
    return bluetooth_devices

def get_time_machine_status():
    """
    Retrieves and returns Time Machine backup status.
    """
    tm_status = {"status": "Unknown"}
    print("\n--- Time Machine Status ---")
    print("-" * 25)

    tmutil_output = run_command("tmutil status")
    if tmutil_output:
        if "Backup not running." in tmutil_output:
            tm_status["status"] = "Not Running"
            print("Time Machine Status: Not Running")
        elif "Backup running." in tmutil_output:
            tm_status["status"] = "Running"
            print("Time Machine Status: Running")
            # Parse progress if available
            for line in tmutil_output.splitlines():
                if "Progress:" in line:
                    match = re.search(r'(\d+\.\d+)%', line)
                    if match:
                        tm_status["progress"] = match.group(1) + "%"
                        print(f"  Progress: {tm_status['progress']}")
                elif "Destination:" in line:
                    tm_status["destination"] = line.split(":", 1)[1].strip()
                    print(f"  Destination: {tm_status['destination']}")
        else:
            tm_status["status"] = "Check output manually"
            print("Time Machine Status: Unknown. Raw output below:")
            print(tmutil_output)
    else:
        print("Could not retrieve Time Machine status.")
    return tm_status

def get_smart_status(disk_identifier="disk0"):
    """
    Retrieves and returns S.M.A.R.T. status for a given disk identifier.
    Defaults to 'disk0'.
    """
    smart_info = {"disk": disk_identifier, "smart_status": "Unknown", "error": None}
    print(f"\n--- S.M.A.R.T. Status for {disk_identifier} ---")
    print("-" * 30)

    # diskutil info <disk_identifier>
    diskutil_output = run_command(f"diskutil info {disk_identifier}")
    if diskutil_output:
        found_smart = False
        for line in diskutil_output.splitlines():
            line = line.strip()
            if "S.M.A.R.T. Status:" in line:
                status = line.split(":")[1].strip()
                smart_info["smart_status"] = status
                found_smart = True
                print(f"S.M.A.R.T. Status: {status}")
                break
        if not found_smart:
            smart_info["smart_status"] = "Not Supported / Not Found"
            print(f"S.M.A.R.T. Status: Not Supported / Not Found for {disk_identifier}")
    else:
        smart_info["error"] = "Could not retrieve disk information via diskutil."
        print(f"Could not retrieve disk information for {disk_identifier}.")
    return smart_info


def main():
    """
    Main function to call all information retrieval functions.
    """
    print("🚀 Collecting macOS System Information... 🚀")
    
    all_info = {}
    all_info['system_overview'] = get_system_overview()
    all_info['cpu_details'] = get_cpu_details()
    all_info['memory_usage'] = get_memory_usage()
    all_info['disk_usage'] = get_disk_usage()
    all_info['disk_io_stats'] = get_disk_io_stats() # New
    all_info['network_info'] = get_network_info()
    all_info['network_connections'] = get_network_connections() # Existing, but worth noting
    all_info['process_list'] = get_process_list()
    all_info['logged_in_users'] = get_logged_in_users()
    all_info['system_logs'] = get_system_logs()
    all_info['installed_applications'] = get_installed_applications()
    all_info['hardware_overview'] = get_hardware_overview()
    all_info['battery_info'] = get_battery_info()
    all_info['sharing_services'] = get_sharing_services()
    all_info['software_updates'] = check_software_updates()
    all_info['kernel_extensions'] = get_kernel_extensions() # New
    all_info['launch_items'] = get_launch_items() # New
    all_info['firewall_status'] = get_firewall_status() # New (might require sudo)
    all_info['usb_devices'] = get_usb_devices() # New
    all_info['bluetooth_devices'] = get_bluetooth_devices() # New
    all_info['time_machine_status'] = get_time_machine_status() # New
    all_info['smart_status_disk0'] = get_smart_status("disk0") # New, check main disk
    all_info['smart_status_disk1'] = get_smart_status("disk1") # New, check another common disk

    print("\n✨ Information Collection Complete! ✨")
    
    # You can now process 'all_info' dictionary further, e.g., save to JSON
    # print("\n--- Full JSON Output (for programmatic use) ---")
    # print(json.dumps(all_info, indent=2))
    return all_info

if __name__ == "__main__":
    import random # For simulating software updates
    main()
