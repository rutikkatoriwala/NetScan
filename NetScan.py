import sys #for command-line arguments and existing
import socket #for networking interface and IP operations
import ipaddress #for IP network calculations
import concurrent.futures #for Parallel thread excuation
import platform #for detecting operating system
import subprocess #for running OS Command
import re #for regular expressions
import os #for Possible future os operations

def print_app_name():
    print(r"""
  _   _      _    _____                 
 | \ | |    | |  / ____|                
 |  \| | ___| |_| (___   ___ __ _ _ __  
 | . ` |/ _ \ __|\___ \ / __/ _` | '_ \ 
 | |\  |  __/ |_ ____) | (_| (_| | | | |
 |_| \_|\___|\__|_____/ \___\__,_|_| |_|
          
Welcome to NetScan, a network scanner brought to you.
Don't missuse it otherwise u can get into a very big trouble. 
          """)
    
#=============================================================================================

def get_local_ip_and_mask():
    """
    Detects the local IP address and subnet mask from the system.
    Works for both Windows and Unix.
    """

    system = platform.system().lower()                                         #detect the OS type
    if system == 'windows':
        output = subprocess.check_output("ipconfig", universal_newlines=True)  #Run ipconfig and get output
        ip_match = re.search(r'IPv4 Address[. ]*: ([\d.]+)', output)           #Find the IPv4 address
        mask_match = re.search(r'Subnet Mask[. ]*: ([\d.]+)', output)          #Find the subnet Mask
        if ip_match and mask_match:
            return ip_match.group(1), mask_match.group(1)                      #return ip and mask if found
    else:
        #for linux/macOS, use ipconfig and parse output
        output = subprocess.check_output("ipconfig", shell=True, universal_newlines=True)
        ip_match = re.search(r'inet ([\d.]+).*?netmask (0x[\da-f]+|[\d.]+)', output)
        if ip_match:
            ip = ip_match.group(1)                                             #Extract ip address
            mask = ip_match.group(2)                                           #Extract NetMask
            if mask.startswith("0x"):                                          #If netmask is in Hex
                mask = socket.inet_ntoa(int(mask,16).to_bytes(4, "big"))       #Convert hex to dotted decimal
            return ip, mask
        
    #Fallback : Try to infer IP, assume /24 mask
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        s.connect(('8.8.8.8', 80))                                             #Dummy connect to get local IP
        ip = s.getsockname()[0]
    except Exception:
        ip = '127.0.0.1'
    finally:
        s.close()

    return ip, '255.255.255.0'                                                #Deafult Mask
#=============================================================================================
#=============================================================================================

def mask_to_cidr(mask):
    """
    Converts a dotted - decimal subnet mask (e.g., 255.255.255.0) to CIDR notation (e.g., 24).
    """
    return sum(bin(int(x)).count('1') for x in mask.split('.'))
#=============================================================================================
#=============================================================================================

def parse_network(arg=None):
    """
    Parses the network argument and returns and ipaddress.ip_network object.
    Handles no argument (auto-detect), /24, /16, etc.
    """

    if not arg:
        ip, mask = get_local_ip_and_mask()                               #Get local ip and mask
        cidr = mask_to_cidr(mask)                                        #Convert Mask to CIDR
        return ipaddress.ip_network(f"{ip}/{cidr}", strict=False)        #Create Network Object
    if '/' in arg:
        return ipaddress.ip_network(arg, strict=False)                   #User provide CDIR
    elif re.match(r'^\d+\.\d+\.\d+$', arg):
        return ipaddress.ip_network(arg + '.0/24', strict=False)         #e.g., 192.168.1 -> 192.168.1.0/24
    elif re.match(r'^\d+\.\d+\.\d+\.\d+$', arg):
        return ipaddress.ip_network(arg + '/24', strict=False)           #e.g., 192.168.1.5 -> 192.168.1.5/24
    else:
        raise ValueError("Invalid Network Format")                       #Invalid Input

#=============================================================================================
#=============================================================================================

def ping(ip):
    """
    Pings a single IP address.
    Returns the IP if online (responds to ping), otherwise none.
    """

    ip = str(ip)                                                        #Ensure Ip is string
    system = platform.system().lower()                                  #Detect OS                              
    if system == "windows":                                              
        cmd = ["ping", "-n", "1", "-w", "1000", ip]                     #Windows: 1 ping, 1s timeout
    else:
        cmd = ["ping", "-c", "1", "-W", "1", ip]                        #Unix: 1 ping, 1s timeout
    try:
        result = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, timeout=2)
        if re.search(r"ttl", result.stdout, re.IGNORECASE):             #"ttl" in output = host responded
            return ip
    except subprocess.TimeoutExpired:
        return None                                                     #Timed out, host not online
    except Exception:
        return None                                                     #Other error, treat as offline

#=============================================================================================
#=============================================================================================

def scan_network(network):
    """
    Scans all Hosts in the given network in parallel.
    Returns a list of online hosts.
    """

    print(f"Scanning network: {network}")                                   #Inform user what is being scanned
    online = []                                                             #List to store online hosts
    try:
        with concurrent.futures.ThreadPoolExecutor(max_workers=100) as executor:    #Use 100 threads
            futures = {executor.submit(ping, ip): ip for ip in network.hosts()}     #Submit ping jobs
            for future in concurrent.futures.as_completed(futures):                 #As each finishes
                try:
                    result = future.result()                                #Get Result
                    if result:
                        online.append(result)                               #Add is Online
                except Exception:
                    continue                                                #Ignore Errors
    except KeyboardInterrupt:
        print("\nScan interrupted by user, showing results so far...")      #Handle Ctrl + C gracefully
    return online
#=======================================================================================
#=============================================================================================

def print_help():
    """
    Displays help information and usage examples for NetScan.
    """
    print("""
NetScan - Network Scanner Tool
==============================

USAGE:
    python NetScan.py [OPTIONS] [NETWORK]

OPTIONS:
    -h, --help      Show this help message and exit

NETWORK FORMATS:
    (no argument)   Auto-detect local network and scan
    X.X.X.X/Y       Scan specific subnet with CIDR notation
    X.X.X           Scan X.X.X.0/24 subnet
    X.X.X.X         Scan X.X.X.X/24 subnet

EXAMPLES:
    python NetScan.py                    # Auto-detect and scan local network
    python NetScan.py 192.168.1.0/24     # Scan the 192.168.1.0/24 subnet
    python NetScan.py 192.168.1          # Scan 192.168.1.0/24
    python NetScan.py 10.0.0.0/16        # Scan a larger /16 network
    python NetScan.py -h                 # Show this help message

NOTES:
    - Scanning large networks (e.g., /16) may take significant time
    - Some hosts may not respond to ICMP ping requests
    - Run with administrator/root privileges for best results
    - Press Ctrl+C to interrupt scan and see partial results
    """)

#=============================================================================================
#=============================================================================================
def main():
    print_app_name()
    
    # Check for help flag
    if len(sys.argv) > 1 and sys.argv[1] in ['-h', '--help']:
        print_help()
        sys.exit(0)
    
    # Parse command-line argument for network (optional)
    arg = sys.argv[1] if len(sys.argv) > 1 else None
    
    try:
        network = parse_network(arg)                                        # Parse/detect network
    except ValueError as e:
        print(f"Error: {e}")
        print("Usage: python NetScan.py [network]")
        print("Examples:")
        print("  python NetScan.py                    # Auto-detect local network")
        print("  python NetScan.py 192.168.1.0/24     # Scan specific subnet")
        print("  python NetScan.py 192.168.1          # Scan 192.168.1.0/24")
        sys.exit(1)
    
    # Perform the network scan
    online_hosts = scan_network(network)
    
    # Display results
    print("\n" + "=" * 50)
    print(f"Scan Complete! Found {len(online_hosts)} online host(s):")
    print("=" * 50)
    
    if online_hosts:
        # Sort IPs numerically for better readability
        online_hosts.sort(key=lambda ip: tuple(map(int, ip.split('.'))))
        for i, host in enumerate(online_hosts, 1):
            print(f"  [{i}] {host}")
    else:
        print("  No hosts found online.")
    
    print("=" * 50)

#=============================================================================================

if __name__ == "__main__":
    main()