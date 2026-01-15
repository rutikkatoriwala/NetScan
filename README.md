# NetScan

```
  _   _      _    _____                 
 | \ | |    | |  / ____|                
 |  \| | ___| |_| (___   ___ __ _ _ __  
 | . ` |/ _ \ __|\___ \ / __/ _` | '_ \ 
 | |\  |  __/ |_ ____) | (_| (_| | | | |
 |_| \_|\___|\__|_____/ \___\__,_|_| |_|
```

A command-line network scanner that discovers active hosts on a network using ICMP ping requests.

## Usage

```
python NetScan.py [network]
```

### Examples

```
python NetScan.py                    # Auto-detect and scan local network
python NetScan.py 192.168.1.0/24     # Scan specific subnet
python NetScan.py 192.168.1          # Scan 192.168.1.0/24
python NetScan.py 10.0.0.0/16        # Scan larger network
python NetScan.py -h                 # Show help
```

### Supported Network Formats

| Format | Description |
|--------|-------------|
| (none) | Auto-detects local network |
| X.X.X.X/Y | CIDR notation |
| X.X.X | Assumes /24 subnet |
| X.X.X.X | Assumes /24 subnet |

## How It Works

1. The script detects the operating system and runs `ipconfig` (Windows) or `ifconfig` (Linux/macOS) to find the local IP address and subnet mask.

2. The subnet mask is converted to CIDR notation. For example, 255.255.255.0 becomes /24.

3. Using Python's `ipaddress` module, all host addresses in the network range are calculated.

4. The scanner spawns 100 parallel threads using `ThreadPoolExecutor`. Each thread pings one IP address.

5. A host is considered online if the ping response contains "TTL" in the output.

6. Results are collected, sorted numerically by IP, and displayed.

## Requirements

- Python 3.6+
- No external dependencies

## Notes

- Run as Administrator (Windows) or with sudo (Linux/macOS) for best results
- Some hosts may not respond to ICMP requests due to firewall settings
- Scanning large networks like /16 will take longer
- Press Ctrl+C to stop the scan and view partial results
