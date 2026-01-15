# NetScan 🔍

```
  _   _      _    _____                 
 | \ | |    | |  / ____|                
 |  \| | ___| |_| (___   ___ __ _ _ __  
 | . ` |/ _ \ __|\___ \ / __/ _` | '_ \ 
 | |\  |  __/ |_ ____) | (_| (_| | | | |
 |_| \_|\___|\__|_____/ \___\__,_|_| |_|
```

A fast, lightweight network scanner written in Python. Discover active hosts on your local network or any specified subnet using ICMP ping requests.

## ✨ Features

- **Auto-Detection** - Automatically detects your local network configuration
- **Fast Scanning** - Uses 100 parallel threads for rapid host discovery
- **Cross-Platform** - Works on Windows, Linux, and macOS
- **Flexible Input** - Supports multiple network format inputs (CIDR, partial IP, etc.)
- **Graceful Interruption** - Press Ctrl+C to stop and see partial results

## 📋 Requirements

- Python 3.6 or higher
- No external dependencies (uses only standard library)

## 🚀 Installation

1. Clone or download this repository:
   ```bash
   git clone https://github.com/yourusername/NetScan.git
   cd NetScan
   ```

2. No additional installation needed - all modules are from Python's standard library!

## 💻 Usage

### Basic Usage (Auto-detect network)
```bash
python NetScan.py
```

### Scan Specific Network
```bash
python NetScan.py 192.168.1.0/24
```

### Shorthand Formats
```bash
python NetScan.py 192.168.1        # Scans 192.168.1.0/24
python NetScan.py 10.0.0.5         # Scans 10.0.0.0/24
```

### Show Help
```bash
python NetScan.py -h
python NetScan.py --help
```

## 📖 Examples

### Example 1: Scan Local Network
```
> python NetScan.py

  _   _      _    _____                 
 | \ | |    | |  / ____|                
 |  \| | ___| |_| (___   ___ __ _ _ __  
 | . ` |/ _ \ __|\___ \ / __/ _` | '_ \ 
 | |\  |  __/ |_ ____) | (_| (_| | | | |
 |_| \_|\___|\__|_____/ \___\__,_|_| |_|

Scanning network: 192.168.1.0/24

==================================================
Scan Complete! Found 5 online host(s):
==================================================
  [1] 192.168.1.1
  [2] 192.168.1.10
  [3] 192.168.1.15
  [4] 192.168.1.20
  [5] 192.168.1.100
==================================================
```

### Example 2: Scan Larger Network
```bash
python NetScan.py 10.0.0.0/16
```
> ⚠️ Note: Larger networks take more time to scan

## 🔧 How It Works

1. **Network Detection** - Parses `ipconfig` (Windows) or `ifconfig` (Unix) to find local IP and subnet mask
2. **CIDR Calculation** - Converts subnet mask to CIDR notation
3. **Parallel Scanning** - Uses ThreadPoolExecutor with 100 workers to ping hosts simultaneously
4. **Response Detection** - Checks for "TTL" in ping response to confirm host is online

## ⚠️ Disclaimer

**Use this tool responsibly and only on networks you own or have permission to scan.**

Unauthorized network scanning may be illegal in your jurisdiction. The author is not responsible for any misuse of this tool.

## 🛡️ Permissions

- **Windows**: Run as Administrator for best results
- **Linux/macOS**: May require `sudo` for ICMP permissions

## 📁 Project Structure

```
NetScan/
├── NetScan.py      # Main scanner script
└── README.md       # This file
```

## 🤝 Contributing

Contributions are welcome! Feel free to:
- Report bugs
- Suggest new features
- Submit pull requests

## 📝 License

This project is open source and available under the [MIT License](LICENSE).

## 🔮 Future Enhancements

- [ ] Port scanning capability
- [ ] MAC address detection
- [ ] Hostname resolution
- [ ] Export results to CSV/JSON
- [ ] OS detection based on TTL
- [ ] Progress bar during scan
- [ ] Colored terminal output

## 👤 Author

Your Name - [@yourusername](https://github.com/yourusername)

---

⭐ Star this repo if you find it useful!
