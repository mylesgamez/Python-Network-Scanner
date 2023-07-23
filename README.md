# Python Network Scanner
This project provides a comprehensive Python script for network scanning, leveraging multiple libraries such as nmap, socks, scapy, and concurrent.futures to conduct various network scans.

## Features
- Host Discovery: Discovers live hosts in the provided network.
- Port Scanning: Scans TCP and UDP ports of discovered hosts. It employs Tor for scanning if available, and falls back to a direct connection if Tor fails.
- Service and Version Detection: Identifies services running on open ports and attempts to determine the version of these services.
- OS Detection: Attempts to detect the operating system of the discovered hosts.
- Firewall Evasion and Stealth Scan: Performs a stealth scan that aims to evade firewall detection.
- Vulnerability Scan: Scans for known vulnerabilities on the discovered hosts.

## Requirements
To run the script, you will need Python 3 and the following Python libraries:
```
nmap
socks
scapy
concurrent.futures
```

## Usage
To use the script, simply run it in your terminal:
```
python network_scanner.py
```

You will be asked to input the target network IP address, and the script will perform the various scanning operations on that network.

## Legal Disclaimer
Unauthorized scanning or port probing can be illegal or seen as a hostile act by some network administrators. You should only use this script to scan networks that you own or have obtained explicit permission to scan.

## License
Distributed under the MIT License. See LICENSE for more information.
