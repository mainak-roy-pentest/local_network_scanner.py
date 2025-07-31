# local_network_scanner.py
This Python tool scans your local network for connected devices, identifies their IP and MAC addresses, checks for open ports, and reports potential vulnerabilities like unsecured services. Optionally, it integrates with Nmap for advanced security analysis, helping you assess and strengthen your network’s security posture.

# Local Network Scanner with Vulnerability Report

This tool scans your local network for active hosts, discovers open ports, and identifies basic vulnerabilities based on open ports and services.

## Features

- Scans network range using ARP requests (quick device discovery).
- Scans common ports (default: 21,22,23,80,139,443,445,3389).
- Identifies potential vulnerabilities from open ports (e.g., unsafe FTP/Telnet/SMB).
- Optionally integrates **Nmap** for in-depth vulnerability check (if installed).

## Requirements

- Python 3.x
- Packages: `scapy`, `argparse`
    ```
    pip install scapy
    ```
- (Optional) Nmap (`nmap` command in PATH for --nmap)

## Usage

