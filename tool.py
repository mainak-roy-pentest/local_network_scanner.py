import argparse
from scapy.all import ARP, Ether, srp
import socket
import subprocess

def scan_network(ip_range):
    """Scan the local network for active hosts using ARP requests."""
    print(f"Scanning network {ip_range} ...")
    arp = ARP(pdst=ip_range)
    ether = Ether(dst="ff:ff:ff:ff:ff:ff")
    packet = ether/arp

    result = srp(packet, timeout=2, verbose=0)[0]
    hosts = []
    for sent, received in result:
        hosts.append({'ip': received.psrc, 'mac': received.hwsrc})
    return hosts

def scan_ports(host, ports):
    """Scan the specified ports on a host. Returns a list of open ports."""
    open_ports = []
    for port in ports:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(0.5)
        try:
            if sock.connect_ex((host, port)) == 0:
                open_ports.append(port)
        except Exception:
            continue
        finally:
            sock.close()
    return open_ports

def check_vulnerabilities(ip, open_ports):
    """Check for basic vulnerabilities based on open ports."""
    vulns = []
    for port in open_ports:
        if port == 21:
            vulns.append("FTP on port 21 (often insecure, check for anonymous access).")
        if port == 23:
            vulns.append("Telnet on port 23 (unencrypted, legacy).")
        if port == 80:
            vulns.append("HTTP on port 80 (unencrypted traffic).")
        if port == 445:
            vulns.append("SMB on port 445 (potential EternalBlue, outdated SMBv1).")
    return vulns

def run_nmap_scan(ip):
    """Optional: Use Nmap for detailed vulnerability assessment if installed."""
    try:
        result = subprocess.run(['nmap', '-sV', '--script', 'vuln', ip],
                                 capture_output=True, text=True, timeout=30)
        return result.stdout
    except Exception as e:
        return f"Error or Nmap not installed: {str(e)}"

def main():
    parser = argparse.ArgumentParser(description="Local Network Scanner with Vulnerability Report")
    parser.add_argument('--range', required=True, help="IP range to scan (e.g., 192.168.1.0/24)")
    parser.add_argument('--ports', default="21,22,23,80,139,443,445,3389",
                        help="Comma-separated port list to scan. Default: common ports.")
    parser.add_argument('--nmap', action='store_true', help="Use Nmap for detailed scans (if installed)")
    args = parser.parse_args()

    hosts = scan_network(args.range)
    if not hosts:
        print("No hosts found.")
        return

    ports = [int(p) for p in args.ports.split(',')]

    print("\nDetailed Report:\n"+"-"*60)
    for host in hosts:
        print(f"Host: {host['ip']}  MAC: {host['mac']}")
        open_ports = scan_ports(host['ip'], ports)
        if open_ports:
            print(f"  Open Ports: {', '.join(map(str, open_ports))}")
            vulns = check_vulnerabilities(host['ip'], open_ports)
            if vulns:
                print("  Possible Vulnerabilities:")
                for v in vulns:
                    print(f"    - {v}")
            if args.nmap:
                print("  Nmap Detailed Vulnerability Scan:")
                print(run_nmap_scan(host['ip']))
        else:
            print("  No common ports open (from specified list).")
        print("-"*60)

if __name__ == "__main__":
    main()
