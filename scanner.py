#!/usr/bin/env python3
"""
Advanced Port Scanner with Vulnerability Detection
Optimized for speed on Parrot OS
"""

import socket
import sys
import time
import argparse
import threading
from queue import Queue
from concurrent.futures import ThreadPoolExecutor, as_completed
import ipaddress
import signal
import os

# Import our modules
from utils import *
from vulnerability_db import get_vulnerabilities, get_service_name

class FastPortScanner:
    def __init__(self, target_ip, timeout=1, max_threads=200):
        self.target_ip = target_ip
        self.timeout = timeout
        self.max_threads = max_threads
        self.open_ports = []
        self.banners = {}
        self.vulnerabilities = {}
        self.scan_start_time = 0
        self.scan_end_time = 0
        
        # For SYN scan
        self.source_port = 12345
        self.raw_socket = None
        
        # Statistics
        self.ports_scanned = 0
        self.total_ports = 0
        
    def connect_scan(self, ports, get_banner=False):
        """
        Traditional connect scan
        """
        print(f"[*] Starting connect scan on {len(ports)} ports...")
        
        with ThreadPoolExecutor(max_workers=self.max_threads) as executor:
            futures = {executor.submit(scan_port, self.target_ip, port, self.timeout, get_banner): port 
                      for port in ports}
            
            for future in as_completed(futures):
                port, is_open, banner = future.result()
                self.ports_scanned += 1
                
                if is_open:
                    self.open_ports.append(port)
                    if banner:
                        self.banners[port] = banner
                    
                    # Check for vulnerabilities
                    vulns = get_vulnerabilities(port, banner)
                    if vulns:
                        self.vulnerabilities[port] = vulns
                    
                    print(f"[+] Port {port} is open - {banner[:50] if banner else ''}")
                
                # Progress indicator
                if self.ports_scanned % 100 == 0:
                    progress = (self.ports_scanned / self.total_ports) * 100
                    sys.stdout.write(f"\r[*] Progress: {progress:.1f}% ({self.ports_scanned}/{self.total_ports})")
                    sys.stdout.flush()
        
        print(f"\r[*] Connect scan completed: {len(self.open_ports)} open ports found")
    
    def syn_scan(self, ports):
        """
        SYN scan (requires root privileges)
        Faster than connect scan
        """
        if os.geteuid() != 0:
            print("[!] SYN scan requires root privileges. Falling back to connect scan.")
            return self.connect_scan(ports)
        
        print(f"[*] Starting SYN scan on {len(ports)} ports...")
        
        # Create raw socket
        try:
            self.raw_socket = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_TCP)
            self.raw_socket.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)
            self.raw_socket.setblocking(0)
        except PermissionError:
            print("[!] Permission denied for raw socket. Falling back to connect scan.")
            return self.connect_scan(ports)
        
        # Set up packet capture
        recv_socket = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_TCP)
        recv_socket.settimeout(1)
        
        # Send SYN packets
        syn_acked = {}
        
        for port in ports:
            packet = create_tcp_packet("127.0.0.1", self.target_ip, self.source_port, port, 2)  # SYN flag
            self.raw_socket.sendto(packet, (self.target_ip, 0))
            syn_acked[port] = False
            self.ports_scanned += 1
            
            # Small delay to avoid flooding
            time.sleep(0.001)
        
        # Listen for responses
        start_time = time.time()
        while time.time() - start_time < self.timeout * 2:
            try:
                packet = recv_socket.recvfrom(1024)[0]
                
                # Parse response
                ip_header = packet[0:20]
                iph = struct.unpack('!BBHHHBBH4s4s', ip_header)
                
                src_ip = socket.inet_ntoa(iph[8])
                
                if src_ip == self.target_ip:
                    tcp_header = packet[20:40]
                    tcph = struct.unpack('!HHLLBBHHH', tcp_header)
                    
                    src_port = tcph[0]
                    dest_port = tcph[1]
                    flags = tcph[5]
                    
                    # Check for SYN-ACK (0x12)
                    if flags == 0x12 and dest_port == self.source_port:
                        if src_port in syn_acked:
                            self.open_ports.append(src_port)
                            syn_acked[src_port] = True
                            print(f"[+] Port {src_port} is open (SYN-ACK)")
            except socket.timeout:
                break
            except:
                continue
        
        recv_socket.close()
        if self.raw_socket:
            self.raw_socket.close()
        
        print(f"[*] SYN scan completed: {len(self.open_ports)} open ports found")
    
    def scan_ports(self, ports, scan_type="connect", get_banner=False):
        """
        Main scanning method
        """
        self.scan_start_time = time.time()
        self.total_ports = len(ports)
        self.ports_scanned = 0
        
        print(f"[*] Scanning {self.target_ip}...")
        print(f"[*] Ports to scan: {len(ports)}")
        print(f"[*] Scan type: {scan_type}")
        print(f"[*] Threads: {self.max_threads}")
        print(f"[*] Timeout: {self.timeout}s")
        print("-" * 50)
        
        if scan_type == "syn":
            self.syn_scan(ports)
        else:
            self.connect_scan(ports, get_banner)
        
        self.scan_end_time = time.time()
        
        return self.open_ports, self.banners, self.vulnerabilities
    
    def get_scan_duration(self):
        """Get scan duration in seconds"""
        return self.scan_end_time - self.scan_start_time

class VulnerabilityScanner:
    """
    Extended vulnerability checks for specific services
    """
    def __init__(self, target_ip):
        self.target_ip = target_ip
    
    def check_http_vulnerabilities(self, port=80):
        """
        Check common HTTP vulnerabilities
        """
        vulns = []
        try:
            import requests
            
            url = f"http://{self.target_ip}:{port}"
            
            # Check for directory traversal
            test_paths = [
                "/../../../../etc/passwd",
                "/..%2f..%2f..%2f..%2fetc/passwd"
            ]
            
            for path in test_paths:
                try:
                    r = requests.get(url + path, timeout=2)
                    if "root:" in r.text and "bin:" in r.text:
                        vulns.append(f"Directory traversal possible at {path}")
                        break
                except:
                    pass
            
            # Check for exposed admin panels
            admin_paths = ["/admin", "/wp-admin", "/administrator", "/manage"]
            for path in admin_paths:
                try:
                    r = requests.get(url + path, timeout=2)
                    if r.status_code == 200:
                        vulns.append(f"Admin panel exposed at {path}")
                except:
                    pass
                    
        except ImportError:
            vulns.append("Install 'requests' library for advanced HTTP checks")
        
        return vulns
    
    def check_ftp_vulnerabilities(self, port=21):
        """
        Check FTP vulnerabilities
        """
        vulns = []
        try:
            from ftplib import FTP
            
            ftp = FTP()
            ftp.connect(self.target_ip, port, timeout=2)
            
            # Try anonymous login
            try:
                ftp.login('anonymous', 'anonymous@example.com')
                vulns.append("Anonymous FTP login allowed")
                ftp.quit()
            except:
                pass
                
        except:
            pass
        
        return vulns

def main():
    parser = argparse.ArgumentParser(
        description="Advanced Port Scanner with Vulnerability Detection",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s 192.168.1.1
  %(prog)s 192.168.1.1 -p 1-1000
  %(prog)s 192.168.1.1 -p 22,80,443,8080
  %(prog)s 192.168.1.1 -p 1-65535 -t 500 -T 0.5 --syn
  %(prog)s 192.168.1.0/24 -p 22,80,443 --network-scan
        """
    )
    
    parser.add_argument("target", help="Target IP address or network (CIDR notation)")
    parser.add_argument("-p", "--ports", default="1-1000", 
                       help="Port range to scan (e.g., '1-1000', '22,80,443')")
    parser.add_argument("-t", "--threads", type=int, default=200,
                       help="Maximum number of threads (default: 200)")
    parser.add_argument("-T", "--timeout", type=float, default=1.0,
                       help="Connection timeout in seconds (default: 1.0)")
    parser.add_argument("--syn", action="store_true",
                       help="Use SYN scan (requires root privileges)")
    parser.add_argument("--banner", action="store_true",
                       help="Attempt to grab service banners")
    parser.add_argument("--network-scan", action="store_true",
                       help="Scan entire network (CIDR notation required)")
    parser.add_argument("--output", help="Save results to file")
    
    args = parser.parse_args()
    
    # Banner
    print("\n" + "="*60)
    print("      ADVANCED PORT SCANNER - PARROT OS EDITION")
    print("="*60)
    print(f"[*] Start time: {time.strftime('%Y-%m-%d %H:%M:%S')}")
    
    try:
        # Parse target(s)
        targets = []
        
        if args.network_scan:
            # Network scan
            try:
                network = ipaddress.ip_network(args.target, strict=False)
                targets = [str(ip) for ip in network.hosts()]
                print(f"[*] Network scan mode: {len(targets)} hosts")
            except ValueError:
                print(f"[-] Invalid network: {args.target}")
                sys.exit(1)
        else:
            # Single target
            if '/' in args.target:
                print("[!] Use --network-scan for network ranges")
                sys.exit(1)
            
            if not is_valid_ip(args.target):
                print(f"[-] Invalid IP address: {args.target}")
                sys.exit(1)
            
            targets = [args.target]
        
        # Parse ports
        try:
            ports = parse_port_range(args.ports)
            print(f"[*] Ports to scan per host: {len(ports)}")
        except ValueError:
            print(f"[-] Invalid port range: {args.ports}")
            sys.exit(1)
        
        results = []
        
        # Scan each target
        for i, target in enumerate(targets):
            print(f"\n[*] Scanning target {i+1}/{len(targets)}: {target}")
            
            # Create scanner
            scanner = FastPortScanner(
                target_ip=target,
                timeout=args.timeout,
                max_threads=args.threads
            )
            
            # Perform scan
            scan_type = "syn" if args.syn else "connect"
            open_ports, banners, vulnerabilities = scanner.scan_ports(
                ports, scan_type, args.banner
            )
            
            # Display results
            display_results(target, open_ports, banners, vulnerabilities)
            
            # Save results
            if open_ports:
                scan_duration = scanner.get_scan_duration()
                results.append({
                    'target': target,
                    'open_ports': open_ports,
                    'banners': banners,
                    'vulnerabilities': vulnerabilities,
                    'duration': scan_duration
                })
                
                print(f"[*] Scan duration: {scan_duration:.2f} seconds")
                print(f"[*] Speed: {len(ports)/scan_duration:.1f} ports/second")
            
            # Small delay between hosts
            if i < len(targets) - 1:
                time.sleep(0.5)
        
        # Save to file if requested
        if args.output and results:
            with open(args.output, 'w') as f:
                import json
                json.dump(results, f, indent=2)
            print(f"\n[*] Results saved to {args.output}")
        
        # Final summary
        print("\n" + "="*60)
        total_open = sum(len(r['open_ports']) for r in results)
        total_vulns = sum(len(v) for r in results for v in r['vulnerabilities'].values())
        print(f"[*] TOTAL: {total_open} open ports found across {len(targets)} hosts")
        print(f"[*] TOTAL: {total_vulns} potential vulnerabilities identified")
        print(f"[*] End time: {time.strftime('%Y-%m-%d %H:%M:%S')}")
        print("="*60)
        
    except KeyboardInterrupt:
        print("\n\n[!] Scan interrupted by user")
        sys.exit(0)
    except Exception as e:
        print(f"\n[-] Error: {e}")
        sys.exit(1)

if __name__ == "__main__":
    # Check for root privileges for SYN scan
    if len(sys.argv) > 1 and "--syn" in sys.argv and os.geteuid() != 0:
        print("[!] SYN scan requires root privileges. Run with sudo.")
        sys.exit(1)
    
    main()