#!/usr/bin/env python3
"""
Utility functions for the port scanner
"""

import socket
import struct
import ipaddress
from concurrent.futures import ThreadPoolExecutor, as_completed
import time
import sys
import os

def is_valid_ip(ip):
    """
    Validate IP address
    """
    try:
        ipaddress.ip_address(ip)
        return True
    except ValueError:
        return False

def parse_port_range(port_range):
    """
    Parse port range string (e.g., '1-1000', '22,80,443')
    """
    ports = []
    
    if ',' in port_range:
        # Comma-separated ports
        parts = port_range.split(',')
        for part in parts:
            if '-' in part:
                start, end = map(int, part.split('-'))
                ports.extend(range(start, end + 1))
            else:
                ports.append(int(part))
    elif '-' in port_range:
        # Range of ports
        start, end = map(int, port_range.split('-'))
        ports = list(range(start, end + 1))
    else:
        # Single port
        ports = [int(port_range)]
    
    return sorted(set(ports))  # Remove duplicates and sort

def get_banner(sock, timeout=2):
    """
    Attempt to grab banner from service
    """
    try:
        sock.settimeout(timeout)
        
        # Send a generic probe
        probe = b"\r\n\r\n"
        sock.send(probe)
        
        # Receive response
        banner = sock.recv(1024)
        
        # Clean up the banner
        if banner:
            banner = banner.decode('utf-8', errors='ignore').strip()
            # Take first line only for cleaner output
            banner = banner.split('\n')[0][:100]
            return banner
        
    except:
        pass
    
    return ""

def scan_port(ip, port, timeout=1, get_banner_flag=False):
    """
    Scan a single port
    """
    try:
        # Create socket
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        
        # Try to connect
        result = sock.connect_ex((ip, port))
        
        if result == 0:
            # Port is open
            banner = ""
            if get_banner_flag:
                banner = get_banner(sock)
            
            sock.close()
            return port, True, banner
        else:
            sock.close()
            return port, False, ""
    
    except socket.error:
        return port, False, ""
    except Exception as e:
        return port, False, ""

def calculate_checksum(data):
    """
    Calculate checksum for TCP packets
    """
    if len(data) % 2:
        data += b'\x00'
    
    s = 0
    for i in range(0, len(data), 2):
        w = (data[i] << 8) + data[i + 1]
        s += w
    
    s = (s >> 16) + (s & 0xffff)
    s = ~s & 0xffff
    
    return s

def create_tcp_packet(source_ip, dest_ip, source_port, dest_port, flags):
    """
    Create raw TCP packet for SYN scan
    """
    # IP Header
    ip_ihl = 5
    ip_ver = 4
    ip_tos = 0
    ip_tot_len = 0  # kernel will fill this
    ip_id = 54321
    ip_frag_off = 0
    ip_ttl = 255
    ip_proto = socket.IPPROTO_TCP
    ip_check = 0
    ip_saddr = socket.inet_aton(source_ip)
    ip_daddr = socket.inet_aton(dest_ip)
    
    ip_ihl_ver = (ip_ver << 4) + ip_ihl
    
    # IP header
    ip_header = struct.pack('!BBHHHBBH4s4s',
                            ip_ihl_ver, ip_tos, ip_tot_len,
                            ip_id, ip_frag_off, ip_ttl, ip_proto,
                            ip_check, ip_saddr, ip_daddr)
    
    # TCP Header
    tcp_source = source_port
    tcp_dest = dest_port
    tcp_seq = 0
    tcp_ack_seq = 0
    tcp_doff = 5
    tcp_fin = (flags & 0x01)
    tcp_syn = ((flags >> 1) & 0x01)
    tcp_rst = ((flags >> 2) & 0x01)
    tcp_psh = ((flags >> 3) & 0x01)
    tcp_ack = ((flags >> 4) & 0x01)
    tcp_urg = ((flags >> 5) & 0x01)
    tcp_window = socket.htons(5840)
    tcp_check = 0
    tcp_urg_ptr = 0
    
    tcp_offset_res = (tcp_doff << 4) + 0
    tcp_flags = (tcp_fin + (tcp_syn << 1) + (tcp_rst << 2) + 
                 (tcp_psh << 3) + (tcp_ack << 4) + (tcp_urg << 5))
    
    # TCP header without checksum
    tcp_header = struct.pack('!HHLLBBHHH',
                             tcp_source, tcp_dest,
                             tcp_seq, tcp_ack_seq,
                             tcp_offset_res, tcp_flags,
                             tcp_window, tcp_check, tcp_urg_ptr)
    
    # Pseudo header for checksum
    source_address = socket.inet_aton(source_ip)
    dest_address = socket.inet_aton(dest_ip)
    placeholder = 0
    protocol = socket.IPPROTO_TCP
    tcp_length = len(tcp_header)
    
    psh = struct.pack('!4s4sBBH',
                      source_address, dest_address,
                      placeholder, protocol, tcp_length)
    psh = psh + tcp_header
    
    tcp_check = calculate_checksum(psh)
    
    # TCP header with correct checksum
    tcp_header = struct.pack('!HHLLBBHHH',
                             tcp_source, tcp_dest,
                             tcp_seq, tcp_ack_seq,
                             tcp_offset_res, tcp_flags,
                             tcp_window, tcp_check, tcp_urg_ptr)
    
    return ip_header + tcp_header

def print_colored(text, color_code):
    """
    Print colored text (for better visualization)
    """
    print(f"\033[{color_code}m{text}\033[0m")

def display_results(ip, open_ports, banners, vulnerabilities):
    """
    Display scan results in a formatted way
    """
    print("\n" + "="*80)
    print(f"SCAN RESULTS for {ip}")
    print("="*80)
    
    if not open_ports:
        print("No open ports found.")
        return
    
    print(f"\nFound {len(open_ports)} open port(s):")
    print("-"*80)
    print(f"{'PORT':<10} {'STATE':<10} {'SERVICE':<15} {'BANNER':<30} {'VULNERABILITIES'}")
    print("-"*80)
    
    for port in sorted(open_ports):
        service = "Unknown"
        banner = banners.get(port, "")
        vulns = vulnerabilities.get(port, [])
        
        # Get service name
        try:
            service = socket.getservbyport(port)
        except:
            # Try our own database
            from vulnerability_db import get_service_name
            service = get_service_name(port)
        
        # Display vulnerabilities with colors
        vuln_text = ", ".join(vulns[:2])  # Show first 2 vulnerabilities
        if len(vulns) > 2:
            vuln_text += f" ... (+{len(vulns)-2} more)"
        
        # Color coding based on risk
        if vulns:
            port_str = f"\033[91m{port:<10}\033[0m"  # Red for vulnerable
        else:
            port_str = f"\033[92m{port:<10}\033[0m"  # Green for safe
        
        print(f"{port_str} {'OPEN':<10} {service:<15} {banner[:30]:<30} {vuln_text}")
    
    print("-"*80)
    
    # Summary
    total_vulns = sum(len(v) for v in vulnerabilities.values())
    print(f"\nSUMMARY: {total_vulns} potential vulnerabilities found")