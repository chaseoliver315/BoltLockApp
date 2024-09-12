from scapy.all import sniff, IP, ICMP, TCP, UDP
from datetime import datetime, timedelta
import logging
import psutil
import socket
import os
import sys
import subprocess

# Dictionary to store protocol mappings
protocol_mapping = {
    1: 'ICMP',
    6: 'TCP',
    17: 'UDP',
    47: 'GRE',
    50: 'ESP',
    58: 'ICMPv6',
    89: 'OSPF'
}

def check_and_elevate():
    if os.geteuid() != 0:
        print("Elevating privileges...")
        subprocess.call(['sudo', 'python3'] + sys.argv)
        sys.exit()

check_and_elevate()

# Set up logging configuration
logging.basicConfig(
    filename='inbound_requests.log',  # Changed to log inbound requests
    level=logging.INFO,
    format='%(asctime)s - %(message)s',
    filemode='w'  # Overwrite the log file each time ('a' to append)
)

# Dictionary to store recently seen requests
recent_requests = {}

# Time window to filter duplicate requests (in seconds)
time_window = 5

def get_local_ip(interface):
    """Finds and returns the local IP address of the machine."""
    try:
        # Create a socket connection to a remote server to get the local IP address
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.settimeout(0)
        # Connecting to an external server (Google's DNS, not sending data)
        s.connect(('8.8.8.8', 1))
        local_ip = s.getsockname()[0]
    except Exception:
        local_ip = '127.0.0.1'  # Fallback in case of an error
    finally:
        s.close()
    
    return local_ip

def get_active_interface():
    
    interfaces = psutil.net_if_stats()  # Get all network interfaces with their stats
    addrs = psutil.net_if_addrs()  # Get network addresses associated with interfaces

    # List of interface names to ignore (loopback and virtual interfaces)
    ignore_interfaces = ['lo', 'docker0', 'vboxnet0', 'virbr0', 'lo0']

    for interface, stats in interfaces.items():
        if stats.isup and interface in addrs and interface not in ignore_interfaces:  # Interface is up and not in the ignore list
            for addr in addrs[interface]:
                if addr.family == socket.AF_INET:  # We only care about IPv4 addresses
                    return interface  # Return the first active non-loopback, non-virtual interface
    return None  # Return None if no valid interface is found


def resolve_dns(ip_address):
    try:
        return socket.gethostbyaddr(ip_address)[0]  # Returns the DNS name
    except socket.herror:
        return None  # If no DNS name is found, return None

def analyze_packet_type(packet):
    if ICMP in packet:
        icmp_type = packet[ICMP].type
        return f"ICMP Packet: Type {icmp_type}"
    elif TCP in packet:
        tcp_flags = packet[TCP].flags
        return f"TCP Packet: Flags {tcp_flags}"
    elif UDP in packet:
        return f"UDP Packet"
    else:
        return "Unknown Packet Type"

# Function to process and log inbound packets, ignoring loopback and local addresses
def process_packet(packet):
    if IP in packet:
        src_ip = packet[IP].src
        dst_ip = packet[IP].dst

        # Ignore loopback interface traffic (127.0.0.1 or ::1)
        if src_ip == '127.0.0.1' or dst_ip == '127.0.0.1' or src_ip == '::1' or dst_ip == '::1':
            return  # Skip processing packets on loopback

        # Now checking if the destination IP is the local machine's IP (inbound traffic)
        if packet[IP].dst == my_ip:
            protocol_number = packet.proto
            protocol_name = protocol_mapping.get(protocol_number, f"Unknown ({protocol_number})")
            packet_size = len(packet)
            timestamp = datetime.now()

            # Analyze the packet type
            packet_type_details = analyze_packet_type(packet)

            # Resolve the DNS name for the source IP (now focusing on the source since it's inbound traffic)
            dns_name = resolve_dns(src_ip)

            # Create a unique key for the packet (based on src, dst, and protocol)
            packet_key = (src_ip, dst_ip, protocol_number)

            # Check if the packet has been seen recently
            if packet_key in recent_requests:
                last_seen = recent_requests[packet_key]
                # If the packet was seen within the time window, skip logging
                if timestamp - last_seen < timedelta(seconds=time_window):
                    return

            # Organize and structure the log message
            log_message = (
                f"Inbound Request - "
                f"Source IP: {src_ip} "
                f"DNS: {dns_name if dns_name else 'N/A'} "
                f"Protocol: {protocol_name} "
                f"{packet_type_details} "
                f"Packet Size: {packet_size} bytes"
            )

            # Log the structured message
            logging.info(log_message)

            # Update the dictionary with the latest timestamp
            recent_requests[packet_key] = timestamp

# Start sniffing inbound traffic
def start_sniffing(interface):
    print(f"Starting to sniff on interface {interface}...")
    print(f"Removing duplicates that appear more than once every {time_window} seconds...")
    # Sniff inbound traffic
    sniff(filter="ip", iface=interface, prn=process_packet, store=0)

if __name__ == "__main__":
    # Get the active network interface and its IP address
    active_interface = get_active_interface()
    my_ip = get_local_ip(active_interface)
    
    # Start sniffing for inbound traffic on the active interface
    start_sniffing(interface=active_interface)
