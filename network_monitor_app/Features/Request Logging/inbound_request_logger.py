from scapy.all import sniff, IP, ICMP, TCP, UDP
from datetime import datetime, timedelta
import logging
import psutil
import socket
import os
import pwd
import sys
import subprocess
import threading
import time
from collections import defaultdict
import logging
from logging.handlers import RotatingFileHandler

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
# Configure logging with RotatingFileHandler
log_formatter = logging.Formatter('%(asctime)s - %(message)s')

log_file = 'inbound_requests.log'

handler = RotatingFileHandler(
    log_file,
    mode='a',
    maxBytes=5 * 1024 * 1024,  # Rotate after 5 MB
    backupCount=5,              # Keep 5 backup files
    encoding=None,
    delay=0
)

handler.setFormatter(log_formatter)
handler.setLevel(logging.INFO)

logger = logging.getLogger()
logger.setLevel(logging.INFO)
logger.addHandler(handler)


# Dictionary to store recently seen requests
recent_requests = {}

# Time window to filter duplicate requests (in seconds)
time_window = 5

# Threshold for packets per source IP
PACKET_THRESHOLD = 300  # Adjust as needed

# Time interval in seconds to reset counts
TIME_INTERVAL = 20  # Adjust as needed

# Packet counts per source IP
packet_counts = defaultdict(int)

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

def drop_privileges(uid_name='nobody'):
    if os.getuid() != 0:
        # Already running as non-root
        return
    try:
        # Get the uid/gid from the name
        pw_record = pwd.getpwnam(uid_name)
        uid = pw_record.pw_uid
        gid = pw_record.pw_gid
        # Remove group privileges
        os.setgroups([])
        # Try setting the new uid/gid
        os.setgid(gid)
        os.setuid(uid)
        # Ensure privileges cannot be regained
        os.umask(0o077)
    except Exception as e:
        logger.error(f"Failed to drop privileges: {e}")
        sys.exit(1)
        
def mask_ip(ip_address):
    if ':' in ip_address:
        # IPv6 address masking (e.g., zero out last segments)
        parts = ip_address.split(':')
        if len(parts) >= 2:
            parts[-1] = '0000'
            parts[-2] = '0000'
            return ':'.join(parts)
        else:
            return ip_address
    else:
        # IPv4 address masking
        parts = ip_address.split('.')
        if len(parts) == 4:
            parts[-1] = '0'
            return '.'.join(parts)
        else:
            return ip_address

def sanitize_dns_name(dns_name):
    if dns_name:
        parts = dns_name.split('.')
        if len(parts) >= 2:
            return '.'.join(parts[-2:])  # Keep only the domain and TLD
        else:
            return dns_name
    else:
        return 'N/A'

def resolve_dns(ip_address):
    try:
        return socket.gethostbyaddr(ip_address)[0]  # Returns the DNS name
    except socket.herror:
        return None  # If no DNS name is found, return None

def analyze_packet_type(packet):
    if ICMP in packet:
        icmp_type = packet[ICMP].type
        return f"Packet Type: {icmp_type}"
    elif TCP in packet:
        tcp_flags = packet[TCP].flags
        return f"Packet Flags: {tcp_flags}"
    elif UDP in packet:
        return f"- UDP Packet"
    else:
        return "Unknown Packet Type"

def detect_dos_attacks():
    global packet_counts
    separator = ' | '
    while True:
        time.sleep(TIME_INTERVAL)
        for ip, count in packet_counts.items():
            if count > PACKET_THRESHOLD:
                alert_message = (
                    
                    f"Potential DoS attack detected{separator}"
                    f"IP: {ip}{separator}"
                    f"Packets: {count}{separator}"
                    f"Interval: {TIME_INTERVAL} seconds"
                    f"\n"
)

                print("\n",alert_message)
                logger.warning(alert_message)
        # Reset packet counts after each interval
        packet_counts.clear()


# Function to process and log inbound packets, ignoring loopback and local addresses
def process_packet(packet):
    try:
        if IP in packet:
            src_ip = packet[IP].src
            dst_ip = packet[IP].dst

            # Ignore loopback interface traffic (127.0.0.1 or ::1)
            if src_ip == '127.0.0.1' or dst_ip == '127.0.0.1' or src_ip == '::1' or dst_ip == '::1':
                return  # Skip processing packets on loopback

            # Now checking if the destination IP is the local machine's IP (inbound traffic)
            if dst_ip == my_ip:
                protocol_number = packet.proto
                # Increment the packet count for the source IP
                packet_counts[src_ip] += 1
                protocol_name = protocol_mapping.get(protocol_number, f"Unknown ({protocol_number})")
                packet_size = len(packet)
                timestamp = datetime.now()

                # Analyze the packet type
                packet_type_details = analyze_packet_type(packet)

                # Resolve the DNS name for the source IP (now focusing on the source since it's inbound traffic)
                dns_name = resolve_dns(src_ip)

                # Sanitize the IP and DNS name 
                masked_src_ip = mask_ip(src_ip)
                sanitized_dns_name = sanitize_dns_name(dns_name)

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
                    f"Inbound Request \n"
                    f"------------------------------------------\n"
                    f"Source IP: {masked_src_ip} \n"
                    f"DNS: {sanitized_dns_name}\n"
                    f"Protocol: {protocol_name} | "
                    f"{packet_type_details} \n"
                    f"Packet Size: {packet_size} bytes\n"
                )

                # Log the structured message
                logger.info(log_message)

                # Update the dictionary with the latest timestamp
                recent_requests[packet_key] = timestamp
    except Exception as e:
        logger.error(f"Packet processing error: {e}")
            
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
    
    if active_interface is None:
        print("No active interface found. Exiting.")
        sys.exit(1)
        
    # Start sniffing for inbound traffic on the active interface
    sniffing_thread = threading.Thread(target=start_sniffing, args=(active_interface,))
    sniffing_thread.start()
    
    drop_privileges(uid_name='nobody')
    
    # Start the DoS detection thread
    detection_thread = threading.Thread(target=detect_dos_attacks, daemon=True)
    detection_thread.start()
    
