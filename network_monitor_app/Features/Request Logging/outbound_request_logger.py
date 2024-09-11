from scapy.all import sniff, IP, ICMP, TCP, UDP
from datetime import datetime, timedelta
import logging
import psutil
import socket
import os
import sys
import subprocess

# TODO - Build a ICMP Echo Request Detector / Blocker
# TODO - Flag potentially problematic packets - large sizes

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
    filename='outbound_requests.log',  # Log file name
    level=logging.INFO,               # Logging level
    format='%(asctime)s - %(message)s',  # Log format with timestamp
    filemode='w'  # Overwrite the log file each time ('a' to append)
)

# Dictionary to store recently seen requests
recent_requests = {}

# Time window to filter duplicate requests (in seconds)
time_window = 5

def get_local_ip(interface):
    """
    Finds and returns the local IP address of the machine.
    """
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
    
    for interface, stats in interfaces.items():
        if stats.isup and interface in addrs:  # Check if the interface is up and has an address
            for addr in addrs[interface]:
                if addr.family == socket.AF_INET:  # Filter for IPv4 addresses
                    return interface  # Return the first active interface found
    return None


# Get the active network interface and its IP
active_interface = get_active_interface()

my_ip = get_local_ip(active_interface)



def resolve_dns(ip_address):
    try:
        return socket.gethostbyaddr(ip_address)[0]  # Returns the DNS name
    except socket.herror:
        return None 


def analyze_packet_type(packet):
    if IP in packet:
        # Check if the packet is ICMP
        if ICMP in packet:
            icmp_type = packet[ICMP].type
            icmp_code = packet[ICMP].code
            return f"Type: {icmp_type}, Code: {icmp_code}"

        # Check if the packet is TCP
        elif TCP in packet:
            tcp_flags = packet[TCP].flags
            src_port = packet[TCP].sport
            dst_port = packet[TCP].dport
            return f"Source Port: {src_port}, Destination Port: {dst_port}, Flags: {tcp_flags}"

        # Check if the packet is UDP
        elif UDP in packet:
            src_port = packet[UDP].sport
            dst_port = packet[UDP].dport
            return f"Source Port: {src_port}, Destination Port: {dst_port}"

        # For unknown protocol types
        else:
            return "Unknown Packet Type"


# Function to process and log outgoing packets
def process_packet(packet):
    if IP in packet and packet[IP].src == my_ip:
        src_ip = packet[IP].src
        dst_ip = packet[IP].dst
        protocol = packet.proto
        packet_size = len(packet)
        protocol_number = packet.proto
        protocol_name = protocol_mapping.get(protocol_number, f"Unknown ({protocol_number})") 
        timestamp = datetime.now()
        dns_name = resolve_dns(dst_ip)
        
        # Create a unique key for the packet (based on src, dst, and protocol)
        packet_key = (src_ip, dst_ip, protocol)

        packet_type_details = analyze_packet_type(packet)

        # Check if the packet has been seen recently
        if packet_key in recent_requests:
            last_seen = recent_requests[packet_key]
            # If the packet was seen within the time window, skip logging
            if timestamp - last_seen < timedelta(seconds=time_window):
                return

        # Organize and structure the log message
        log_message = (
            f"Outbound Request - "
            f"Destination IP: {dst_ip} "
             f"DNS: {dns_name if dns_name else 'N/A'} "
            f"Protocol: {protocol_name} "
            f"{packet_type_details} "
            f"Packet Size: {packet_size} bytes"
        )

        # Log the structured message
        logging.info(log_message)
        #print(log_message) - uncomment to write in script
        
        # Update the dictionary with the latest timestamp
        recent_requests[packet_key] = timestamp

# Start sniffing outgoing traffic
def start_sniffing(interface):
    print(f"Starting to sniff on interface {interface}...")
    print(f"Removing duplicates that appear more than once every {time_window} seconds...")
    # Filter for outbound packets (tcp, udp, icmp)
    sniff(filter="ip", iface=interface, prn=process_packet, store=0)

if __name__ == "__main__":
    # Replace 'eth0' with the name of your network interface (e.g., wlan0 for Wi-Fi)
    start_sniffing(interface='en0')
