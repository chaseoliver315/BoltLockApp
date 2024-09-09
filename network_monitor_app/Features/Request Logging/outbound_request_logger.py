from scapy.all import sniff, IP, TCP, UDP
from datetime import datetime, timedelta
import logging
import socket
import os
import sys
import subprocess


# TODO - Find the active network interface and automatically use that to sniff traffic.
# TODO - Maybe reverse DNS Lookup to resolve DNS names.
# TODO - Flag potentially problematic packets - large sizes



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

def get_local_ip():
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

my_ip = get_local_ip()

def resolve_dns(ip_address):
    try:
        return socket.gethostbyaddr(ip_address)[0]  # Returns the DNS name
    except socket.herror:
        return None 

# Function to process and log outgoing packets
def process_packet(packet):
    if IP in packet and packet[IP].src == my_ip:
        src_ip = packet[IP].src
        dst_ip = packet[IP].dst
        protocol = packet.proto
        packet_size = len(packet)
        timestamp = datetime.now()
        dns_name = resolve_dns(dst_ip)
        
        # Create a unique key for the packet (based on src, dst, and protocol)
        packet_key = (src_ip, dst_ip, protocol)

        # Check if the packet has been seen recently
        if packet_key in recent_requests:
            last_seen = recent_requests[packet_key]
            # If the packet was seen within the time window, skip logging
            if timestamp - last_seen < timedelta(seconds=time_window):
                return

        # Organize and structure the log message
        log_message = (
            f"Outbound Request - "
            f"Destination IP: {dst_ip}, "
             f"DNS: {dns_name if dns_name else 'N/A'}, "
            f"Protocol: {protocol}, "
            f"Packet Size: {packet_size} bytes"
        )

        # Log the structured message
        logging.info(log_message)
        #print(log_message) - uncomment to write in script
        
        # Update the dictionary with the latest timestamp
        recent_requests[packet_key] = timestamp

# Start sniffing outgoing traffic
def start_sniffing(interface='en0'):
    print(f"Starting to sniff on interface {interface}...")
    
    # Filter for outbound packets (tcp, udp, icmp)
    sniff(filter="ip", iface=interface, prn=process_packet, store=0)

if __name__ == "__main__":
    # Replace 'eth0' with the name of your network interface (e.g., wlan0 for Wi-Fi)
    start_sniffing(interface='en0')
