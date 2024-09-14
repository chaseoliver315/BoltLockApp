from scapy.all import IP, ICMP, TCP, UDP
from datetime import datetime, timedelta
from sanitization_utils import mask_ip, sanitize_dns_name
from network_utils import resolve_dns
import logging

# Protocol mapping dictionary
protocol_mapping = {
    1: 'ICMP',
    6: 'TCP',
    17: 'UDP',
    47: 'GRE',
    50: 'ESP',
    58: 'ICMPv6',
    89: 'OSPF'
}

recent_requests = {}
time_window = 5  # Time window to filter duplicate requests
packet_counts = {}  # For DoS detection
my_ip = None  # Will be set in the main script
logger = logging.getLogger()

def analyze_packet_type(packet):
    if ICMP in packet:
        icmp_type = packet[ICMP].type
        return f"ICMP Packet: Type {icmp_type}"
    elif TCP in packet:
        tcp_flags = packet[TCP].flags
        return f"TCP Packet: Flags {tcp_flags}"
    elif UDP in packet:
        return "UDP Packet"
    else:
        return "Unknown Packet Type"

def process_packet(packet):
    global recent_requests, packet_counts
    if IP in packet:
        src_ip = packet[IP].src
        dst_ip = packet[IP].dst

        # Ignore loopback traffic
        if src_ip.startswith('127.') or dst_ip.startswith('127.'):
            return

        # Check if the packet is inbound
        if dst_ip == my_ip:
            # Increment the packet count for DoS detection
            packet_counts[src_ip] = packet_counts.get(src_ip, 0) + 1

            # Existing logging and processing logic
            protocol_number = packet.proto
            protocol_name = protocol_mapping.get(protocol_number, f"Unknown ({protocol_number})")
            packet_size = len(packet)
            timestamp = datetime.now()

            # Analyze the packet type
            packet_type_details = analyze_packet_type(packet)

            # Resolve and sanitize the DNS name
            dns_name = resolve_dns(src_ip)
            sanitized_dns_name = sanitize_dns_name(dns_name)

            # Mask the source IP
            masked_src_ip = mask_ip(src_ip)

            # Create a unique key for the packet
            packet_key = (src_ip, dst_ip, protocol_number)

            # Check for duplicate requests
            if packet_key in recent_requests:
                last_seen = recent_requests[packet_key]
                if timestamp - last_seen < timedelta(seconds=time_window):
                    return

            # Organize and structure the log message
            log_message = (
                f"Inbound Request\n"
                f"Source IP: {masked_src_ip}\n"
                f"DNS: {sanitized_dns_name}\n"
                f"Protocol: {protocol_name}\n"
                f"{packet_type_details}\n"
                f"Packet Size: {packet_size} bytes\n"
                f"\n"
            )

            # Log the structured message
            logger.info(log_message)

            # Update the dictionary with the latest timestamp
            recent_requests[packet_key] = timestamp
