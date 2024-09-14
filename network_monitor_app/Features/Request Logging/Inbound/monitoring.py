import time
from prometheus_client import Gauge

# Define a Gauge metric to track packet counts per IP
packet_count_gauge = Gauge('dos_detector_packet_count', 'Packet counts per IP', ['ip'])

def update_metrics(packet_counts):
    while True:
        for ip, count in packet_counts.items():
            packet_count_gauge.labels(ip=ip).set(count)
        time.sleep(5)  # Update every 5 seconds
