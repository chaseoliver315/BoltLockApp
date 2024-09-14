import time
import logging
from sanitization_utils import mask_ip

PACKET_THRESHOLD = 100  # Adjust as needed
TIME_INTERVAL = 10      # Time interval for checking packet counts
logger = logging.getLogger()

def detect_dos_attacks(packet_counts):
    while True:
        time.sleep(TIME_INTERVAL)
        for ip, count in packet_counts.items():
            if count > PACKET_THRESHOLD:
                masked_ip = mask_ip(ip)
                alert_message = (
                    f"Potential DoS attack detected\n"
                    f"IP: {masked_ip}\n"
                    f"Packets: {count}\n"
                    f"Interval: {TIME_INTERVAL} seconds\n"
                    f"\n"
                )
                print(alert_message)
                logger.warning(alert_message)
        # Reset packet counts
        packet_counts.clear()
