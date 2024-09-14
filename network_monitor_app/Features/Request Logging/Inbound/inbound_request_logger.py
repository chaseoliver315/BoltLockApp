from scapy.all import sniff
from privilege_utils import check_and_elevate, drop_privileges
from network_utils import get_active_interface, get_local_ip
import packet_processor  # Import the module, not just functions
from dos_detector import detect_dos_attacks
from log_setup import setup_logging
import threading
import sys

if __name__ == "__main__":
    # Check and elevate privileges
    check_and_elevate()

    # Set up logging
    setup_logging()

    # Get the active network interface and IP
    active_interface = get_active_interface()
    my_ip_address = get_local_ip(active_interface)
    packet_processor.my_ip = my_ip_address  # Set the global my_ip in packet_processor

    if active_interface is None:
        print("No active network interface found. Exiting.")
        sys.exit(1)

    # Start the DoS detection thread
    detection_thread = threading.Thread(target=detect_dos_attacks, args=(packet_processor.packet_counts,))
    detection_thread.daemon = True
    detection_thread.start()

    # Start packet sniffing
    print(f"Starting to sniff on interface {active_interface}...")
    sniff_thread = threading.Thread(target=sniff, kwargs={
        'filter': "ip",
        'iface': active_interface,
        'prn': packet_processor.process_packet,
        'store': 0
    })
    sniff_thread.start()

    # Drop privileges after initializing sniffing
    drop_privileges(uid_name='nobody')

    # Wait for threads to complete
    sniff_thread.join()
    detection_thread.join()
