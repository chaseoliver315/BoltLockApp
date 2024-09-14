import socket
import psutil

def resolve_dns(ip_address):
    """Resolves the DNS name for a given IP address."""
    try:
        return socket.gethostbyaddr(ip_address)[0]  # Returns the DNS name
    except socket.herror:
        return None  # If no DNS name is found, return None

def get_local_ip(interface):
    """Finds and returns the local IP address of the machine."""
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.settimeout(0)
        # Connect to an external server to get local IP
        s.connect(('8.8.8.8', 1))
        local_ip = s.getsockname()[0]
    except Exception:
        local_ip = '127.0.0.1'  # Fallback
    finally:
        s.close()
    return local_ip

def get_active_interface():
    interfaces = psutil.net_if_stats()
    addrs = psutil.net_if_addrs()
    ignore_interfaces = ['lo', 'docker0', 'vboxnet0', 'virbr0', 'lo0']
    for interface, stats in interfaces.items():
        if stats.isup and interface in addrs and interface not in ignore_interfaces:
            for addr in addrs[interface]:
                if addr.family == socket.AF_INET:
                    return interface
    return None
