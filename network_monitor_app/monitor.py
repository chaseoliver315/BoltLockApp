# monitor.py
import psutil

class NetworkMonitor:
    def __init__(self):
        self.prev_data = psutil.net_io_counters()

    def get_network_stats(self):
        current_data = psutil.net_io_counters()
        bytes_sent = current_data.bytes_sent - self.prev_data.bytes_sent
        bytes_recv = current_data.bytes_recv - self.prev_data.bytes_recv
        self.prev_data = current_data
        return bytes_sent, bytes_recv

    def get_active_connections(self):
        connections = psutil.net_connections()
        return [
            {
                "local_address": conn.laddr,
                "remote_address": conn.raddr,
                "status": conn.status
            }
            for conn in connections if conn.raddr
        ]