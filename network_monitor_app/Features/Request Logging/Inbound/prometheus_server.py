import os
import webbrowser
import logging
import argparse
import signal
import sys
from http.server import HTTPServer, BaseHTTPRequestHandler

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

class InboundRequestHandler(BaseHTTPRequestHandler):
    def do_GET(self):
        logger.info(f"Received GET request: Path={self.path}, Headers={self.headers}")
        self.send_response(200)
        self.end_headers()
        self.wfile.write(b"Hello, Prometheus!")

    def log_message(self, format, *args):
        return  # Override to prevent default console logging

def start_http_server(port):
    server_address = ('', port)
    httpd = HTTPServer(server_address, InboundRequestHandler)
    logger.info(f"Starting HTTP server on port {port}")
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        logger.info("Shutting down HTTP server...")
        httpd.server_close()

def open_prometheus_ui(url):
    try:
        webbrowser.open(url)
        logger.info("Opened Prometheus server UI")
    except Exception as e:
        logger.error(f"Failed to open Prometheus server UI: {e}")

def signal_handler(sig, frame):
    logger.info('Received shutdown signal. Exiting gracefully...')
    sys.exit(0)

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--prometheus-url', type=str, default='http://localhost:9090', help='URL to open Prometheus server')
    parser.add_argument('--port', type=int, default=8000, help='Port for the inbound HTTP server')
    args = parser.parse_args()

    # Handle graceful shutdown
    signal.signal(signal.SIGINT, signal_handler)
    signal.signal(signal.SIGTERM, signal_handler)

    # Start the HTTP server
    start_http_server(args.port)

    # Open Prometheus UI
    open_prometheus_ui(args.prometheus_url)

if __name__ == "__main__":
    main()