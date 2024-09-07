from monitor import NetworkMonitor
from ui import NetworkMonitorApp
from tkinter import *
# Main function to start the application
if __name__ == "__main__":
    monitor = NetworkMonitor()  # Initialize the network monitor
    app = NetworkMonitorApp(monitor)  # Create the UI and pass in the monitor
    app.mainloop()  # Run the UI event loop