import matplotlib.pyplot as plt
from matplotlib.backends.backend_tkagg import FigureCanvasTkAgg
import tkinter as tk
class NetworkMonitorApp(tk.Tk):
    def __init__(self, monitor):
        super().__init__()
        self.monitor = monitor
        self.title("Network Monitor")
        self.geometry("600x400")
        
        self.label_sent = tk.Label(self, text="Data Sent: 0 bytes")
        self.label_sent.pack(pady=10)
        
        self.label_recv = tk.Label(self, text="Data Received: 0 bytes")
        self.label_recv.pack(pady=10)

        # Matplotlib figure
        self.fig, self.ax = plt.subplots()
        self.canvas = FigureCanvasTkAgg(self.fig, master=self)
        self.canvas.get_tk_widget().pack(pady=10)
        
        self.data_sent = []
        self.data_recv = []

        self.update_stats()

    def update_stats(self):
        sent, recv = self.monitor.get_network_stats()
        self.label_sent.config(text=f"Data Sent: {sent} bytes")
        self.label_recv.config(text=f"Data Received: {recv} bytes")
        
        self.data_sent.append(sent)
        self.data_recv.append(recv)

        # Update graph
        self.ax.clear()
        self.ax.plot(self.data_sent[-20:], label='Bytes Sent')
        self.ax.plot(self.data_recv[-20:], label='Bytes Received')
        self.ax.legend()
        self.canvas.draw()

        self.after(1000, self.update_stats)