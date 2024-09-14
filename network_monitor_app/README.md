//This is a security application - the goals of this application is:
    1. Ensure network security
        a. Monitor network traffic
            - Inbound Traffic
            - Outbound Traffic
            - Active Connections
            - Network usage by application
                -- CPU and RAM usage in relation to the app
        b. Block potential threats
            - DoS/DDoS protection

        c. Robust alerting

        

Screens/Modules:
Home Dashboard:
Overview of network activity.
Graphs of current and past network speeds.
CPU and RAM indicators for network-related processes.
Connections Tab:
List of active connections.
Source IP, destination IP, hostname, port, and data usage.
Settings Panel:
Allow users to set thresholds for alerts.
Configure update frequency and logs retention period.
Alerts Section:
View recent alerts for unusual activity (e.g., high traffic, connection spikes).
Lightweight Design Considerations:
Low CPU and Memory Usage: Ensure the app stays lightweight by optimizing polling intervals (e.g., update every second or less frequently).
Background Execution: Provide an option to run in the system tray and monitor in the background without affecting system performance.
Minimal Dependencies: Avoid large libraries or dependencies, especially if using Electron or similar frameworks, to keep the app small.