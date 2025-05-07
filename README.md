# Nexus IDS - Advanced Network Intrusion Detection System

**🛡️ Securing Networks, Protecting Data 🛡️**

## 📋 Overview

Nexus IDS is a powerful, real-time network intrusion detection system designed to monitor network traffic, detect suspicious activities, and alert administrators to potential security threats. With its advanced threat detection algorithms and visually rich interface, Nexus IDS offers comprehensive protection for any network environment.

## ✨ Key Features

- **Real-time Traffic Monitoring**: Analyze network packets as they traverse your network
- **Threat Detection Engine**: Identify suspicious patterns and potential attacks using advanced heuristics
- **Visual Dashboard**: Monitor network status with a rich, interactive console interface
- **Alert System**: Get notified of potential threats with visual and audio alerts
- **Protocol Analysis**: Track and analyze different network protocols (TCP, UDP, ICMP)
- **Threat Scoring**: Quantify the severity of detected threats for prioritized responses
- **Comprehensive Reporting**: Generate detailed reports of monitoring sessions
- **Low Resource Footprint**: Efficient operation on standard hardware

## 🔧 Requirements

- Python 3.7+
- Linux/Unix environment (requires root privileges for packet capture)
- The following Python packages:
  - scapy
  - rich
  - pygame
  - netifaces
  - psutil
  - numpy

## 🚀 Installation

1. Clone the repository:
   ```bash
   git clone https://github.com/yourusername/nexus-ids.git
   cd nexus-ids
   ```

2. Create a requirements.txt file with the following content:
   ```
   scapy
   rich
   pygame
   netifaces
   psutil
   numpy
   ```

3. Install the required dependencies:
   ```bash
   pip install -r requirements.txt
   ```

4. Ensure you have the necessary permissions:
   ```bash
   chmod +x nexus_ids.py
   ```

## 📘 Usage Guide

### Starting the Tool

Run Nexus IDS with root privileges (required for packet capture):

```bash
sudo python nexus_ids.py
```

### User Interface Overview

When you start Nexus IDS, you'll see:

1. **Banner**: The Nexus IDS ASCII banner appears during startup
2. **Initialization Animation**: Shows the loading progress of various security modules
3. **Main Dashboard**: Four-panel display showing:
   - Current status bar (top)
   - Normal traffic panel (left top)
   - Malicious traffic panel (left bottom)
   - Live statistics panel (right)

### Interpreting the Dashboard

**Status Bar**:
- Shows current monitoring status with animation
- Displays count of active threats

**Normal Traffic Panel**:
- Lists the 5 most recent legitimate network connections
- Shows timestamp, source IP, and protocol

**Malicious Traffic Panel**:
- Lists the 5 most recent suspicious activities
- Shows timestamp, source IP, and threat score
- Higher threat scores indicate more dangerous traffic

**Live Statistics Panel**:
- System Status: CPU and memory usage
- Network Status: Uptime, packets per second, total packets analyzed
- Security Stats: Active threats count, total alerts, unique IPs
- Protocol Distribution: Percentage breakdown of traffic by protocol

### Alert System

When Nexus IDS detects suspicious activity:
1. The entry appears in the Malicious Traffic panel
2. An alert sound plays (if threat score exceeds threshold)
3. The alert is logged for the final report

### Common Threat Indicators

Look for these signs of potential threats:
- Rapid increases in the packets per second count
- Multiple entries from the same IP in the Malicious Traffic panel
- High threat scores (above 7.0)
- Increasing Active Threats count in the Status Bar

### Ending a Monitoring Session

To gracefully exit and generate a monitoring report:
1. Press `Ctrl+C`
2. You'll be asked if you want to save the monitoring report
3. Enter `y` to save or `n` to exit without saving
4. If saving, you can specify a filename or accept the default

### Report Interpretation

The JSON report contains:
- **session_info**: Details about the monitoring session duration
- **network_stats**: Raw data about the monitored network traffic
- **security_stats**: Summary of alerts and traffic classifications
- **alerts**: Chronological list of all security alerts
- **malicious_traffic**: Details of all detected suspicious activities

## 🔧 Advanced Configuration

To customize the tool for your environment, edit these variables in the source code:

```python
# Enhanced configuration
self.scan_threshold = 5        # Increase for busy networks
self.connection_threshold = 50 # Increase for busy networks
self.threat_score_threshold = 7.0 # Lower for more sensitivity
self.malicious_ports = {22, 23, 445, 3389, 5900} # Add/remove based on your environment
self.suspicious_patterns = {
    b'eval(', b'exec(', b'system(', b'cmd.exe', b'/bin/sh',
    b'SELECT', b'UNION', b'DROP TABLE', b'rm -rf', b'wget'
}
```

### Configuration Guidelines

1. **scan_threshold**: 
   - Default: 5
   - Recommendation: 3-10 (Lower value = more sensitive)
   - Purpose: Controls how many different port accesses trigger port scan detection

2. **connection_threshold**:
   - Default: 50
   - Recommendation: 20-100 (Adjust based on network size)
   - Purpose: Controls how many connections from one IP are considered suspicious

3. **threat_score_threshold**:
   - Default: 7.0
   - Recommendation: 5.0-9.0 (Lower value = more alerts)
   - Purpose: Minimum score to trigger audio alerts

4. **malicious_ports**:
   - Add any ports that should be considered suspicious in your environment
   - Remove ports that are legitimately used in your network

5. **suspicious_patterns**:
   - Add byte patterns specific to your threat environment
   - Can be customized for specific web application attacks

## 🛠️ Troubleshooting

Common issues and solutions:

1. **Permission Error**: If you see "This program must be run as root!", ensure you're using sudo.

2. **Interface Not Found**: Check that you have the correct network interface available:
   ```bash
   ip addr show
   ```

3. **High CPU Usage**: On very busy networks, try increasing thresholds to reduce processing load.

4. **No Audio Alerts**: Make sure pygame is installed correctly and your system has audio output enabled.

5. **Program Crashes**: Check for dependency issues:
   ```bash
   pip install -r requirements.txt --upgrade
   ```

## 🤝 Contributing

Contributions are welcome! Please feel free to submit a Pull Request. For major changes, please open an issue first to discuss what you would like to change.

## 📜 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## 📧 Contact

Created by Jivant Loganathan - Feel free to reach out!

---

🛡️ Nexus IDS - Because network security matters 🛡️
