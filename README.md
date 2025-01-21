Nexus IDS: Advanced Network Defense System 🛡️
A sophisticated real-time network intrusion detection system with comprehensive monitoring, threat detection, and security analytics capabilities, featuring an elegant terminal user interface.
Show Image
Features 🚀
Core Capabilities

Real-time packet analysis and threat detection
Live traffic monitoring with protocol distribution analytics
Intelligent threat scoring system
Port scanning and suspicious behavior detection
Internal/external traffic analysis
Comprehensive logging and reporting

Interface & Monitoring

Beautiful terminal-based UI powered by Rich library
Live network statistics and performance metrics
Audio alerts for high-severity threats
Dynamic protocol distribution visualization
Real-time threat monitoring dashboard

Security Features

Suspicious pattern recognition
Malicious payload detection
Connection tracking and analysis
Customizable threat thresholds
Automated alert system
Internal network monitoring

Installation 🔧
Prerequisites

Python 3.x
Root/Administrator privileges
Linux/Unix-based system (Windows support coming soon)

Required Packages
bashCopypip install scapy
pip install rich
pip install pygame
pip install psutil
pip install netifaces
Quick Start

Clone the repository:

bashCopygit clone https://github.com/JivantLoganathan/nexus-ids.git
cd nexus-ids

Install dependencies:

bashCopypip install -r requirements.txt

Run with root privileges:

bashCopysudo python3 nexus_ids.py
Usage 📖
Basic Operation

Launch the application with root privileges
The system will automatically:

Initialize security modules
Configure network monitors
Establish baseline metrics
Begin real-time packet analysis



Interface Navigation

Real-time statistics are displayed in the right panel
Normal traffic appears in the top-left panel
Suspicious/malicious traffic appears in the bottom-left panel
System alerts are shown with color-coding based on severity

Customization
Edit the following parameters in the configuration section:
pythonCopyscan_threshold = 5
connection_threshold = 50
threat_score_threshold = 7.0
malicious_ports = {22, 23, 445, 3389, 5900}
Configuration ⚙️
Threat Detection Parameters

scan_threshold: Maximum allowed port scans before flagging
connection_threshold: Connection count threshold for suspicious activity
threat_score_threshold: Minimum score for high-severity alerts
malicious_ports: List of ports considered potentially dangerous

Alert System

Audio alerts for high-severity threats
Customizable alert cooldown period
Visual alerts with severity-based color coding

Report Generation 📊
The system automatically generates comprehensive JSON reports including:

Session information
Network statistics
Security events
Threat detections
Traffic analysis

Example report generation:
pythonCopyreport = ids.generate_report()
Contributing 🤝

Fork the repository
Create your feature branch (git checkout -b feature/AmazingFeature)
Commit your changes (git commit -m 'Add some AmazingFeature')
Push to the branch (git push origin feature/AmazingFeature)
Open a Pull Request

Security Notes 🔒

This tool requires root privileges to capture network packets
Use responsibly and in accordance with your organization's security policies
Regularly update threat definitions and suspicious patterns
Monitor and adjust thresholds based on your network's baseline

License 📄
This project is licensed under the MIT License - see the LICENSE file for details.
Acknowledgments 🙏

Scapy library for packet capture functionality
Rich library for the beautiful terminal interface
PyGame for audio alert system
All contributors and testers


Screenshots 📸
DASHBOARD:
![image](https://github.com/user-attachments/assets/bf24ab70-72c2-4ec1-bcbe-7495f6abab09)
ALERT:
![image](https://github.com/user-attachments/assets/3fa1c71e-5a8d-4b66-8a5f-b3dbbd121abc)
LOG FILE:
![image](https://github.com/user-attachments/assets/6b5e6553-5818-4763-929c-c5f971f9a6b1)
![image](https://github.com/user-attachments/assets/1092563c-52bf-4014-9573-ffe4bb52ca93)




