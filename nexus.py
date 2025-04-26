import scapy.all as scapy
from datetime import datetime, timedelta
import threading
import time
import sys
import signal
import os
import random
import ipaddress
import collections
from rich.console import Console
from rich.live import Live
from rich.panel import Panel
from rich.layout import Layout
from rich.table import Table
from rich.text import Text
from rich import box
from rich.style import Style
from rich.align import Align
from rich.progress import Progress, SpinnerColumn, BarColumn, TextColumn
import netifaces
import socket
from collections import defaultdict
import psutil
import json
import pygame
import numpy
import math

# Ensure scapy has SSL/TLS support
try:
    from scapy.layers.ssl import TLS
except ImportError:
    TLS = None

class AdvancedNexusNIDS:
    def __init__(self):
        self.console = Console()
        self.alerts = []
        self.malicious_traffic = []
        self.normal_traffic = []
        self.encrypted_traffic = []  # New list for encrypted traffic
        self.is_running = True
        self.animation_frames = ["⠋", "⠙", "⠹", "⠸", "⠼", "⠴", "⠦", "⠧", "⠇", "⠏"]
        self.frame_idx = 0
        self.start_time = datetime.now()

        # Initialize audio system
        pygame.mixer.init()
        
        # Create the alert sound (a simple beep using pygame)
        self.alert_frequency = 440  # Hz (A4 note)
        self.alert_duration = 1000  # milliseconds
        self.alert_volume = 0.5  # 50% volume
        
        # Generate the alert sound
        sample_rate = 44100
        num_samples = int(sample_rate * (self.alert_duration / 1000.0))
        sound_buffer = numpy.zeros((num_samples, 2), dtype=numpy.int16)
        max_sample = 2**(16 - 1) - 1
        
        for sample in range(num_samples):
            t = float(sample) / sample_rate
            value = int(max_sample * math.sin(2.0 * math.pi * self.alert_frequency * t) * self.alert_volume)
            sound_buffer[sample][0] = value
            sound_buffer[sample][1] = value
        
        self.alert_sound = pygame.sndarray.make_sound(sound_buffer)
        
        # Add a cooldown mechanism to prevent alert spam
        self.last_alert_time = datetime.now()
        self.alert_cooldown = timedelta(seconds=5)  # Minimum time between alerts
        
        # Key rotation intervals for encryption protocols (in seconds)
        self.key_rotation_intervals = {
            "TLS": 3600,  # 1 hour
            "SSL": 3600,  # 1 hour (deprecated, included for completeness)
            "SSH": 7200   # 2 hours
        }
        
        # Custom ASCII Banner
        self.ascii_banner = """
    ███╗   ██╗███████╗██╗  ██╗██╗   ██╗███████╗    ██╗██████╗ ███████╗
    ████╗  ██║██╔════╝╚██╗██╔╝██║   ██║██╔════╝    ██║██╔══██╗██╔════╝
    ██╔██╗ ██║█████╗   ╚███╔╝ ██║   ██║███████╗    ██║██║  ██║███████╗
    ██║╚██╗██║██╔══╝   ██╔██╗ ██║   ██║╚════██║    ██║██║  ██║╚════██║
    ██║ ╚████║███████╗██╔╝ ██╗╚██████╔╝███████║    ██║██████╔╝███████║
    ╚═╝  ╚═══╝╚══════╝╚═╝  ╚═╝ ╚═════╝ ╚══════╝    ╚═╝╚═════╝ ╚══════╝
                      **JivantLoganathan**                
            🛡️ Advanced Network Defense System 🛡️
            [ Securing Networks, Protecting Data ]
    ================================================================================
    """
       
        # Traffic tracking
        self.port_access_history = defaultdict(lambda: collections.deque(maxlen=1000))
        self.connection_count = defaultdict(int)
        self.internal_subnets = set()
        self.known_services = defaultdict(set)
        self.threat_scores = defaultdict(float)
        self.baseline_established = False
        
        # Add scan tracking for Nmap detection
        self.port_scan_window = timedelta(seconds=10)  # Time window to detect port scans
        self.port_scan_history = defaultdict(list)  # Track scanned ports by IP
       
        # Network statistics
        self.bytes_received = 0
        self.bytes_sent = 0
        self.packets_analyzed = 0
        self.last_minute_packets = collections.deque(maxlen=60)
        self.unique_ips = set()
        self.protocol_stats = defaultdict(int)
       
        # Enhanced configuration
        self.scan_threshold = 4  # Lowered from 5 to better detect nmap scans
        self.connection_threshold = 50
        self.threat_score_threshold = 7.0
        self.malicious_ports = {22, 23, 445, 3389, 5900}
        
        # Add common nmap signature ports
        self.nmap_signature_ports = {80, 443, 21, 22, 25, 53, 110, 111, 135, 139, 445, 3389}
        
        self.suspicious_patterns = {
            b'eval(', b'exec(', b'system(', b'cmd.exe', b'/bin/sh',
            b'SELECT', b'UNION', b'DROP TABLE', b'rm -rf', b'wget',
            # Add nmap signature patterns
            b'Nmap', b'PORT STATE SERVICE', b'Host discovery'
        }
       
        # Banner configuration
        self.banner_colors = [
            "bright_red", "bright_green", "bright_yellow",
            "bright_blue", "bright_magenta", "bright_cyan"
        ]
        self.banner_frames = [
            "🛡️", "⚔️", "🔒", "🔍", "⚡", "🎯", "🔐", "⛨"
        ]

    def play_alert(self):
        """Plays the alert sound if cooldown period has passed"""
        current_time = datetime.now()
        if current_time - self.last_alert_time > self.alert_cooldown:
            self.alert_sound.play()
            self.last_alert_time = current_time

    def print_banner(self):
        """Prints the ASCII banner with color"""
        banner_color = random.choice(self.banner_colors)
        self.console.print(Text(self.ascii_banner, style=banner_color))
        self.console.print("\n")

    def show_enhanced_startup_animation(self):
        """Shows an enhanced startup animation with progress bars and dynamic effects"""
        self.print_banner()
        with self.console.screen() as screen:
            progress = Progress(
                SpinnerColumn(),
                BarColumn(),
                TextColumn("[progress.description]{task.description}"),
                TextColumn("[progress.percentage]{task.percentage:>3.0f}%")
            )
           
            with progress:
                tasks = [
                    ("Initializing security modules...", "cyan"),
                    ("Loading threat detection engine...", "green"),
                    ("Configuring network monitors...", "yellow"),
                    ("Establishing baseline...", "magenta"),
                    ("Activating defense systems...", "red")
                ]
               
                running_tasks = []
                for desc, color in tasks:
                    task = progress.add_task(f"[{color}]{desc}", total=100)
                    running_tasks.append(task)
               
                while not progress.finished:
                    for task in running_tasks:
                        progress.advance(task, random.uniform(1, 4))
                    time.sleep(0.1)
                    screen.update(progress)

            for frame in self.banner_frames:
                text = Text(
                    f"\n\nActivating Nexus Defense Shield {frame}\n",
                    style=random.choice(self.banner_colors)
                )
                screen.update(Align.center(text))
                time.sleep(0.2)

    def get_uptime(self):
        """Gets formatted uptime string"""
        uptime = datetime.now() - self.start_time
        hours = int(uptime.total_seconds() // 3600)
        minutes = int((uptime.total_seconds() % 3600) // 60)
        seconds = int(uptime.total_seconds() % 60)
        return f"{hours:02d}:{minutes:02d}:{seconds:02d}"

    def get_system_stats(self):
        """Gets current system statistics"""
        cpu_percent = psutil.cpu_percent()
        memory = psutil.virtual_memory()
        return {
            'cpu': cpu_percent,
            'memory': memory.percent,
            'network_io': psutil.net_io_counters()
        }

    def get_status_style(self, value):
        """Returns appropriate style based on value"""
        if value < 50:
            return "bright_green"
        elif value < 80:
            return "bright_yellow"
        else:
            return "bright_red"

    def update_network_stats(self, packet):
        """Updates network statistics based on packet data"""
        self.packets_analyzed += 1
        self.last_minute_packets.append(datetime.now())
       
        if packet.haslayer(scapy.IP):
            ip = packet[scapy.IP]
            self.bytes_received += len(packet)
            self.unique_ips.add(ip.src)
            self.unique_ips.add(ip.dst)
           
            if packet.haslayer(scapy.TCP):
                self.protocol_stats['TCP'] += 1
            elif packet.haslayer(scapy.UDP):
                self.protocol_stats['UDP'] += 1
            elif packet.haslayer(scapy.ICMP):
                self.protocol_stats['ICMP'] += 1
            else:
                self.protocol_stats['Other'] += 1

    def get_packets_per_second(self):
        """Calculates current packets per second"""
        now = datetime.now()
        minute_ago = now - timedelta(minutes=1)
        recent_packets = sum(1 for timestamp in self.last_minute_packets if timestamp > minute_ago)
        return recent_packets / 60 if recent_packets > 0 else 0

    def generate_stats_panel(self):
        """Generates an enhanced statistics panel"""
        stats_table = Table(show_header=False, box=box.ROUNDED, expand=True)
       
        # System Stats
        system_stats = self.get_system_stats()
        stats_table.add_row("📊 System Status", style="bold cyan")
        stats_table.add_row(
            f"CPU Usage: {system_stats['cpu']}%",
            style=self.get_status_style(system_stats['cpu'])
        )
        stats_table.add_row(
            f"Memory Usage: {system_stats['memory']}%",
            style=self.get_status_style(system_stats['memory'])
        )
       
        # Network Stats
        stats_table.add_row("", style="dim")
        stats_table.add_row("🌐 Network Status", style="bold cyan")
        stats_table.add_row(f"Uptime: {self.get_uptime()}", style="bright_green")
        stats_table.add_row(f"Packets/sec: {self.get_packets_per_second():.1f}", style="bright_blue")
        stats_table.add_row(f"Total Packets: {self.packets_analyzed:,}", style="bright_blue")
       
        # Threat Stats
        stats_table.add_row("", style="dim")
        stats_table.add_row("🔒 Security Stats", style="bold cyan")
        stats_table.add_row(
            f"Active Threats: {len(self.malicious_traffic)}",
            style="bright_red" if self.malicious_traffic else "bright_green"
        )
        stats_table.add_row(f"Total Alerts: {len(self.alerts)}", style="bright_yellow")
        stats_table.add_row(f"Unique IPs: {len(self.unique_ips):,}", style="bright_magenta")
       
        # Protocol Distribution
        stats_table.add_row("", style="dim")
        stats_table.add_row("📈 Protocol Distribution", style="bold cyan")
        for protocol, count in self.protocol_stats.items():
            percentage = (count / self.packets_analyzed * 100) if self.packets_analyzed > 0 else 0
            stats_table.add_row(f"{protocol}: {percentage:.1f}%", style="bright_white")
       
        return Panel(
            stats_table,
            title="📈 Live Statistics",
            border_style="blue",
            box=box.ROUNDED
        )

    def generate_traffic_panels(self):
        """Generates traffic monitoring panels, including encrypted traffic"""
        # Normal Traffic Table
        normal_table = Table(show_header=True, header_style="bold green", box=box.ROUNDED)
        normal_table.add_column("Time", style="cyan")
        normal_table.add_column("Source", style="bright_white")
        normal_table.add_column("Protocol", style="bright_green")
       
        for traffic in self.normal_traffic[-5:]:
            normal_table.add_row(
                traffic['timestamp'].strftime("%H:%M:%S"),
                traffic['source_ip'],
                traffic['protocol']
            )
           
        # Malicious Traffic Table
        malicious_table = Table(show_header=True, header_style="bold red", box=box.ROUNDED)
        malicious_table.add_column("Time", style="cyan")
        malicious_table.add_column("Source", style="bright_white")
        malicious_table.add_column("Threat Score", style="bright_red")
        malicious_table.add_column("Type", style="bright_yellow")
       
        for traffic in self.malicious_traffic[-5:]:
            threat_type = traffic.get('threat_type', 'Unknown')
            malicious_table.add_row(
                traffic['timestamp'].strftime("%H:%M:%S"),
                traffic['source_ip'],
                f"{traffic['threat_score']:.1f}",
                threat_type
            )
           
        # Encrypted Traffic Table
        encrypted_table = Table(show_header=True, header_style="bold blue", box=box.ROUNDED)
        encrypted_table.add_column("Time", style="cyan")
        encrypted_table.add_column("Source", style="bright_white")
        encrypted_table.add_column("Protocol", style="bright_blue")
        encrypted_table.add_column("Key Rotation", style="bright_cyan")
       
        for traffic in self.encrypted_traffic[-5:]:
            protocol = traffic.get('protocol', 'Unknown')
            key_rotation = self.key_rotation_intervals.get(protocol, 0)
            encrypted_table.add_row(
                traffic['timestamp'].strftime("%H:%M:%S"),
                traffic['source_ip'],
                protocol,
                f"{key_rotation}s"
            )
           
        return normal_table, malicious_table, encrypted_table

    def generate_display(self):
        """Generates the main display layout with encrypted traffic panel"""
        layout = Layout()
        layout.split_column(
            Layout(name="banner", size=10),
            Layout(name="status", size=3),
            Layout(name="main")
        )
        layout["main"].split_row(
            Layout(name="traffic", ratio=2),
            Layout(name="stats", ratio=1)
        )
        layout["traffic"].split_column(
            Layout(name="normal_traffic"),
            Layout(name="malicious_traffic"),
            Layout(name="encrypted_traffic")  # New panel for encrypted traffic
        )

        layout["banner"].update(Panel(
            Align.center(self.get_enhanced_banner()),
            box=box.DOUBLE_EDGE,
            border_style="bright_blue",
            padding=(0, 2)
        ))

        status = Text(
            f"🛡️ Monitoring Network Traffic {self.animation_frames[self.frame_idx]} | " +
            f"Active Threats: {sum(1 for score in self.threat_scores.values() if score > self.threat_score_threshold)}",
            style="bold green"
        )
        layout["status"].update(Panel(
            Align.center(status),
            box=box.ROUNDED,
            border_style="green"
        ))

        normal_table, malicious_table, encrypted_table = self.generate_traffic_panels()
       
        layout["normal_traffic"].update(Panel(
            normal_table,
            title="✅ Normal Traffic",
            border_style="green"
        ))
       
        layout["malicious_traffic"].update(Panel(
            malicious_table,
            title="⚠️ Malicious Traffic",
            border_style="red"
        ))
       
        layout["encrypted_traffic"].update(Panel(
            encrypted_table,
            title="🔐 Encrypted Traffic",
            border_style="blue"
        ))

        layout["stats"].update(self.generate_stats_panel())

        self.frame_idx = (self.frame_idx + 1) % len(self.animation_frames)
        return layout

    def get_enhanced_banner(self):
        current_time = time.time()
        frame_index = int(current_time * 2) % len(self.banner_frames)
        color_index = int(current_time * 4) % len(self.banner_colors)
       
        banner = f"""
    ███    ██ ███████ ██   ██ ██    ██ ███████
    ████   ██ ██       ██ ██  ██    ██ ██      
    ██ ██  ██ █████     ███   ██    ██ ███████
    ██  ██ ██ ██       ██ ██  ██    ██      ██
    ██   ████ ███████ ██   ██  ██████  ███████
                -JIVANT LOGANATHAN
    {self.banner_frames[frame_index]} Advanced Network Defense System {self.banner_frames[(frame_index + 4) % len(self.banner_frames)]}
         Securing Networks, Protecting Data
"""
        return Text(banner, style=self.banner_colors[color_index])

    def is_port_scan(self, src_ip):
        """Detects if an IP is conducting a port scan"""
        if src_ip not in self.port_scan_history:
            return False
            
        # Get port access history for the scan detection window
        now = datetime.now()
        scan_window_start = now - self.port_scan_window
        
        # Filter to only include port accesses within the window
        recent_accesses = [access for access in self.port_scan_history[src_ip] 
                          if access['timestamp'] >= scan_window_start]
        
        if not recent_accesses:
            return False
            
        # Extract unique ports accessed
        unique_ports = set(access['port'] for access in recent_accesses)
        
        # If many unique ports accessed in short time, likely a port scan
        if len(unique_ports) >= self.scan_threshold:
            # Check if there are typical nmap scan signature ports
            nmap_signature_ports_found = unique_ports.intersection(self.nmap_signature_ports)
            if len(nmap_signature_ports_found) >= 2:  # At least 2 signature ports
                return True
                
            # Check for sequential port scanning (common in nmap)
            port_list = sorted(list(unique_ports))
            for i in range(len(port_list) - 1):
                if port_list[i+1] - port_list[i] == 1:  # Sequential ports
                    return True
                    
            # Check for general port scanning
            return len(unique_ports) >= self.scan_threshold * 2  # Higher threshold for general scanning
            
        return False

    def is_syn_scan(self, packet):
        """Detects SYN scan (half-open connections typical of nmap)"""
        if packet.haslayer(scapy.TCP):
            # Check for SYN packet with no ACK (typical of nmap SYN scan)
            if packet[scapy.TCP].flags == 2:  # SYN flag only
                return True
        return False

    def is_malicious_packet(self, packet):
        """Checks if a packet is potentially malicious"""
        if not packet.haslayer(scapy.IP):
            return False
            
        src_ip = packet[scapy.IP].src
        
        # Check if this IP is conducting a port scan
        if self.is_port_scan(src_ip):
            return True
        
        # Check if it's a SYN scan
        if self.is_syn_scan(packet):
            return True
           
        if packet.haslayer(scapy.TCP):
            if packet[scapy.TCP].dport in self.malicious_ports:
                return True
               
        if packet.haslayer(scapy.Raw):
            payload = bytes(packet[scapy.Raw].load)
            if any(pattern in payload for pattern in self.suspicious_patterns):
                return True
               
        if (len(self.port_access_history[src_ip]) > self.scan_threshold or
            self.connection_count[src_ip] > self.connection_threshold):
            return True
           
        return False

    def get_protocol(self, packet):
        """Gets the protocol of a packet"""
        if packet.haslayer(scapy.TCP):
            return 'TCP'
        elif packet.haslayer(scapy.UDP):
            return 'UDP'
        elif packet.haslayer(scapy.ICMP):
            return 'ICMP'
        return 'Other'

    def detect_encryption_protocol(self, packet):
        """Detects encryption protocols in the packet"""
        if not packet.haslayer(scapy.IP) or not packet.haslayer(scapy.TCP):
            return None
            
        src_ip = packet[scapy.IP].src
        dst_ip = packet[scapy.IP].dst
        dst_port = packet[scapy.TCP].dport
        timestamp = datetime.now()
        
        # Check for TLS/SSL
        if TLS and packet.haslayer(TLS):
            return {
                'timestamp': timestamp,
                'source_ip': src_ip,
                'dest_ip': dst_ip,
                'protocol': 'TLS'
            }
        elif dst_port == 443:  # Fallback for HTTPS
            return {
                'timestamp': timestamp,
                'source_ip': src_ip,
                'dest_ip': dst_ip,
                'protocol': 'TLS'
            }
        
        # Check for SSH
        if dst_port == 22 and packet.haslayer(scapy.Raw):
            payload = bytes(packet[scapy.Raw].load)
            if payload.startswith(b'SSH-'):
                return {
                    'timestamp': timestamp,
                    'source_ip': src_ip,
                    'dest_ip': dst_ip,
                    'protocol': 'SSH'
                }
                
        return None

    def update_tracking_data(self, packet):
        """Updates packet tracking data"""
        if not packet.haslayer(scapy.IP):
            return
            
        src_ip = packet[scapy.IP].src
        self.connection_count[src_ip] += 1
       
        if packet.haslayer(scapy.TCP):
            dst_port = packet[scapy.TCP].dport
            
            # Update regular port access history
            self.port_access_history[src_ip].append((datetime.now(), dst_port))
            
            # Update port scan detection history
            self.port_scan_history[src_ip].append({
                'timestamp': datetime.now(),
                'port': dst_port,
                'flags': packet[scapy.TCP].flags
            })
            
            # Cleanup old entries in port scan history
            self.cleanup_port_scan_history(src_ip)

    def cleanup_port_scan_history(self, src_ip):
        """Removes entries older than the scan window from port scan history"""
        if src_ip not in self.port_scan_history:
            return
            
        now = datetime.now()
        scan_window_start = now - self.port_scan_window
        
        self.port_scan_history[src_ip] = [
            entry for entry in self.port_scan_history[src_ip]
            if entry['timestamp'] >= scan_window_start
        ]

    def get_threat_type(self, packet, threat_score):
        """Determines the type of threat based on packet analysis"""
        if not packet.haslayer(scapy.IP):
            return "Unknown"
            
        src_ip = packet[scapy.IP].src
        
        if self.is_port_scan(src_ip):
            return "Port Scan"
            
        if self.is_syn_scan(packet):
            return "SYN Scan"
            
        if packet.haslayer(scapy.TCP) and packet[scapy.TCP].dport in self.malicious_ports:
            return "Malicious Port"
            
        if packet.haslayer(scapy.Raw):
            payload = bytes(packet[scapy.Raw].load)
            if any(pattern in payload for pattern in self.suspicious_patterns):
                return "Suspicious Payload"
                
        if len(self.port_access_history[src_ip]) > self.scan_threshold:
            return "Unusual Port Activity"
            
        if self.connection_count[src_ip] > self.connection_threshold:
            return "Connection Flood"
            
        return "Suspicious Activity"

    def calculate_threat_score(self, src_ip, packet):
        """Calculates a threat score for a given packet"""
        score = 0.0
        
        # Check for port scanning
        if self.is_port_scan(src_ip):
            score += 8.0  # High score for port scanning
            
        # Check for SYN scanning
        if self.is_syn_scan(packet):
            score += 7.0  # High score for SYN scanning
       
        if len(self.port_access_history[src_ip]) > self.scan_threshold:
            score += 3.0
       
        if self.connection_count[src_ip] > self.connection_threshold:
            score += 2.0
       
        if packet.haslayer(scapy.TCP):
            dst_port = packet[scapy.TCP].dport
            if dst_port in self.malicious_ports:
                score += 2.5
       
        if packet.haslayer(scapy.Raw):
            payload = bytes(packet[scapy.Raw].load)
            if any(pattern in payload for pattern in self.suspicious_patterns):
                score += 3.0
               
        if (self.is_internal_ip(src_ip) and
            packet.haslayer(scapy.IP) and
            self.is_internal_ip(packet[scapy.IP].dst)):
            if packet.haslayer(scapy.TCP):
                dst_port = packet[scapy.TCP].dport
                if dst_port not in self.known_services[packet[scapy.IP].dst]:
                    score += 2.0
       
        return score

    def is_internal_ip(self, ip):
        """Checks if an IP address is internal"""
        try:
            ip_obj = ipaddress.ip_address(ip)
            return (ip_obj.is_private or
                   ip_obj.is_loopback or
                   ip_obj.is_link_local or
                   str(ip_obj).startswith('169.254.'))
        except ValueError:
            return False

    def cleanup_old_data(self):
        """Periodically cleans up old data to prevent memory overflow"""
        while self.is_running:
            current_time = datetime.now()
            cutoff_time = current_time - timedelta(hours=24)
           
            # Cleanup old traffic data
            self.normal_traffic = [
                traffic for traffic in self.normal_traffic
                if traffic['timestamp'] > cutoff_time
            ]
            self.malicious_traffic = [
                traffic for traffic in self.malicious_traffic
                if traffic['timestamp'] > cutoff_time
            ]
            self.encrypted_traffic = [
                traffic for traffic in self.encrypted_traffic
                if traffic['timestamp'] > cutoff_time
            ]
           
            # Cleanup old alerts
            self.alerts = [
                alert for alert in self.alerts
                if alert['timestamp'] > cutoff_time
            ]
           
            # Cleanup old port scan history
            for src_ip in list(self.port_scan_history.keys()):
                self.cleanup_port_scan_history(src_ip)
                
                # Remove the entry if it's empty
                if not self.port_scan_history[src_ip]:
                    del self.port_scan_history[src_ip]
           
            # Reset connection counts periodically
            self.connection_count.clear()
           
            time.sleep(60)

    def packet_callback(self, packet):
        """Callback function for packet processing"""
        if packet.haslayer(scapy.IP):
            self.update_network_stats(packet)
            self.update_tracking_data(packet)
            
            src_ip = packet[scapy.IP].src
            dst_ip = packet[scapy.IP].dst
            timestamp = datetime.now()
           
            # Check for encryption protocols
            encrypted_info = self.detect_encryption_protocol(packet)
            if encrypted_info:
                self.encrypted_traffic.append(encrypted_info)
            
            # Check for malicious packets
            if self.is_malicious_packet(packet):
                threat_score = self.calculate_threat_score(src_ip, packet)
                threat_type = self.get_threat_type(packet, threat_score)
                
                self.malicious_traffic.append({
                    'timestamp': timestamp,
                    'source_ip': src_ip,
                    'dest_ip': dst_ip,
                    'protocol': self.get_protocol(packet),
                    'threat_score': threat_score,
                    'threat_type': threat_type
                })
                
                # Play audio alert for any malicious packet detection
                self.play_alert()
                
                # Add specific alert messages based on threat type
                if threat_type == "Port Scan":
                    self.add_alert(f"🚨 Port scan detected from {src_ip}", "HIGH")
                elif threat_type == "SYN Scan":
                    self.add_alert(f"🚨 SYN scan (possible nmap) detected from {src_ip}", "HIGH")
                else:
                    self.add_alert(f"🚨 Malicious traffic ({threat_type}) detected from {src_ip}", "HIGH")
                
                # Update threat score tracking
                self.threat_scores[src_ip] = max(self.threat_scores[src_ip], threat_score)
                
            else:
                self.normal_traffic.append({
                    'timestamp': timestamp,
                    'source_ip': src_ip,
                    'dest_ip': dst_ip,
                    'protocol': self.get_protocol(packet)
                })

    def add_alert(self, message, severity="LOW"):
        """Adds an alert to the alert list"""
        severity_colors = {
            "LOW": "green",
            "MEDIUM": "yellow",
            "HIGH": "red"
        }
        self.alerts.append({
            'timestamp': datetime.now(),
            'message': message,
            'severity': severity,
            'color': severity_colors.get(severity, "white")
        })

    def start_capture(self):
        """Starts packet capture using scapy"""
        try:
            scapy.sniff(prn=self.packet_callback, store=False)
        except Exception as e:
            self.add_alert(f"❌ Error in packet capture: {str(e)}", "HIGH")

    def generate_report(self):
        """Generates a comprehensive monitoring report"""
        report = {
            "session_info": {
                "start_time": self.start_time.isoformat(),
                "end_time": datetime.now().isoformat(),
                "total_uptime": self.get_uptime(),
                "packets_analyzed": self.packets_analyzed
            },
            "network_stats": {
                "bytes_received": self.bytes_received,
                "bytes_sent": self.bytes_sent,
                "unique_ips": len(self.unique_ips),
                "protocol_distribution": dict(self.protocol_stats),
                "packets_per_second": self.get_packets_per_second()
            },
            "security_stats": {
                "total_alerts": len(self.alerts),
                "malicious_traffic_count": len(self.malicious_traffic),
                "normal_traffic_count": len(self.normal_traffic),
                "encrypted_traffic_count": len(self.encrypted_traffic)
            },
            "alerts": [
                {
                    "timestamp": alert["timestamp"].isoformat(),
                    "message": alert["message"],
                    "severity": alert["severity"]
                }
                for alert in self.alerts
            ],
            "malicious_traffic": [
                {
                    "timestamp": traffic["timestamp"].isoformat(),
                    "source_ip": traffic["source_ip"],
                    "dest_ip": traffic["dest_ip"],
                    "threat_score": traffic["threat_score"],
                    "threat_type": traffic.get("threat_type", "Unknown")
                }
                for traffic in self.malicious_traffic
            ],
            "encrypted_traffic": [
                {
                    "timestamp": traffic["timestamp"].isoformat(),
                    "source_ip": traffic["source_ip"],
                    "dest_ip": traffic["dest_ip"],
                    "protocol": traffic["protocol"],
                    "key_rotation_interval": self.key_rotation_intervals.get(traffic["protocol"], 0)
                }
                for traffic in self.encrypted_traffic
            ]
        }
        return report

    def prompt_save_report(self):
        """Prompts the user to save the monitoring report and continue monitoring"""
        report = self.generate_report()
        
        self.console.clear()
        self.print_banner()
        save_report = input("\nWould you like to save the monitoring report? (y/n): ").lower().strip()
    
        if save_report == 'y':
            default_filename = f"nexus_report_{datetime.now().strftime('%Y-%m-%d_%H-%M-%S')}.json"
            filename = input(f"\nEnter filename (default: {default_filename}): ").strip()
            
            if not filename:
                filename = default_filename
                
            if not filename.endswith('.json'):
                filename += '.json'
                
            try:
                with open(filename, 'w') as f:
                    json.dump(report, f, indent=4)
                self.console.print(f"\n[green]Report successfully saved to [bold]{filename}[/bold][/green]")
            except Exception as e:
                self.console.print(f"\n[red]Error saving report: {str(e)}[/red]")
        else:
            self.console.print("\n[yellow]Report not saved.[/yellow]")
            
        # Ask if user wants to continue monitoring
        continue_monitoring = input("\nContinue monitoring? (y/n): ").lower().strip()
        return continue_monitoring == 'y'

    def run(self):
        """Main method to run the NIDS"""
        self.show_enhanced_startup_animation()
        
        # Start background threads
        cleanup_thread = threading.Thread(target=self.cleanup_old_data)
        cleanup_thread.daemon = True
        cleanup_thread.start()
        
        capture_thread = threading.Thread(target=self.start_capture)
        capture_thread.daemon = True
        capture_thread.start()
        
        # Setup signal handler for graceful exit
        def signal_handler(sig, frame):
            self.is_running = False
            self.console.print("\n[yellow]Shutting down Nexus IDS...[/yellow]")
            time.sleep(1)
            continue_monitoring = self.prompt_save_report()
            if not continue_monitoring:
                sys.exit(0)
        
        signal.signal(signal.SIGINT, signal_handler)
        
        # Main display loop
        try:
            with Live(self.generate_display(), refresh_per_second=4) as live:
                while self.is_running:
                    live.update(self.generate_display())
                    time.sleep(0.25)
        except KeyboardInterrupt:
            self.is_running = False
            self.console.print("\n[yellow]Shutting down Nexus IDS...[/yellow]")
            time.sleep(1)
            self.prompt_save_report()

def main():
    """Entry point for the application"""
    nids = AdvancedNexusNIDS()
    
    try:
        nids.run()
    except Exception as e:
        nids.console.print(f"[red]Critical error: {str(e)}[/red]")
        with open("nexus_error_log.txt", "a") as f:
            f.write(f"{datetime.now().isoformat()}: {str(e)}\n")
    finally:
        nids.console.print("[green]Thank you for using Advanced Nexus NIDS![/green]")

if __name__ == "__main__":
    main()
