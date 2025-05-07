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

class AdvancedNexusNIDS:
    def __init__(self):
        self.console = Console()
        self.alerts = []
        self.malicious_traffic = []
        self.normal_traffic = []
        self.is_running = True
        self.animation_frames = ["⠋", "⠙", "⠹", "⠸", "⠼", "⠴", "⠦", "⠧", "⠇", "⠏"]
        self.frame_idx = 0
        self.start_time = datetime.now()

        # Initialize audio system
        try:
            if not pygame.mixer.get_init():
                pygame.mixer.init()
        except pygame.error as e:
            print(f"Error initializing audio system: {e}")
        
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
       
        # Network statistics
        self.bytes_received = 0
        self.bytes_sent = 0
        self.packets_analyzed = 0
        self.last_minute_packets = collections.deque(maxlen=60)
        self.unique_ips = set()
        self.protocol_stats = defaultdict(int)
       
        # Enhanced configuration
        self.scan_threshold = 5
        self.connection_threshold = 50
        self.threat_score_threshold = 7.0
        self.malicious_ports = {22, 23, 445, 3389, 5900}
        self.suspicious_patterns = {
            b'eval(', b'exec(', b'system(', b'cmd.exe', b'/bin/sh',
            b'SELECT', b'UNION', b'DROP TABLE', b'rm -rf', b'wget'
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
        """Generates traffic monitoring panels"""
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
           
        malicious_table = Table(show_header=True, header_style="bold red", box=box.ROUNDED)
        malicious_table.add_column("Time", style="cyan")
        malicious_table.add_column("Source", style="bright_white")
        malicious_table.add_column("Threat Score", style="bright_red")
       
        for traffic in self.malicious_traffic[-5:]:
            malicious_table.add_row(
                traffic['timestamp'].strftime("%H:%M:%S"),
                traffic['source_ip'],
                f"{traffic['threat_score']:.1f}"
            )
           
        return normal_table, malicious_table

    def generate_display(self):
        """Generates the main display layout"""
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
            Layout(name="malicious_traffic")
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

        normal_table, malicious_table = self.generate_traffic_panels()
       
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

    def is_malicious_packet(self, packet):
        """Checks if a packet is potentially malicious"""
        if not packet.haslayer(scapy.IP):
            return False
           
        if packet.haslayer(scapy.TCP):
            if packet[scapy.TCP].dport in self.malicious_ports:
                return True
               
        if packet.haslayer(scapy.Raw):
            payload = bytes(packet[scapy.Raw].load)
            if any(pattern in payload for pattern in self.suspicious_patterns):
                return True
               
        src_ip = packet[scapy.IP].src
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
        return 'Other'

    def update_tracking_data(self, packet):
        """Updates packet tracking data"""
        src_ip = packet[scapy.IP].src
        self.connection_count[src_ip] += 1
       
        if packet.haslayer(scapy.TCP):
            dst_port = packet[scapy.TCP].dport
            self.port_access_history[src_ip].append((datetime.now(), dst_port))

    def calculate_threat_score(self, src_ip, packet):
        """Calculates a threat score for a given packet"""
        score = 0.0
       
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
           
            # Cleanup old alerts
            self.alerts = [
                alert for alert in self.alerts
                if alert['timestamp'] > cutoff_time
            ]
           
            # Reset connection counts periodically
            self.connection_count.clear()
           
            time.sleep(60)

    def packet_callback(self, packet):
        """Callback function for packet processing"""
        if packet.haslayer(scapy.IP):
            self.update_network_stats(packet)
            src_ip = packet[scapy.IP].src
            dst_ip = packet[scapy.IP].dst
            timestamp = datetime.now()
           
            if self.is_malicious_packet(packet):
                threat_score = self.calculate_threat_score(src_ip, packet)
                self.malicious_traffic.append({
                    'timestamp': timestamp,
                    'source_ip': src_ip,
                    'dest_ip': dst_ip,
                    'protocol': self.get_protocol(packet),
                    'threat_score': threat_score
                })
                self.add_alert(f"🚨 Malicious traffic detected from {src_ip}", "HIGH")
                
                # Play alert sound for high threat scores
                if threat_score > self.threat_score_threshold:
                    self.play_alert()
            else:
                self.normal_traffic.append({
                    'timestamp': timestamp,
                    'source_ip': src_ip,
                    'dest_ip': dst_ip,
                    'protocol': self.get_protocol(packet)
                })

            self.update_tracking_data(packet)

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
                "normal_traffic_count": len(self.normal_traffic)
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
                    "threat_score": traffic["threat_score"]
                }
                for traffic in self.malicious_traffic
            ]
        }
        return report

    def save_report(self):
        """Saves the monitoring report to a file"""
        report = self.generate_report()
       
        self.console.clear()
        self.print_banner()
        save_report = input("\nWould you like to save the monitoring report? (y/n): ").lower().strip()
       
        if save_report == 'y':
            default_filename = f"nexus_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
            filename = input(f"\nEnter filename (default: {default_filename}): ").strip()
           
            if not filename:
                filename = default_filename
           
            if not filename.endswith('.json'):
                filename += '.json'
           
            try:
                with open(filename, 'w') as f:
                    json.dump(report, f, indent=4)
                print(f"\nReport successfully saved to {filename}")
            except Exception as e:
                print(f"\nError saving report: {str(e)}")
        else:
            print("\nReport not saved")

    def cleanup(self):
        """Performs cleanup operations before exit"""
        self.is_running = False
        pygame.mixer.quit()  # Clean up audio system
        self.save_report()
        print("\nShutting down Nexus Defense Shield...")
        time.sleep(1)

    def signal_handler(self, signum, frame):
        """Handles interrupt signals"""
        self.cleanup()
        sys.exit(0)

    def run(self):
        """Main execution method"""
        # Set up signal handler for graceful termination
        signal.signal(signal.SIGINT, self.signal_handler)
       
        self.console.clear()
        self.show_enhanced_startup_animation()
       
        # Start monitoring threads
        threading.Thread(target=self.cleanup_old_data, daemon=True).start()
        threading.Thread(target=self.start_capture, daemon=True).start()
       
        # Main display loop
        try:
            with Live(self.generate_display(), refresh_per_second=4, screen=True) as live:
                while self.is_running:
                    live.update(self.generate_display())
                    time.sleep(0.25)
        except KeyboardInterrupt:
            self.cleanup()
        except Exception as e:
            print(f"\nFatal error: {str(e)}")
            self.cleanup()
            sys.exit(1)

if __name__ == "__main__":
    if os.geteuid() != 0:
        print("This program must be run as root!")
        sys.exit(1)
   
    try:
        ids = AdvancedNexusNIDS()
        ids.run()
    except Exception as e:
        print(f"Fatal error: {str(e)}")
        sys.exit(1)
