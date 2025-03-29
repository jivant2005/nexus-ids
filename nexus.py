import pandas as pd
import numpy as np
import random
import time
import uuid
import datetime
import os
import curses
import threading
import sys
import json
from collections import deque
from ml_engine import MLDetectionEngine, NetworkPacket, FEATURE_COLUMNS

# Set up terminal colors
class Colors:
    HEADER = '\033[95m'
    BLUE = '\033[94m'
    CYAN = '\033[96m'
    GREEN = '\033[92m'
    YELLOW = '\033[93m'
    RED = '\033[91m'
    ENDC = '\033[0m'
    BOLD = '\033[1m'
    UNDERLINE = '\033[4m'
    BLINK = '\033[5m'
    BG_BLACK = '\033[40m'
    BG_RED = '\033[41m'
    BG_GREEN = '\033[42m'
    BG_YELLOW = '\033[43m'
    BG_BLUE = '\033[44m'
    BG_MAGENTA = '\033[45m'
    BG_CYAN = '\033[46m'
    BG_WHITE = '\033[47m'

class Alert:
    def __init__(self, packet, confidence):
        self.id = str(uuid.uuid4())[:8]
        self.timestamp = datetime.datetime.now()
        self.packet = packet
        self.confidence = confidence
        
        # Determine severity based on confidence
        if confidence > 0.8:
            self.severity = "HIGH"
            self.color = Colors.BG_RED + Colors.BOLD
        elif confidence > 0.6:
            self.severity = "MEDIUM"
            self.color = Colors.BG_YELLOW + Colors.BOLD
        else:
            self.severity = "LOW"
            self.color = Colors.BG_BLUE + Colors.BOLD
            
    def __str__(self):
        return f"{self.color}[{self.severity}]{Colors.ENDC} {self.timestamp.strftime('%H:%M:%S.%f')[:-3]} {self.packet.src_ip} → {self.packet.dst_ip} ({self.confidence:.2f})"
    
    def to_dict(self):
        """Convert alert to dictionary for logging"""
        return {
            "id": self.id,
            "timestamp": self.timestamp.strftime('%Y-%m-%d %H:%M:%S.%f'),
            "src_ip": self.packet.src_ip,
            "dst_ip": self.packet.dst_ip,
            "protocol": self.packet.protocol,
            "confidence": self.confidence,
            "severity": self.severity
        }

class Logger:
    def __init__(self, enabled=True):
        self.enabled = enabled
        self.log_file = f"nids_log_{datetime.datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
        self.logs = []
        
    def log_packet(self, packet, is_malicious, confidence=0.0):
        """Log packet information"""
        if not self.enabled:
            return
            
        log_entry = {
            "timestamp": packet.timestamp.strftime('%Y-%m-%d %H:%M:%S.%f'),
            "src_ip": packet.src_ip,
            "dst_ip": packet.dst_ip,
            "protocol": packet.protocol,
            "is_malicious": is_malicious,
            "confidence": confidence if is_malicious else 0.0
        }
        
        self.logs.append(log_entry)
        
    def save_logs(self):
        """Save logs to file"""
        if not self.enabled or not self.logs:
            return False
            
        try:
            with open(self.log_file, 'w') as f:
                json.dump(self.logs, f, indent=2)
            return True
        except Exception as e:
            print(f"Error saving logs: {e}")
            return False

class NIDSTerminalUI:
    def __init__(self, stdscr):
        self.stdscr = stdscr
        self.running = True
        self.normal_packets = deque(maxlen=40)  # Store last 40 normal packets
        self.malicious_packets = deque(maxlen=40)  # Store last 40 malicious packets
        self.alerts = deque(maxlen=10)  # Store last 10 alerts for display
        self.logger = Logger()
        self.stats = {
            'total_packets': 0,
            'normal_packets': 0,
            'malicious_packets': 0,
            'detection_rate': 0,
            'tcp_packets': 0,
            'udp_packets': 0,
            'icmp_packets': 0,
            'high_severity': 0,
            'medium_severity': 0,
            'low_severity': 0,
            'start_time': datetime.datetime.now(),
            'last_alert_time': None
        }
        
        # Initialize curses
        curses.start_color()
        curses.use_default_colors()
        curses.init_pair(1, curses.COLOR_GREEN, -1)    # Normal
        curses.init_pair(2, curses.COLOR_RED, -1)      # Malicious
        curses.init_pair(3, curses.COLOR_YELLOW, -1)   # Headers/Status
        curses.init_pair(4, curses.COLOR_CYAN, -1)     # Info
        curses.init_pair(5, curses.COLOR_MAGENTA, -1)  # Highlights
        curses.init_pair(6, curses.COLOR_WHITE, curses.COLOR_RED)     # High Alerts
        curses.init_pair(7, curses.COLOR_BLACK, curses.COLOR_GREEN)   # Success
        curses.init_pair(8, curses.COLOR_BLACK, curses.COLOR_YELLOW)  # Medium Alerts
        curses.init_pair(9, curses.COLOR_WHITE, curses.COLOR_BLUE)    # Low Alerts
        curses.init_pair(10, curses.COLOR_BLACK, curses.COLOR_CYAN)   # Info Highlights
        
        # Get terminal size
        self.update_dimensions()
        
        # Hide cursor
        curses.curs_set(0)
        
    def update_dimensions(self):
        """Update dimensions based on current terminal size"""
        self.rows, self.cols = self.stdscr.getmaxyx()
        
    def draw_border(self):
        """Draw the main interface border and headers"""
        # Clear the screen
        self.stdscr.clear()
        
        # Draw main border with double lines
        self.stdscr.addstr(0, 0, "╔" + "═" * (self.cols - 2) + "╗")
        for i in range(1, self.rows - 1):
            self.stdscr.addstr(i, 0, "║")
            self.stdscr.addstr(i, self.cols - 1, "║")
        self.stdscr.addstr(self.rows - 1, 0, "╚" + "═" * (self.cols - 2) + "╝")
        
        # Draw title
        title = "[ NEXUS INTRUSION DETECTION SYSTEM ]"
        self.stdscr.addstr(0, (self.cols - len(title)) // 2, title, curses.color_pair(3) | curses.A_BOLD)
        
        # Draw runtime info
        runtime = datetime.datetime.now() - self.stats['start_time']
        runtime_str = f"Runtime: {runtime.seconds // 3600:02d}:{(runtime.seconds % 3600) // 60:02d}:{runtime.seconds % 60:02d}"
        self.stdscr.addstr(1, self.cols - len(runtime_str) - 2, runtime_str, curses.color_pair(4))
        
        # Draw traffic headers
        normal_header = "[ LEGITIMATE TRAFFIC ]"
        malicious_header = "[ MALICIOUS TRAFFIC ]"
        col_width = self.cols // 2 - 4
        
        self.stdscr.addstr(2, col_width // 2, normal_header, curses.color_pair(7) | curses.A_BOLD)
        self.stdscr.addstr(2, self.cols // 2 + col_width // 2, malicious_header, curses.color_pair(6) | curses.A_BOLD)
        
        # Draw column divider with fancy pattern
        div_middle = self.rows - 13
        for i in range(3, self.rows - 12):
            char = "╟" if i == div_middle else "║"
            self.stdscr.addstr(i, self.cols // 2 - 1, char)
            
        # Draw horizontal dividers
        self.stdscr.addstr(self.rows - 12, 1, "╠" + "═" * (self.cols - 4) + "╣")
        
        # Draw alerts section header
        alerts_header = "[ REAL-TIME ALERTS ]"
        self.stdscr.addstr(self.rows - 11, (self.cols - len(alerts_header)) // 2, alerts_header, curses.color_pair(6) | curses.A_BOLD)
        
        # Draw status bar
        status_bar = " PRESS 'Q' TO QUIT | 'P' TO PAUSE/RESUME | 'R' TO RESET STATS | 'L' TO TOGGLE LOGGING "
        self.stdscr.addstr(self.rows - 1, (self.cols - len(status_bar)) // 2, status_bar, curses.color_pair(3))
        
    def draw_stats(self):
        """Draw statistics dashboard"""
        # Update detection rate
        if self.stats['total_packets'] > 0:
            self.stats['detection_rate'] = (self.stats['malicious_packets'] / self.stats['total_packets']) * 100
        
        # Stats box top
        self.stdscr.addstr(3, 2, "┌" + "─" * 24 + "┐")
        self.stdscr.addstr(3, self.cols - 28, "┌" + "─" * 24 + "┐")
        
        # Traffic stats
        self.stdscr.addstr(4, 2, "│ TRAFFIC STATISTICS    │", curses.color_pair(3) | curses.A_BOLD)
        self.stdscr.addstr(4, self.cols - 28, "│ PROTOCOL BREAKDOWN    │", curses.color_pair(3) | curses.A_BOLD)
        
        self.stdscr.addstr(5, 2, "├" + "─" * 24 + "┤")
        self.stdscr.addstr(5, self.cols - 28, "├" + "─" * 24 + "┤")
        
        traffic_stats = [
            f"│ Total Packets: {self.stats['total_packets']:8d} │",
            f"│ Legitimate:   {self.stats['normal_packets']:8d} │",
            f"│ Malicious:    {self.stats['malicious_packets']:8d} │",
            f"│ Detection %:   {self.stats['detection_rate']:7.1f}% │"
        ]
        
        protocol_stats = [
            f"│ TCP:          {self.stats['tcp_packets']:8d} │",
            f"│ UDP:          {self.stats['udp_packets']:8d} │",
            f"│ ICMP:         {self.stats['icmp_packets']:8d} │",
            f"│ Logging:    {'ON ' if self.logger.enabled else 'OFF'} {' ' * 6} │"
        ]
        
        for i, stat in enumerate(traffic_stats):
            self.stdscr.addstr(6 + i, 2, stat, curses.color_pair(4))
            
        for i, stat in enumerate(protocol_stats):
            self.stdscr.addstr(6 + i, self.cols - 28, stat, curses.color_pair(4))
            
        # Stats box bottom
        self.stdscr.addstr(10, 2, "└" + "─" * 24 + "┘")
        self.stdscr.addstr(10, self.cols - 28, "└" + "─" * 24 + "┘")
        
        # Security stats box
        self.stdscr.addstr(12, 2, "┌" + "─" * 24 + "┐")
        self.stdscr.addstr(13, 2, "│ SECURITY ALERTS       │", curses.color_pair(3) | curses.A_BOLD)
        self.stdscr.addstr(14, 2, "├" + "─" * 24 + "┤")
        
        security_stats = [
            f"│ High Severity: {self.stats['high_severity']:7d} │",
            f"│ Medium:       {self.stats['medium_severity']:7d} │",
            f"│ Low:          {self.stats['low_severity']:7d} │"
        ]
        
        for i, stat in enumerate(security_stats):
            color = curses.color_pair(6 if i == 0 else (8 if i == 1 else 9))
            self.stdscr.addstr(15 + i, 2, stat, color)
            
        self.stdscr.addstr(18, 2, "└" + "─" * 24 + "┘")
            
    def draw_packets(self):
        """Draw the packet lists in each column"""
        col_width = self.cols // 2 - 4
        
        # Draw column headers
        self.stdscr.addstr(3, (self.cols // 4) - 12, "SOURCE", curses.color_pair(5))
        self.stdscr.addstr(3, (self.cols // 4) + 5, "DESTINATION", curses.color_pair(5))
        self.stdscr.addstr(3, (self.cols // 4) + 20, "PROTO", curses.color_pair(5))
        
        self.stdscr.addstr(3, (self.cols * 3 // 4) - 12, "SOURCE", curses.color_pair(5))
        self.stdscr.addstr(3, (self.cols * 3 // 4) + 5, "DESTINATION", curses.color_pair(5))
        self.stdscr.addstr(3, (self.cols * 3 // 4) + 20, "PROTO", curses.color_pair(5))
        
        # Draw normal packets
        for i, packet in enumerate(self.normal_packets):
            if i >= self.rows - 17:  # Limit based on available space
                break
                
            time_str = packet.timestamp.strftime('%H:%M:%S')
            proto_color = {
                'tcp': curses.color_pair(1),
                'udp': curses.color_pair(4),
                'icmp': curses.color_pair(3)
            }.get(packet.protocol.lower(), curses.color_pair(1))
            
            # Draw with appropriate spacing and color
            self.stdscr.addstr(i + 4, 4, time_str, curses.color_pair(1))
            self.stdscr.addstr(i + 4, 14, packet.src_ip, curses.color_pair(1))
            self.stdscr.addstr(i + 4, 30, packet.dst_ip, curses.color_pair(1))
            self.stdscr.addstr(i + 4, 46, packet.protocol.upper(), proto_color)
                
        # Draw malicious packets with flashing effect for newest entries
        for i, packet in enumerate(self.malicious_packets):
            if i >= self.rows - 17:  # Limit based on available space
                break
                
            time_str = packet.timestamp.strftime('%H:%M:%S')
            
            # Determine color based on age of packet
            if i == 0 and not curses.has_colors():
                # Blink effect for newest packet (terminal dependent)
                attr = curses.A_BOLD | curses.A_BLINK
            else:
                attr = curses.A_BOLD if i < 3 else 0
            
            # Draw with appropriate spacing and color
            self.stdscr.addstr(i + 4, self.cols // 2 + 4, time_str, curses.color_pair(2) | attr)
            self.stdscr.addstr(i + 4, self.cols // 2 + 14, packet.src_ip, curses.color_pair(2) | attr)
            self.stdscr.addstr(i + 4, self.cols // 2 + 30, packet.dst_ip, curses.color_pair(2) | attr)
            self.stdscr.addstr(i + 4, self.cols // 2 + 46, packet.protocol.upper(), curses.color_pair(2) | attr)
            
    def draw_alerts(self):
        """Draw real-time alerts at the bottom of the screen"""
        available_rows = self.rows - 13  # Space for alerts section
        
        # Draw alerts
        for i, alert in enumerate(self.alerts):
            if i >= available_rows:
                break
                
            # Determine color based on severity
            if alert.severity == "HIGH":
                color = curses.color_pair(6)
            elif alert.severity == "MEDIUM":
                color = curses.color_pair(8)
            else:
                color = curses.color_pair(9)
                
            # Format alert text
            alert_time = alert.timestamp.strftime('%H:%M:%S')
            alert_text = f"[{alert_time}] [{alert.severity}] {alert.packet.src_ip} → {alert.packet.dst_ip} ({alert.confidence:.2f}) - {alert.packet.protocol.upper()}"
            
            # Truncate if needed
            if len(alert_text) > self.cols - 4:
                alert_text = alert_text[:self.cols - 7] + "..."
                
            # Draw alert
            self.stdscr.addstr(self.rows - 10 + i, 2, alert_text, color | curses.A_BOLD)
    
    # In the NIDSTerminalUI class, modify the update method:
	# In the NIDSTerminalUI class, modify the update method:
def update(self):
    """Update the terminal UI more efficiently"""
    try:
        # Only redraw if the terminal size has changed
        new_rows, new_cols = self.stdscr.getmaxyx()
        full_redraw = (new_rows != self.rows or new_cols != self.cols)
        
        if full_redraw:
            self.update_dimensions()
            self.draw_border()
        
        # Always update dynamic content
        self.draw_stats()
        self.draw_packets()
        self.draw_alerts()
        self.stdscr.refresh()
    except curses.error:
        # Handle curses errors (usually from terminal resizing)
        pass
            
    def add_normal_packet(self, packet):
        """Add a normal packet to the display"""
        self.normal_packets.appendleft(packet)
        self.stats['normal_packets'] += 1
        self.stats['total_packets'] += 1
        
        # Update protocol stats
        if packet.protocol.lower() == 'tcp':
            self.stats['tcp_packets'] += 1
        elif packet.protocol.lower() == 'udp':
            self.stats['udp_packets'] += 1
        elif packet.protocol.lower() == 'icmp':
            self.stats['icmp_packets'] += 1
            
        # Log packet
        self.logger.log_packet(packet, False)
            
    def add_malicious_packet(self, packet, confidence):
        """Add a malicious packet to the display and create alert"""
        self.malicious_packets.appendleft(packet)
        self.stats['malicious_packets'] += 1
        self.stats['total_packets'] += 1
        
        # Update protocol stats
        if packet.protocol.lower() == 'tcp':
            self.stats['tcp_packets'] += 1
        elif packet.protocol.lower() == 'udp':
            self.stats['udp_packets'] += 1
        elif packet.protocol.lower() == 'icmp':
            self.stats['icmp_packets'] += 1
            
        # Create and add alert
        alert = Alert(packet, confidence)
        self.alerts.appendleft(alert)
        self.stats['last_alert_time'] = datetime.datetime.now()
        
        # Update severity stats
        if alert.severity == "HIGH":
            self.stats['high_severity'] += 1
        elif alert.severity == "MEDIUM":
            self.stats['medium_severity'] += 1
        else:
            self.stats['low_severity'] += 1
            
        # Log packet
        self.logger.log_packet(packet, True, confidence)
        
    def toggle_logging(self):
        """Toggle logging on/off"""
        self.logger.enabled = not self.logger.enabled
        return self.logger.enabled
            
class NIDS:
    def __init__(self):
        self.ml_engine = MLDetectionEngine()
        self.paused = False
        self.traffic_generator = None
        
class NIDS:
    def __init__(self):
        self.ml_engine = MLDetectionEngine()
        self.paused = False
        self.traffic_generator = None
        
    def generate_traffic(self, ui):
        """Generate network traffic and analyze it"""
        update_counter = 0
        batch_size = 10  # Process packets in batches
        
        while ui.running:
            if not self.paused:
                # Generate multiple packets before updating UI
                num_packets = random.randint(1, 5)
                for _ in range(num_packets):
                    # Create a packet
                    packet = NetworkPacket()
                    
                    # Analyze with ML engine
                    is_attack, confidence = self.ml_engine.analyze_packet(packet)
                    
                    # Add to appropriate list
                    if is_attack:
                        ui.add_malicious_packet(packet, confidence)
                    else:
                        ui.add_normal_packet(packet)
                    
                    # Only update UI periodically
                    update_counter += 1
                    if update_counter >= batch_size:
                        ui.update()
                        update_counter = 0
            
            # Sleep to control traffic rate
            time.sleep(0.5)  # Increased from 0.2
    def run(self, stdscr):
        """Main NIDS function"""
        # Initialize the UI
        ui = NIDSTerminalUI(stdscr)
        
        # Start traffic generation in a separate thread
        self.traffic_generator = threading.Thread(target=self.generate_traffic, args=(ui,))
        self.traffic_generator.daemon = True
        self.traffic_generator.start()
        
        # Main loop
        while ui.running:
            try:
                # Get keyboard input (non-blocking)
                key = ui.stdscr.getch()
                
                # Process keys
                if key == ord('q') or key == ord('Q'):
                    ui.running = False
                elif key == ord('p') or key == ord('P'):
                    self.paused = not self.paused
                elif key == ord('r') or key == ord('R'):
                    # Reset stats
                    ui.stats = {k: 0 for k in ui.stats}
                    ui.stats['start_time'] = datetime.datetime.now()
                elif key == ord('l') or key == ord('L'):
                    # Toggle logging
                    ui.toggle_logging()
                
                # Update UI
                ui.update()
                
                # A brief pause to reduce CPU usage
                time.sleep(0.05)
                
            except KeyboardInterrupt:
                break
        
        # Ask about saving logs if logging was enabled
        curses.endwin()
        if ui.logger.enabled and ui.logger.logs:
            save_logs = input(f"{Colors.YELLOW}Do you want to save logs to file? (y/n): {Colors.ENDC}")
            if save_logs.lower() == 'y':
                if ui.logger.save_logs():
                    print(f"{Colors.GREEN}[+] Logs saved to {ui.logger.log_file}{Colors.ENDC}")
                else:
                    print(f"{Colors.RED}[!] Failed to save logs{Colors.ENDC}")

def display_startup_animation():
    """Display an animated startup sequence"""
    os.system('cls' if os.name == 'nt' else 'clear')
    
    # ASCII art for animation frames
    frames = [
        [
            f"{Colors.BLUE}╔════════════════════════════════════════════════════════════════╗{Colors.ENDC}",
            f"{Colors.BLUE}║                                                                ║{Colors.ENDC}",
            f"{Colors.BLUE}║                                                                ║{Colors.ENDC}",
            f"{Colors.BLUE}║                                                                ║{Colors.ENDC}",
            f"{Colors.BLUE}║                                                                ║{Colors.ENDC}",
            f"{Colors.BLUE}║                                                                ║{Colors.ENDC}",
            f"{Colors.BLUE}║                                                                ║{Colors.ENDC}",
            f"{Colors.BLUE}║                                                                ║{Colors.ENDC}",
            f"{Colors.BLUE}║                                                                ║{Colors.ENDC}",
            f"{Colors.BLUE}╚════════════════════════════════════════════════════════════════╝{Colors.ENDC}"
        ],
        [
            f"{Colors.BLUE}╔════════════════════════════════════════════════════════════════╗{Colors.ENDC}",
            f"{Colors.BLUE}║                                                                ║{Colors.ENDC}",
            f"{Colors.BLUE}║  {Colors.RED}██{Colors.BLUE}                                                          ║{Colors.ENDC}",
            f"{Colors.BLUE}║  {Colors.RED}██{Colors.BLUE}                                                          ║{Colors.ENDC}",
            f"{Colors.BLUE}║  {Colors.RED}██{Colors.BLUE}                                                          ║{Colors.ENDC}",
            f"{Colors.BLUE}║  {Colors.RED}██{Colors.BLUE}                                                          ║{Colors.ENDC}",
            f"{Colors.BLUE}║  {Colors.RED}███████{Colors.BLUE}                                                     ║{Colors.ENDC}",
            f"{Colors.BLUE}║                                                                ║{Colors.ENDC}",
            f"{Colors.BLUE}║                                                                ║{Colors.ENDC}",
            f"{Colors.BLUE}╚════════════════════════════════════════════════════════════════╝{Colors.ENDC}"
        ],
        [
            f"{Colors.BLUE}╔════════════════════════════════════════════════════════════════╗{Colors.ENDC}",
            f"{Colors.BLUE}║                                                                ║{Colors.ENDC}",
            f"{Colors.BLUE}║  {Colors.RED}███╗   ██╗{Colors.BLUE}                                                  ║{Colors.ENDC}",
            f"{Colors.BLUE}║  {Colors.RED}████╗  ██║{Colors.BLUE}                                                  ║{Colors.ENDC}",
            f"{Colors.BLUE}║  {Colors.RED}██╔██╗ ██║{Colors.BLUE}                                                  ║{Colors.ENDC}",
            f"{Colors.BLUE}║  {Colors.RED}██║╚██╗██║{Colors.BLUE}                                                  ║{Colors.ENDC}",
            f"{Colors.BLUE}║  {Colors.RED}██║ ╚████║{Colors.BLUE}                                                  ║{Colors.ENDC}",
            f"{Colors.BLUE}║  {Colors.RED}╚═╝  ╚═══╝{Colors.BLUE}                                                  ║{Colors.ENDC}",
            f"{Colors.BLUE}║                                                                ║{Colors.ENDC}",
            f"{Colors.BLUE}╚════════════════════════════════════════════════════════════════╝{Colors.ENDC}"
        ],
        [
            f"{Colors.BLUE}╔════════════════════════════════════════════════════════════════╗{Colors.ENDC}",
            f"{Colors.BLUE}║                                                                ║{Colors.ENDC}",
            f"{Colors.BLUE}║  {Colors.RED}███╗   ██╗███████╗{Colors.BLUE}                                          ║{Colors.ENDC}",
            f"{Colors.BLUE}║  {Colors.RED}████╗  ██║██╔════╝{Colors.BLUE}                                          ║{Colors.ENDC}",
            f"{Colors.BLUE}║  {Colors.RED}██╔██╗ ██║█████╗{Colors.BLUE}                                            ║{Colors.ENDC}",
            f"{Colors.BLUE}║  {Colors.RED}██║╚██╗██║██╔══╝{Colors.BLUE}                                            ║{Colors.ENDC}",
            f"{Colors.BLUE}║  {Colors.RED}██║ ╚████║███████╗{Colors.BLUE}                                          ║{Colors.ENDC}",
            f"{Colors.BLUE}║  {Colors.RED}╚═╝  ╚═══╝╚══════╝{Colors.BLUE}                                          ║{Colors.ENDC}",
            f"{Colors.BLUE}║                                                                ║{Colors.ENDC}",
            f"{Colors.BLUE}╚════════════════════════════════════════════════════════════════╝{Colors.ENDC}"
        ],
        [
            f"{Colors.BLUE}╔════════════════════════════════════════════════════════════════╗{Colors.ENDC}",
            f"{Colors.BLUE}║                                                                ║{Colors.ENDC}",
            f"{Colors.BLUE}║  {Colors.RED}███╗   ██╗███████╗██╗  ██╗{Colors.BLUE}                                  ║{Colors.ENDC}",
            f"{Colors.BLUE}║  {Colors.RED}████╗  ██║██╔════╝╚██╗██╔╝{Colors.BLUE}                                  ║{Colors.ENDC}",
            f"{Colors.BLUE}║  {Colors.RED}██╔██╗ ██║█████╗   ╚███╔╝{Colors.BLUE}                                   ║{Colors.ENDC}",
            f"{Colors.BLUE}║  {Colors.RED}██║╚██╗██║██╔══╝   ██╔██╗{Colors.BLUE}                                   ║{Colors.ENDC}",
            f"{Colors.BLUE}║  {Colors.RED}██║ ╚████║███████╗██╔╝ ██╗{Colors.BLUE}                                  ║{Colors.ENDC}",
            f"{Colors.BLUE}║  {Colors.RED}╚═╝  ╚═══╝╚══════╝╚═╝  ╚═╝{Colors.BLUE}                                  ║{Colors.ENDC}",
f"{Colors.BLUE}║                                                                ║{Colors.ENDC}",
            f"{Colors.BLUE}╚════════════════════════════════════════════════════════════════╝{Colors.ENDC}"
        ],
        [
            f"{Colors.BLUE}╔════════════════════════════════════════════════════════════════╗{Colors.ENDC}",
            f"{Colors.BLUE}║                                                                ║{Colors.ENDC}",
            f"{Colors.BLUE}║  {Colors.RED}███╗   ██╗███████╗██╗  ██╗██╗   ██╗███████╗{Colors.BLUE}                ║{Colors.ENDC}",
            f"{Colors.BLUE}║  {Colors.RED}████╗  ██║██╔════╝╚██╗██╔╝██║   ██║██╔════╝{Colors.BLUE}                ║{Colors.ENDC}",
            f"{Colors.BLUE}║  {Colors.RED}██╔██╗ ██║█████╗   ╚███╔╝ ██║   ██║███████╗{Colors.BLUE}                ║{Colors.ENDC}",
            f"{Colors.BLUE}║  {Colors.RED}██║╚██╗██║██╔══╝   ██╔██╗ ██║   ██║╚════██║{Colors.BLUE}                ║{Colors.ENDC}",
            f"{Colors.BLUE}║  {Colors.RED}██║ ╚████║███████╗██╔╝ ██╗╚██████╔╝███████║{Colors.BLUE}                ║{Colors.ENDC}",
            f"{Colors.BLUE}║  {Colors.RED}╚═╝  ╚═══╝╚══════╝╚═╝  ╚═╝ ╚═════╝ ╚══════╝{Colors.BLUE}                ║{Colors.ENDC}",
            f"{Colors.BLUE}║                                                                ║{Colors.ENDC}",
            f"{Colors.BLUE}╚════════════════════════════════════════════════════════════════╝{Colors.ENDC}"
        ]
    ]
    
    # Loading messages
    loading_messages = [
        f"{Colors.GREEN}[+] Initializing system components...{Colors.ENDC}",
        f"{Colors.GREEN}[+] Loading machine learning models...{Colors.ENDC}",
        f"{Colors.GREEN}[+] Configuring network interfaces...{Colors.ENDC}",
        f"{Colors.GREEN}[+] Establishing detection parameters...{Colors.ENDC}",
        f"{Colors.GREEN}[+] Calibrating threat detection algorithms...{Colors.ENDC}",
        f"{Colors.YELLOW}[*] Starting Nexus IDS engine...{Colors.ENDC}"
    ]
    
    # Display each frame with loading messages
    for i, frame in enumerate(frames):
        os.system('cls' if os.name == 'nt' else 'clear')
        for line in frame:
            print(line)
        
        # Add loading message below the frame
        if i < len(loading_messages):
            print("\n" + loading_messages[i])
        
        # Add progressing dots animation
        dots = "." * (i + 1)
        print(f"\n{Colors.CYAN}Loading{dots.ljust(6)}{Colors.ENDC}")
        
        # Add progress bar
        bar_length = 50
        progress = int((i + 1) / len(frames) * bar_length)
        bar = "█" * progress + "░" * (bar_length - progress)
        percentage = int((i + 1) / len(frames) * 100)
        print(f"{Colors.CYAN}[{bar}] {percentage}%{Colors.ENDC}")
        
        # Show advanced system information
        if i > 2:
            print(f"\n{Colors.YELLOW}System Information:{Colors.ENDC}")
            print(f"{Colors.CYAN}► ML Model Version: 4.2.1{Colors.ENDC}")
            print(f"{Colors.CYAN}► Signature Database: {datetime.datetime.now().strftime('%Y-%m-%d')}{Colors.ENDC}")
            print(f"{Colors.CYAN}► Detection Engine: Advanced Heuristic v3{Colors.ENDC}")
            
        time.sleep(0.6)  # Slow down animation for better effect
    
    # Final message before starting
    os.system('cls' if os.name == 'nt' else 'clear')
    
    # Full logo
    logo = f"""
{Colors.BLUE}╔═════════════════════════════════════════════════════════════════╗
║                                                                 ║
║  {Colors.RED}{Colors.BOLD}███╗   ██╗███████╗██╗  ██╗██╗   ██╗███████╗{Colors.BLUE}                ║
║  {Colors.RED}{Colors.BOLD}████╗  ██║██╔════╝╚██╗██╔╝██║   ██║██╔════╝{Colors.BLUE}                ║
║  {Colors.RED}{Colors.BOLD}██╔██╗ ██║█████╗   ╚███╔╝ ██║   ██║███████╗{Colors.BLUE}                ║
║  {Colors.RED}{Colors.BOLD}██║╚██╗██║██╔══╝   ██╔██╗ ██║   ██║╚════██║{Colors.BLUE}                ║
║  {Colors.RED}{Colors.BOLD}██║ ╚████║███████╗██╔╝ ██╗╚██████╔╝███████║{Colors.BLUE}                ║
║  {Colors.RED}{Colors.BOLD}╚═╝  ╚═══╝╚══════╝╚═╝  ╚═╝ ╚═════╝ ╚══════╝{Colors.BLUE}                ║
║                                                                 ║
║     {Colors.YELLOW}Network Intrusion Detection System with ML{Colors.BLUE}                ║
║     {Colors.CYAN}(c) 2025 - Advanced Security Tools{Colors.BLUE}                         ║
║                                                                 ║
╚═════════════════════════════════════════════════════════════════╝{Colors.ENDC}
"""
    print(logo)
    
    # Simulate system initialization messages with gradual progress
    startup_messages = [
        "Initializing machine learning engine...",
        "Loading network packet analyzers...",
        "Setting up real-time monitoring...",
        "Calibrating detection thresholds...",
        "Establishing logging services...",
        "Configuring user interface..."
    ]
    
    for msg in startup_messages:
        sys.stdout.write(f"{Colors.GREEN}[+] {msg}{Colors.ENDC}")
        sys.stdout.flush()
        
        # Simulate variable processing time
        delay = 0.1
        for _ in range(3):
            time.sleep(delay)
            sys.stdout.write(".")
            sys.stdout.flush()
            delay += 0.05
            
        print(" Done!")
        time.sleep(0.2)
        
    print(f"\n{Colors.YELLOW}[*] System initialized. Starting monitoring interface...{Colors.ENDC}")
    time.sleep(1.5)

def main():
    """Main entry point"""
    # Display startup animation
    display_startup_animation()
    
    # Start NIDS with curses
    nids = NIDS()
    curses.wrapper(nids.run)
    
    # Shutdown message
    print(f"\n{Colors.GREEN}[+] Nexus IDS shutdown complete.{Colors.ENDC}")
    print(f"{Colors.YELLOW}Thank you for using our security monitoring tool!{Colors.ENDC}")

if __name__ == "__main__":
    main()
