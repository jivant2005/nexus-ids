import pandas as pd
import numpy as np
import joblib
import random
import time
import uuid
import datetime
import os
import curses
import threading
from sklearn.ensemble import RandomForestClassifier
from collections import deque

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

# Sample feature columns that our NIDS will use
FEATURE_COLUMNS = [
    'duration', 'protocol_type', 'service', 'flag', 'src_bytes', 'dst_bytes',
    'land', 'wrong_fragment', 'urgent', 'hot', 'num_failed_logins',
    'logged_in', 'num_compromised', 'root_shell', 'su_attempted', 'num_root',
    'num_file_creations', 'num_shells', 'num_access_files', 'num_outbound_cmds',
    'is_host_login', 'is_guest_login', 'count', 'srv_count', 'serror_rate',
    'srv_serror_rate', 'rerror_rate', 'srv_rerror_rate', 'same_srv_rate',
    'diff_srv_rate', 'srv_diff_host_rate', 'dst_host_count', 'dst_host_srv_count',
    'dst_host_same_srv_rate', 'dst_host_diff_srv_rate', 'dst_host_same_src_port_rate',
    'dst_host_srv_diff_host_rate', 'dst_host_serror_rate', 'dst_host_srv_serror_rate',
    'dst_host_rerror_rate', 'dst_host_srv_rerror_rate'
]

class NetworkPacket:
    def __init__(self, src_ip=None, dst_ip=None, protocol=None):
        self.id = str(uuid.uuid4())[:8]
        self.timestamp = datetime.datetime.now()
        self.src_ip = src_ip or f"192.168.1.{random.randint(1, 254)}"
        self.dst_ip = dst_ip or f"10.0.0.{random.randint(1, 254)}"
        self.protocol = protocol or random.choice(['tcp', 'udp', 'icmp'])
        self.service = random.choice(['http', 'ftp', 'ssh', 'dns', 'smtp', 'telnet'])
        self.flag = random.choice(['SF', 'REJ', 'S0', 'RSTO'])
        self.src_bytes = random.randint(100, 10000)
        self.dst_bytes = random.randint(100, 5000)
        self.is_attack = random.random() < 0.2  # 20% chance of being an attack
        
        # Generate all required features for ML model
        self.features = self._generate_features()
        
    def _generate_features(self):
        """Generate all features needed for the ML model"""
        features = {
            'duration': random.randint(0, 58329),
            'protocol_type': self.protocol,
            'service': self.service,
            'flag': self.flag,
            'src_bytes': self.src_bytes,
            'dst_bytes': self.dst_bytes,
            'land': random.choice([0, 1]) if self.is_attack else 0,
            'wrong_fragment': random.choice([0, 1]) if self.is_attack else 0,
            'urgent': random.choice([0, 1]) if self.is_attack else 0,
            'hot': random.randint(0, 30) if self.is_attack else 0,
            'num_failed_logins': random.randint(0, 5) if self.is_attack else 0,
            'logged_in': random.choice([0, 1]),
            'num_compromised': random.randint(0, 7) if self.is_attack else 0,
            'root_shell': random.choice([0, 1]) if self.is_attack else 0,
            'su_attempted': random.choice([0, 1]) if self.is_attack else 0,
            'num_root': random.randint(0, 7) if self.is_attack else 0,
            'num_file_creations': random.randint(0, 9) if self.is_attack else 0,
            'num_shells': random.randint(0, 5) if self.is_attack else 0,
            'num_access_files': random.randint(0, 8) if self.is_attack else 0,
            'num_outbound_cmds': 0,  # Always 0 in the KDD dataset
            'is_host_login': random.choice([0, 1]) if self.is_attack else 0,
            'is_guest_login': random.choice([0, 1]),
            'count': random.randint(1, 511),
            'srv_count': random.randint(1, 511),
        }
        
        # Attack-related rate features
        if self.is_attack:
            features.update({
                'serror_rate': random.uniform(0.7, 1.0),
                'srv_serror_rate': random.uniform(0.7, 1.0),
                'rerror_rate': random.uniform(0.7, 1.0),
                'srv_rerror_rate': random.uniform(0.7, 1.0),
                'same_srv_rate': random.uniform(0, 0.3),
                'diff_srv_rate': random.uniform(0.7, 1.0),
                'srv_diff_host_rate': random.uniform(0.7, 1.0),
                'dst_host_count': random.randint(1, 255),
                'dst_host_srv_count': random.randint(1, 255),
                'dst_host_same_srv_rate': random.uniform(0, 0.3),
                'dst_host_diff_srv_rate': random.uniform(0.7, 1.0),
                'dst_host_same_src_port_rate': random.uniform(0, 0.3),
                'dst_host_srv_diff_host_rate': random.uniform(0.7, 1.0),
                'dst_host_serror_rate': random.uniform(0.7, 1.0),
                'dst_host_srv_serror_rate': random.uniform(0.7, 1.0),
                'dst_host_rerror_rate': random.uniform(0.7, 1.0),
                'dst_host_srv_rerror_rate': random.uniform(0.7, 1.0)
            })
        else:
            features.update({
                'serror_rate': random.uniform(0, 0.3),
                'srv_serror_rate': random.uniform(0, 0.3),
                'rerror_rate': random.uniform(0, 0.3),
                'srv_rerror_rate': random.uniform(0, 0.3),
                'same_srv_rate': random.uniform(0.7, 1.0),
                'diff_srv_rate': random.uniform(0, 0.3),
                'srv_diff_host_rate': random.uniform(0, 0.3),
                'dst_host_count': random.randint(1, 255),
                'dst_host_srv_count': random.randint(1, 255),
                'dst_host_same_srv_rate': random.uniform(0.7, 1.0),
                'dst_host_diff_srv_rate': random.uniform(0, 0.3),
                'dst_host_same_src_port_rate': random.uniform(0.7, 1.0),
                'dst_host_srv_diff_host_rate': random.uniform(0, 0.3),
                'dst_host_serror_rate': random.uniform(0, 0.3),
                'dst_host_srv_serror_rate': random.uniform(0, 0.3),
                'dst_host_rerror_rate': random.uniform(0, 0.3),
                'dst_host_srv_rerror_rate': random.uniform(0, 0.3)
            })
            
        return features
    
    def get_feature_vector(self):
        """Convert categorical features to numerical for ML model"""
        vector = {}
        for feature in FEATURE_COLUMNS:
            if feature == 'protocol_type':
                vector['protocol_type_tcp'] = 1 if self.features[feature] == 'tcp' else 0
                vector['protocol_type_udp'] = 1 if self.features[feature] == 'udp' else 0
                vector['protocol_type_icmp'] = 1 if self.features[feature] == 'icmp' else 0
            elif feature == 'service':
                for service in ['http', 'ftp', 'ssh', 'dns', 'smtp', 'telnet']:
                    vector[f'service_{service}'] = 1 if self.features[feature] == service else 0
            elif feature == 'flag':
                for flag in ['SF', 'REJ', 'S0', 'RSTO']:
                    vector[f'flag_{flag}'] = 1 if self.features[feature] == flag else 0
            else:
                vector[feature] = self.features[feature]
        return vector
        
    def __str__(self):
        return f"{self.timestamp.strftime('%H:%M:%S.%f')[:-3]} {self.src_ip} → {self.dst_ip} [{self.protocol.upper()}] {self.service}"

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

class MLDetectionEngine:
    def __init__(self):
        self.model = None
        self.initialize_model()
        
    def initialize_model(self):
        """Create and train a simple ML model for intrusion detection"""
        print(f"{Colors.YELLOW}[*] Initializing machine learning model...{Colors.ENDC}")
        
        # Generate sample training data
        X_train = []
        y_train = []
        
        # Generate 1000 sample packets for training
        for _ in range(1000):
            packet = NetworkPacket()
            feature_vector = packet.get_feature_vector()
            X_train.append(list(feature_vector.values()))
            y_train.append(1 if packet.is_attack else 0)
            
        # Train the model
        self.model = RandomForestClassifier(n_estimators=100, random_state=42)
        self.model.fit(X_train, y_train)
        print(f"{Colors.GREEN}[+] Model training complete!{Colors.ENDC}")
        
    def analyze_packet(self, packet):
        """Analyze a packet and determine if it's an attack"""
        # Extract features
        feature_vector = packet.get_feature_vector()
        X = [list(feature_vector.values())]
        
        # Make prediction
        is_attack = self.model.predict(X)[0]
        confidence = max(self.model.predict_proba(X)[0])
        
        return is_attack, confidence

class NIDSTerminalUI:
    def __init__(self, stdscr):
        self.stdscr = stdscr
        self.rows, self.cols = self.stdscr.getmaxyx()
        self.running = True
        self.normal_packets = deque(maxlen=30)  # Store last 30 normal packets
        self.malicious_packets = deque(maxlen=30)  # Store last 30 malicious packets
        self.stats = {
            'total_packets': 0,
            'normal_packets': 0,
            'malicious_packets': 0,
            'detection_rate': 0,
            'tcp_packets': 0,
            'udp_packets': 0,
            'icmp_packets': 0
        }
        
        # Initialize curses
        curses.start_color()
        curses.use_default_colors()
        curses.init_pair(1, curses.COLOR_GREEN, -1)  # Normal
        curses.init_pair(2, curses.COLOR_RED, -1)    # Malicious
        curses.init_pair(3, curses.COLOR_YELLOW, -1) # Headers/Status
        curses.init_pair(4, curses.COLOR_CYAN, -1)   # Info
        curses.init_pair(5, curses.COLOR_MAGENTA, -1) # Highlights
        curses.init_pair(6, curses.COLOR_WHITE, curses.COLOR_RED) # Alerts
        curses.init_pair(7, curses.COLOR_BLACK, curses.COLOR_GREEN) # Success
        
        # Hide cursor
        curses.curs_set(0)
        
    def draw_border(self):
        """Draw the main interface border and headers"""
        # Clear the screen
        self.stdscr.clear()
        
        # Draw main border
        self.stdscr.box()
        
        # Draw title
        title = "[ NETWORK INTRUSION DETECTION SYSTEM ]"
        self.stdscr.addstr(0, (self.cols - len(title)) // 2, title, curses.color_pair(3) | curses.A_BOLD)
        
        # Draw column headers
        normal_header = "[ NORMAL TRAFFIC ]"
        malicious_header = "[ MALICIOUS TRAFFIC ]"
        col_width = self.cols // 2 - 2
        
        self.stdscr.addstr(2, col_width // 2, normal_header, curses.color_pair(7) | curses.A_BOLD)
        self.stdscr.addstr(2, self.cols // 2 + col_width // 2, malicious_header, curses.color_pair(6) | curses.A_BOLD)
        
        # Draw column divider
        for i in range(3, self.rows - 6):
            self.stdscr.addch(i, self.cols // 2, '|')
            
        # Draw status bar
        status_bar = " PRESS 'Q' TO QUIT | 'P' TO PAUSE/RESUME | 'R' TO RESET STATS "
        self.stdscr.addstr(self.rows - 1, (self.cols - len(status_bar)) // 2, status_bar, curses.color_pair(3))
        
        # Draw horizontal line above stats
        for i in range(1, self.cols - 1):
            self.stdscr.addch(self.rows - 6, i, '-')
            
    def draw_stats(self):
        """Draw statistics at the bottom of the screen"""
        # Update detection rate
        if self.stats['total_packets'] > 0:
            self.stats['detection_rate'] = (self.stats['malicious_packets'] / self.stats['total_packets']) * 100
        
        # Format stats strings
        stats_strings = [
            f"TOTAL: {self.stats['total_packets']}",
            f"NORMAL: {self.stats['normal_packets']}",
            f"MALICIOUS: {self.stats['malicious_packets']}",
            f"DETECTION: {self.stats['detection_rate']:.1f}%",
            f"TCP: {self.stats['tcp_packets']}",
            f"UDP: {self.stats['udp_packets']}",
            f"ICMP: {self.stats['icmp_packets']}"
        ]
        
        # Calculate spacing
        spacing = self.cols // len(stats_strings)
        
        # Draw stats
        for i, stat in enumerate(stats_strings):
            x_pos = i * spacing + (spacing - len(stat)) // 2
            self.stdscr.addstr(self.rows - 4, x_pos, stat, curses.color_pair(4) | curses.A_BOLD)
            
    def draw_packets(self):
        """Draw the packet lists in each column"""
        col_width = self.cols // 2 - 2
        
        # Draw normal packets
        for i, packet in enumerate(self.normal_packets):
            if i < self.rows - 11:  # Leave space for stats and borders
                packet_str = f"{packet.timestamp.strftime('%H:%M:%S')} | {packet.src_ip} → {packet.dst_ip} | {packet.protocol.upper()}"
                if len(packet_str) > col_width:
                    packet_str = packet_str[:col_width - 3] + "..."
                self.stdscr.addstr(i + 4, 2, packet_str, curses.color_pair(1))
                
        # Draw malicious packets
        for i, packet in enumerate(self.malicious_packets):
            if i < self.rows - 11:  # Leave space for stats and borders
                packet_str = f"{packet.timestamp.strftime('%H:%M:%S')} | {packet.src_ip} → {packet.dst_ip} | {packet.protocol.upper()}"
                if len(packet_str) > col_width:
                    packet_str = packet_str[:col_width - 3] + "..."
                
                # Alternate colors for malicious packets for visual effect
                color = curses.color_pair(2) | (curses.A_BOLD if i % 2 == 0 else 0)
                self.stdscr.addstr(i + 4, self.cols // 2 + 2, packet_str, color)
                
    def update(self):
        """Update the terminal UI"""
        self.draw_border()
        self.draw_stats()
        self.draw_packets()
        self.stdscr.refresh()
        
    def add_normal_packet(self, packet):
        """Add a normal packet to the display"""
        self.normal_packets.appendleft(packet)
        self.stats['normal_packets'] += 1
        self.stats['total_packets'] += 1
        
        # Update protocol stats
        if packet.protocol == 'tcp':
            self.stats['tcp_packets'] += 1
        elif packet.protocol == 'udp':
            self.stats['udp_packets'] += 1
        elif packet.protocol == 'icmp':
            self.stats['icmp_packets'] += 1
            
    def add_malicious_packet(self, packet):
        """Add a malicious packet to the display"""
        self.malicious_packets.appendleft(packet)
        self.stats['malicious_packets'] += 1
        self.stats['total_packets'] += 1
        
        # Update protocol stats
        if packet.protocol == 'tcp':
            self.stats['tcp_packets'] += 1
        elif packet.protocol == 'udp':
            self.stats['udp_packets'] += 1
        elif packet.protocol == 'icmp':
            self.stats['icmp_packets'] += 1
            
class NIDS:
    def __init__(self):
        self.ml_engine = MLDetectionEngine()
        self.paused = False
        self.traffic_generator = None
        
    def generate_traffic(self, ui):
        """Generate network traffic and analyze it"""
        while ui.running:
            if not self.paused:
                # Generate 1-5 packets
                num_packets = random.randint(1, 5)
                for _ in range(num_packets):
                    # Create a packet
                    packet = NetworkPacket()
                    
                    # Analyze with ML engine
                    is_attack, confidence = self.ml_engine.analyze_packet(packet)
                    
                    # Add to appropriate list
                    if is_attack:
                        ui.add_malicious_packet(packet)
                    else:
                        ui.add_normal_packet(packet)
                    
                    # Update UI
                    ui.update()
            
            # Sleep to control traffic rate
            time.sleep(0.2)
            
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
                
                # Update UI
                ui.update()
                
                # A brief pause to reduce CPU usage
                time.sleep(0.05)
                
            except KeyboardInterrupt:
                break
                
        # Clean up
        curses.endwin()
            
def main():
    """Main entry point"""
    # Clear terminal
    os.system('cls' if os.name == 'nt' else 'clear')
    
    # Print banner
    banner = f"""
{Colors.BLUE}╔═════════════════════════════════════════════════════════════════╗
║                                                                 ║
║  {Colors.RED}{Colors.BOLD}███╗   ██╗██╗██████╗ ███████╗{Colors.BLUE}                              ║
║  {Colors.RED}{Colors.BOLD}████╗  ██║██║██╔══██╗██╔════╝{Colors.BLUE}                              ║
║  {Colors.RED}{Colors.BOLD}██╔██╗ ██║██║██║  ██║███████╗{Colors.BLUE}                              ║
║  {Colors.RED}{Colors.BOLD}██║╚██╗██║██║██║  ██║╚════██║{Colors.BLUE}                              ║
║  {Colors.RED}{Colors.BOLD}██║ ╚████║██║██████╔╝███████║{Colors.BLUE}                              ║
║  {Colors.RED}{Colors.BOLD}╚═╝  ╚═══╝╚═╝╚═════╝ ╚══════╝{Colors.BLUE}                              ║
║                                                                 ║
║     {Colors.YELLOW}Network Intrusion Detection System with ML{Colors.BLUE}                ║
║     {Colors.CYAN}(c) 2025 - Advanced Security Tools{Colors.BLUE}                         ║
║                                                                 ║
╚═════════════════════════════════════════════════════════════════╝{Colors.ENDC}
    """
    print(banner)
    print(f"{Colors.GREEN}[+] Starting NIDS with Machine Learning...{Colors.ENDC}")
    time.sleep(1)
    
    # Start NIDS with curses
    nids = NIDS()
    curses.wrapper(nids.run)
    
    print(f"{Colors.GREEN}[+] NIDS shutdown complete. Thank you for using our tool!{Colors.ENDC}")

if __name__ == "__main__":
    main()
