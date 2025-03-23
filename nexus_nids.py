import scapy.all as scapy
from datetime import datetime, timedelta
import threading
import time
import random
import socket
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
from collections import defaultdict
import psutil
import json
import pygame
import numpy
import math
import numpy as np
import pandas as pd
from sklearn.ensemble import IsolationForest
from flask import Flask, jsonify, request
import logging
from concurrent.futures import ThreadPoolExecutor

class AdvancedNexusNIDS:
    def __init__(self):
        # Set up logging
        logging.basicConfig(
            level=logging.INFO,
            format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
            handlers=[
                logging.FileHandler("nexus_nids.log"),
                logging.StreamHandler()
            ]
        )
        self.logger = logging.getLogger("NexusNIDS")
        
        self.console = Console()
        self.alerts = []
        self.malicious_traffic = []
        self.normal_traffic = []
        self.is_running = True
        self.animation_frames = ["⠋", "⠙", "⠹", "⠸", "⠼", "⠴", "⠦", "⠧", "⠇", "⠏"]
        self.frame_idx = 0
        self.start_time = datetime.now()

        # Initialize audio system with error handling
        try:
            pygame.mixer.init()
            
            # Create the alert sound
            self.alert_frequency = 440
            self.alert_duration = 1000
            self.alert_volume = 0.5
            
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
            self.audio_enabled = True
        except Exception as e:
            self.logger.error(f"Failed to initialize audio: {str(e)}")
            self.audio_enabled = False
        
        self.last_alert_time = datetime.now()
        self.alert_cooldown = timedelta(seconds=5)
        
        # Restored ASCII banner with color tags
        self.ascii_banner = """
    [bright_red]███╗   ██╗[/][bright_green]███████╗[/][bright_yellow]██╗  ██╗[/][bright_blue]██╗   ██╗[/][bright_magenta]███████╗[/]    [bright_cyan]██╗[/][bright_white]██████╗ [/][red]███████╗[/]
    [bright_red]████╗  ██║[/][bright_green]██╔════╝[/][bright_yellow]╚██╗██╔╝[/][bright_blue]██║   ██║[/][bright_magenta]██╔════╝[/]    [bright_cyan]██║[/][bright_white]██╔══██╗[/][red]██╔════╝[/]
    [bright_red]██╔██╗ ██║[/][bright_green]█████╗  [/][bright_yellow] ╚███╔╝ [/][bright_blue]██║   ██║[/][bright_magenta]███████╗[/]    [bright_cyan]██║[/][bright_white]██║  ██║[/][red]███████╗[/]
    [bright_red]██║╚██╗██║[/][bright_green]██╔══╝  [/][bright_yellow] ██╔██╗ [/][bright_blue]██║   ██║[/][bright_magenta]╚════██║[/]    [bright_cyan]██║[/][bright_white]██║  ██║[/][red]╚════██║[/]
    [bright_red]██║ ╚████║[/][bright_green]███████╗[/][bright_yellow]██╔╝ ██╗[/][bright_blue]╚██████╔╝[/][bright_magenta]███████║[/]    [bright_cyan]██║[/][bright_white]██████╔╝[/][red]███████║[/]
    [bright_red]╚═╝  ╚═══╝[/][bright_green]╚══════╝[/][bright_yellow]╚═╝  ╚═╝[/][bright_blue] ╚═════╝ [/][bright_magenta]╚══════╝[/]    [bright_cyan]╚═╝[/][bright_white]╚═════╝ [/][red]╚══════╝[/]
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
        self.ip_geolocation_cache = {}
       
        # Enhanced configuration
        self.scan_threshold = 5
        self.connection_threshold = 50
        self.threat_score_threshold = 7.0
        self.malicious_ports = {
            22, 23, 445, 3389, 5900,
            1433, 3306, 8080, 8888, 4444,
            25, 465, 587,
            20, 21, 69,
            161, 162
        }
        self.suspicious_patterns = {
            b'eval(', b'exec(', b'system(', b'cmd.exe', b'/bin/sh',
            b'SELECT', b'UNION', b'DROP TABLE', b'rm -rf', b'wget',
            b'bash -i', b'nc -e', b'powershell -e', b'chmod +x', b'curl|bash',
            b'OR 1=1', b'--', b'/*', b'#', b'SLEEP(',
            b'<script>', b'javascript:', b'onerror=', b'onload=',
            b'&&', b'||', b';', b'`', b'$(', b'${',
            b'../../../', b'file://', b'php://', b'data://'
        }
        
        self.incident_response_rules = {
            'port_scan': {
                'threshold': 10,
                'action': 'alert',
                'message': 'Port scan detected from {ip}'
            },
            'brute_force': {
                'threshold': 5,
                'ports': {22, 3389, 5900},
                'action': 'alert',
                'message': 'Possible brute force attack detected on {port} from {ip}'
            },
            'data_exfiltration': {
                'threshold': 1000000,
                'action': 'alert',
                'message': 'Possible data exfiltration detected: {bytes} bytes sent to {ip}'
            }
        }
       
        self.banner_colors = [
            "bright_red", "bright_green", "bright_yellow", "bright_blue",
            "bright_magenta", "bright_cyan", "bright_white", "red on black",
            "green on black", "yellow on blue", "cyan on magenta"
        ]
        self.banner_frames = [
            "🌩️", "⚡️", "🔥", "💥", "🌟", "✨", "🌀", "🌠", "🔮", "⚜️"
        ]
        self.banner_rotation_speed = 0.3
        
        self.packet_queue = collections.deque(maxlen=10000)
        self.packet_processing_thread = None
        
        self.thread_pool = ThreadPoolExecutor(max_workers=4)
        
        self.initialize_ml_model()
        self.initialize_api()
        self.logger.info("Nexus NIDS initialized successfully")

    def get_enhanced_banner(self):
        current_time = time.time()
        frame_index = int(current_time / self.banner_rotation_speed) % len(self.banner_frames)
        color_cycle = int(current_time * 2) % len(self.banner_colors)
        
        banner_text = Text()
        banner_text.append(self.ascii_banner, style="bold")
        banner_text.append("\n", style="")
        
        banner_text.append(
            f"[bold {self.banner_colors[color_cycle]}]"
            "╔════════════════════════════════════════════════════╗[/]\n",
            style=""
        )
        banner_text.append(
            f"[bold {self.banner_colors[color_cycle]}]║[/] "
            f"[bright_red]N[/][bright_green]E[/][bright_yellow]X[/][bright_blue]U[/][bright_magenta]S[/] "
            f"[bright_cyan]NIDS[/] "
            f"[bold {self.banner_colors[color_cycle]}]║[/]\n",
            style=""
        )
        banner_text.append(
            f"[bold {self.banner_colors[color_cycle]}]"
            "╠════════════════════════════════════════════════════╣[/]\n",
            style=""
        )
        
        banner_text.append(
            f"[bold {self.banner_colors[(color_cycle + 1) % len(self.banner_colors)]}]║[/] "
            f"[bright_white]Advanced Network Defense System {self.banner_frames[frame_index]}[/]\n",
            style=""
        )
        banner_text.append(
            f"[bold {self.banner_colors[(color_cycle + 2) % len(self.banner_colors)]}]║[/] "
            f"[italic green]Created by Jivant Loganathan[/]\n",
            style=""
        )
        banner_text.append(
            f"[bold {self.banner_colors[(color_cycle + 3) % len(self.banner_colors)]}]"
            "╠════════════════════════════════════════════════════╣[/]\n",
            style=""
        )
        
        banner_text.append(
            f"[bold {self.banner_colors[(color_cycle + 4) % len(self.banner_colors)]}]║[/] "
            f"[bright_green]🛡️ ML-Enhanced Protection[/]\n",
            style=""
        )
        banner_text.append(
            f"[bold {self.banner_colors[(color_cycle + 5) % len(self.banner_colors)]}]║[/] "
            f"[bright_blue]🌐 Real-time API Monitoring[/]\n",
            style=""
        )
        banner_text.append(
            f"[bold {self.banner_colors[(color_cycle + 6) % len(self.banner_colors)]}]║[/] "
            f"[bright_red]🔒 Dynamic Threat Detection[/]\n",
            style=""
        )
        banner_text.append(
            f"[bold {self.banner_colors[(color_cycle + 7) % len(self.banner_colors)]}]║[/] "
            f"[bright_yellow]🧩 Advanced Incident Response[/]\n",
            style=""
        )
        
        banner_text.append(
            f"[bold {self.banner_colors[color_cycle]}]"
            "╚════════════════════════════════════════════════════╝[/]\n",
            style=""
        )
        
        return banner_text

    def initialize_ml_model(self):
        self.ml_model = IsolationForest(contamination=0.05, random_state=42)
        self.training_data = []
        self.model_trained = False
        self.training_threshold = 1000
        self.anomaly_scores = []
        self.feature_columns = [
            'packet_size', 'is_tcp', 'is_udp', 'is_icmp', 
            'src_port', 'dst_port', 'flag_syn', 'flag_ack', 
            'flag_rst', 'flag_fin', 'payload_size',
            'ttl', 'ip_length', 'total_length',
            'fragment', 'tcp_window'
        ]
        self.model_version = 1
        self.logger.info("ML model initialized")

    def extract_packet_features(self, packet):
        features = np.zeros(len(self.feature_columns))
        
        try:
            if packet.haslayer(scapy.IP):
                features[0] = len(packet)
                ip_layer = packet[scapy.IP]
                features[12] = ip_layer.ihl * 4
                features[13] = ip_layer.len
                features[11] = ip_layer.ttl
                features[14] = 1 if ip_layer.flags.MF or ip_layer.frag != 0 else 0
                
                if packet.haslayer(scapy.TCP):
                    features[1] = 1
                    tcp = packet[scapy.TCP]
                    features[4] = tcp.sport
                    features[5] = tcp.dport
                    features[6] = 1 if tcp.flags & 0x02 else 0
                    features[7] = 1 if tcp.flags & 0x10 else 0
                    features[8] = 1 if tcp.flags & 0x04 else 0
                    features[9] = 1 if tcp.flags & 0x01 else 0
                    features[15] = tcp.window
                
                elif packet.haslayer(scapy.UDP):
                    features[2] = 1
                    udp = packet[scapy.UDP]
                    features[4] = udp.sport
                    features[5] = udp.dport
                
                elif packet.haslayer(scapy.ICMP):
                    features[3] = 1
                
                if packet.haslayer(scapy.Raw):
                    features[10] = len(packet[scapy.Raw].load)
        
        except Exception as e:
            self.logger.error(f"Error extracting features: {str(e)}")
        
        return features

    def update_ml_model(self, packet):
        try:
            features = self.extract_packet_features(packet)
            self.training_data.append(features)
            if not self.model_trained and len(self.training_data) >= self.training_threshold:
                self.train_anomaly_model()
        except Exception as e:
            self.logger.error(f"Error updating ML model: {str(e)}")

    def train_anomaly_model(self):
        if len(self.training_data) >= self.training_threshold:
            try:
                self.logger.info(f"Training ML model with {len(self.training_data)} samples")
                data = np.vstack(self.training_data)
                self.ml_model.fit(data)
                self.model_trained = True
                self.add_alert(f"🧠 Machine learning model v{self.model_version} trained successfully", "LOW")
                
                self.anomaly_scores = self.ml_model.decision_function(data)
                df = pd.DataFrame(data, columns=self.feature_columns)
                df['anomaly_score'] = self.anomaly_scores
                score_mean = df['anomaly_score'].mean()
                score_std = df['anomaly_score'].std()
                self.add_alert(f"📊 Model stats - Mean: {score_mean:.2f}, Std: {score_std:.2f}", "LOW")
                self.anomaly_threshold = np.percentile(self.anomaly_scores, 2)
                
                importances = {}
                for i, feature in enumerate(self.feature_columns):
                    importances[feature] = np.mean(np.abs(data[:, i]))
                
                sorted_features = sorted(importances.items(), key=lambda x: x[1], reverse=True)
                top_features = sorted_features[:5]
                self.add_alert(f"🔍 Top ML features: {', '.join([f[0] for f in top_features])}", "LOW")
                
                self.logger.info(f"ML model v{self.model_version} trained successfully")
                self.model_version += 1
                
            except Exception as e:
                self.logger.error(f"Error training ML model: {str(e)}")
                self.add_alert(f"❌ Error training ML model: {str(e)}", "HIGH")

    def predict_anomaly(self, packet):
        if not self.model_trained:
            return False, 0.0
            
        try:
            features = self.extract_packet_features(packet)
            features = features.reshape(1, -1)
            prediction = self.ml_model.predict(features)[0]
            anomaly_score = self.ml_model.decision_function(features)[0]
            is_anomaly = (prediction == -1) or (anomaly_score <= self.anomaly_threshold)
            
            if is_anomaly:
                self.add_alert(f"🔍 ML detected anomalous traffic [score: {anomaly_score:.2f}]", "MEDIUM")
                
            return is_anomaly, anomaly_score
            
        except Exception as e:
            self.logger.error(f"Error in anomaly prediction: {str(e)}")
            return False, 0.0

    def initialize_api(self):
        self.api_app = Flask(__name__)
        
        @self.api_app.after_request
        def add_cors_headers(response):
            response.headers['Access-Control-Allow-Origin'] = '*'
            response.headers['Access-Control-Allow-Headers'] = 'Content-Type'
            response.headers['Access-Control-Allow-Methods'] = 'GET, POST, OPTIONS'
            return response
        
        @self.api_app.route('/api/status', methods=['GET'])
        def get_status():
            system_stats = self.get_system_stats()
            return jsonify({
                'status': 'running',
                'uptime': self.get_uptime(),
                'packets_analyzed': self.packets_analyzed,
                'packets_per_second': self.get_packets_per_second(),
                'alerts_count': len(self.alerts),
                'malicious_traffic_count': len(self.malicious_traffic),
                'normal_traffic_count': len(self.normal_traffic),
                'unique_ips': len(self.unique_ips),
                'cpu_usage': system_stats['cpu'],
                'memory_usage': system_stats['memory'],
                'ml_model_trained': self.model_trained,
                'ml_model_version': self.model_version - 1 if self.model_trained else 0
            })
        
        @self.api_app.route('/api/alerts', methods=['GET'])
        def get_alerts():
            limit = request.args.get('limit', default=50, type=int)
            severity = request.args.get('severity', default=None, type=str)
            
            filtered_alerts = self.alerts
            if severity:
                filtered_alerts = [a for a in filtered_alerts if a['severity'] == severity.upper()]
                
            return jsonify([
                {
                    'timestamp': alert['timestamp'].isoformat(),
                    'message': alert['message'],
                    'severity': alert['severity']
                }
                for alert in filtered_alerts[-limit:]
            ])
        
        @self.api_app.route('/api/traffic/malicious', methods=['GET'])
        def get_malicious_traffic():
            limit = request.args.get('limit', default=50, type=int)
            return jsonify([
                {
                    'timestamp': traffic['timestamp'].isoformat(),
                    'source_ip': traffic['source_ip'],
                    'dest_ip': traffic['dest_ip'],
                    'protocol': traffic['protocol'],
                    'threat_score': traffic['threat_score'],
                    'detection_method': traffic.get('detection_method', 'Rule-based')
                }
                for traffic in self.malicious_traffic[-limit:]
            ])
        
        @self.api_app.route('/api/stats/protocol', methods=['GET'])
        def get_protocol_stats():
            return jsonify(dict(self.protocol_stats))
        
        @self.api_app.route('/api/report', methods=['GET'])
        def get_report():
            return jsonify(self.generate_report())
        
        @self.api_app.route('/api/threats/top', methods=['GET'])
        def get_top_threats():
            limit = request.args.get('limit', default=10, type=int)
            top_threats = sorted(
                [(ip, score) for ip, score in self.threat_scores.items() if score > self.threat_score_threshold],
                key=lambda x: x[1],
                reverse=True
            )[:limit]
            
            return jsonify([
                {'ip': ip, 'threat_score': score} 
                for ip, score in top_threats
            ])
        
        @self.api_app.route('/api/ml/status', methods=['GET'])
        def get_ml_status():
            return jsonify({
                'trained': self.model_trained,
                'version': self.model_version - 1 if self.model_trained else 0,
                'training_samples': len(self.training_data),
                'training_threshold': self.training_threshold,
                'training_progress': f"{len(self.training_data)}/{self.training_threshold}",
                'progress_percentage': (len(self.training_data) / self.training_threshold) * 100,
                'anomalies_detected': sum(1 for traffic in self.malicious_traffic 
                                       if traffic.get('detection_method') == 'ML-based')
            })
            
        @self.api_app.route('/api/config', methods=['GET'])
        def get_config():
            return jsonify({
                'scan_threshold': self.scan_threshold,
                'connection_threshold': self.connection_threshold,
                'threat_score_threshold': self.threat_score_threshold,
                'malicious_ports_count': len(self.malicious_ports),
                'suspicious_patterns_count': len(self.suspicious_patterns),
                'incident_response_rules': list(self.incident_response_rules.keys())
            })
            
        @self.api_app.route('/api/config/update', methods=['POST'])
        def update_config():
            try:
                data = request.json
                updated = {}
                
                if 'scan_threshold' in data:
                    self.scan_threshold = data['scan_threshold']
                    updated['scan_threshold'] = self.scan_threshold
                    
                if 'connection_threshold' in data:
                    self.connection_threshold = data['connection_threshold']
                    updated['connection_threshold'] = self.connection_threshold
                    
                if 'threat_score_threshold' in data:
                    self.threat_score_threshold = data['threat_score_threshold']
                    updated['threat_score_threshold'] = self.threat_score_threshold
                
                self.add_alert(f"🔧 Configuration updated via API", "LOW")
                self.logger.info(f"Configuration updated: {updated}")
                
                return jsonify({
                    'status': 'success',
                    'updated': updated
                })
            except Exception as e:
                self.logger.error(f"Error updating config via API: {str(e)}")
                return jsonify({
                    'status': 'error',
                    'message': str(e)
                }), 400
        
        api_port = 5000
        api_thread = threading.Thread(
            target=lambda: self.api_app.run(host='0.0.0.0', port=api_port, debug=False, threaded=True),
            daemon=True
        )
        api_thread.start()
        self.add_alert(f"🌐 REST API started on port {api_port}", "LOW")
        self.logger.info(f"REST API started on port {api_port}")

    def play_alert(self):
        if not self.audio_enabled:
            return
            
        current_time = datetime.now()
        if current_time - self.last_alert_time > self.alert_cooldown:
            try:
                self.alert_sound.play()
                self.last_alert_time = current_time
            except Exception as e:
                self.logger.error(f"Error playing alert sound: {str(e)}")
                self.audio_enabled = False

    def print_banner(self):
        self.console.print(self.get_enhanced_banner())
        self.console.print("\n")

    def show_enhanced_startup_animation(self):
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
                    ("Configuring network monitors...", "magenta"),
                    ("Initializing machine learning model...", "yellow"),
                    ("Starting REST API service...", "blue"),
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
        uptime = datetime.now() - self.start_time
        hours = int(uptime.total_seconds() // 3600)
        minutes = int((uptime.total_seconds() % 3600) // 60)
        seconds = int(uptime.total_seconds() % 60)
        return f"{hours:02d}:{minutes:02d}:{seconds:02d}"

    def get_system_stats(self):
        try:
            cpu_percent = psutil.cpu_percent()
            memory = psutil.virtual_memory()
            return {
                'cpu': cpu_percent,
                'memory': memory.percent,
                'network_io': psutil.net_io_counters()
            }
        except Exception as e:
            self.logger.error(f"Error getting system stats: {str(e)}")
            return {
                'cpu': 0,
                'memory': 0,
                'network_io': None
            }

    def get_status_style(self, value):
        if value < 50:
            return "bright_green"
        elif value < 80:
            return "bright_yellow"
        else:
            return "bright_red"

    def update_network_stats(self, packet):
        try:
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
        except Exception as e:
            self.logger.error(f"Error updating network stats: {str(e)}")

    def get_packets_per_second(self):
        try:
            current_time = datetime.now()
            one_minute_ago = current_time - timedelta(minutes=1)
            recent_packets = [p for p in self.last_minute_packets if p > one_minute_ago]
            
            if not recent_packets:
                return 0
                
            seconds = (recent_packets[-1] - recent_packets[0]).total_seconds() if len(recent_packets) > 1 else 60
            return len(recent_packets) / max(1, seconds)
        except Exception as e:
            self.logger.error(f"Error calculating packets per second: {str(e)}")
            return 0

    def add_alert(self, message, severity="MEDIUM"):
        try:
            alert = {
                "timestamp": datetime.now(),
                "message": message,
                "severity": severity
            }
            
            self.alerts.append(alert)
            
            if severity == "HIGH":
                self.play_alert()
                
            self.logger.info(f"Alert: {message} [Severity: {severity}]")
            return alert
        except Exception as e:
            self.logger.error(f"Error adding alert: {str(e)}")

    def detect_port_scan(self, packet):
        try:
            if packet.haslayer(scapy.IP) and packet.haslayer(scapy.TCP):
                ip = packet[scapy.IP]
                tcp = packet[scapy.TCP]
                
                src_ip = ip.src
                dst_port = tcp.dport
                
                self.port_access_history[src_ip].append((dst_port, datetime.now()))
                
                recent_time = datetime.now() - timedelta(seconds=10)
                recent_ports = set([port for port, time in self.port_access_history[src_ip] if time > recent_time])
                
                if len(recent_ports) >= self.scan_threshold:
                    message = f"🔍 Port scan detected from {src_ip} - {len(recent_ports)} ports in 10s"
                    self.add_alert(message, "HIGH")
                    self.register_malicious_traffic(packet, "Port scanning", 8.5, "Rule-based")
                    return True
        except Exception as e:
            self.logger.error(f"Error in port scan detection: {str(e)}")
        
        return False

    def detect_suspicious_content(self, packet):
        try:
            if packet.haslayer(scapy.Raw):
                payload = packet[scapy.Raw].load
                
                for pattern in self.suspicious_patterns:
                    if pattern in payload:
                        src_ip = packet[scapy.IP].src if packet.haslayer(scapy.IP) else "Unknown"
                        dst_ip = packet[scapy.IP].dst if packet.haslayer(scapy.IP) else "Unknown"
                        
                        pattern_str = pattern.decode('utf-8', errors='replace')
                        message = f"⚠️ Suspicious pattern '{pattern_str}' detected from {src_ip} to {dst_ip}"
                        self.add_alert(message, "HIGH")
                        self.register_malicious_traffic(packet, f"Suspicious pattern: {pattern_str}", 9.0, "Pattern-based")
                        return True
        except Exception as e:
            self.logger.error(f"Error in suspicious content detection: {str(e)}")
            
        return False

    def detect_malicious_port(self, packet):
        try:
            if packet.haslayer(scapy.IP) and (packet.haslayer(scapy.TCP) or packet.haslayer(scapy.UDP)):
                ip_layer = packet[scapy.IP]
                
                if packet.haslayer(scapy.TCP):
                    port_layer = packet[scapy.TCP]
                else:
                    port_layer = packet[scapy.UDP]
                
                dst_port = port_layer.dport
                
                if dst_port in self.malicious_ports:
                    src_ip = ip_layer.src
                    dst_ip = ip_layer.dst
                    
                    protocol = "TCP" if packet.haslayer(scapy.TCP) else "UDP"
                    message = f"⚠️ Access to potentially vulnerable port {dst_port}/{protocol} from {src_ip} to {dst_ip}"
                    self.add_alert(message, "MEDIUM")
                    
                    self.threat_scores[src_ip] += 2.0
                    
                    if self.threat_scores[src_ip] > self.threat_score_threshold:
                        self.register_malicious_traffic(packet, f"Multiple access to suspicious ports", 
                                                     self.threat_scores[src_ip], "Behavior-based")
                        return True
        except Exception as e:
            self.logger.error(f"Error in malicious port detection: {str(e)}")
            
        return False

    def detect_brute_force(self, packet):
        try:
            if packet.haslayer(scapy.IP) and packet.haslayer(scapy.TCP):
                ip = packet[scapy.IP]
                tcp = packet[scapy.TCP]
                
                src_ip = ip.src
                dst_ip = ip.dst
                dst_port = tcp.dport
                
                if dst_port in self.incident_response_rules['brute_force']['ports']:
                    src_key = f"{src_ip}_{dst_ip}_{dst_port}"
                    self.connection_count[src_key] += 1
                    
                    threshold = self.incident_response_rules['brute_force']['threshold']
                    if self.connection_count[src_key] > threshold:
                        message = f"🔒 Possible brute force attack from {src_ip} to {dst_ip}:{dst_port}"
                        self.add_alert(message, "HIGH")
                        self.register_malicious_traffic(packet, "Possible brute force attack", 9.5, "Rule-based")
                        return True
        except Exception as e:
            self.logger.error(f"Error in brute force detection: {str(e)}")
            
        return False

    def detect_data_exfiltration(self, packet):
        try:
            if packet.haslayer(scapy.IP) and packet.haslayer(scapy.Raw):
                ip = packet[scapy.IP]
                payload_size = len(packet[scapy.Raw].load)
                
                if payload_size > self.incident_response_rules['data_exfiltration']['threshold']:
                    src_ip = ip.src
                    dst_ip = ip.dst
                    
                    is_internal_src = any(src_ip.startswith(subnet.split('/')[0]) for subnet in self.internal_subnets)
                    is_internal_dst = any(dst_ip.startswith(subnet.split('/')[0]) for subnet in self.internal_subnets)
                    
                    if is_internal_src and not is_internal_dst:
                        message = f"📤 Possible data exfiltration: {payload_size/1024:.2f} KB from {src_ip} to {dst_ip}"
                        self.add_alert(message, "HIGH")
                        self.register_malicious_traffic(packet, "Possible data exfiltration", 9.0, "Rule-based")
                        return True
        except Exception as e:
            self.logger.error(f"Error in data exfiltration detection: {str(e)}")
            
        return False

    def register_malicious_traffic(self, packet, reason, threat_score, detection_method):
        try:
            if packet.haslayer(scapy.IP):
                ip = packet[scapy.IP]
                src_ip = ip.src
                dst_ip = ip.dst
                
                protocol = "Unknown"
                if packet.haslayer(scapy.TCP):
                    protocol = "TCP"
                elif packet.haslayer(scapy.UDP):
                    protocol = "UDP"
                elif packet.haslayer(scapy.ICMP):
                    protocol = "ICMP"
                
                self.threat_scores[src_ip] += threat_score / 10.0
                
                malicious_traffic = {
                    "timestamp": datetime.now(),
                    "source_ip": src_ip,
                    "dest_ip": dst_ip,
                    "protocol": protocol,
                    "reason": reason,
                    "threat_score": threat_score,
                    "detection_method": detection_method
                }
                
                self.malicious_traffic.append(malicious_traffic)
                self.logger.warning(f"Malicious traffic registered: {reason} from {src_ip} to {dst_ip}")
                
                return malicious_traffic
        except Exception as e:
            self.logger.error(f"Error registering malicious traffic: {str(e)}")
            
        return None

    def register_normal_traffic(self, packet):
        try:
            if packet.haslayer(scapy.IP):
                ip = packet[scapy.IP]
                
                protocol = "Unknown"
                if packet.haslayer(scapy.TCP):
                    protocol = "TCP"
                elif packet.haslayer(scapy.UDP):
                    protocol = "UDP"
                elif packet.haslayer(scapy.ICMP):
                    protocol = "ICMP"
                
                normal_traffic = {
                    "timestamp": datetime.now(),
                    "source_ip": ip.src,
                    "dest_ip": ip.dst,
                    "protocol": protocol
                }
                
                self.normal_traffic.append(normal_traffic)
                
                if len(self.normal_traffic) > 10000:
                    self.normal_traffic = self.normal_traffic[-10000:]
                
                return normal_traffic
        except Exception as e:
            self.logger.error(f"Error registering normal traffic: {str(e)}")
            
        return None

    def process_packet(self, packet):
        try:
            self.packet_queue.append(packet)
            self.update_network_stats(packet)
            
            is_malicious = False
            
            is_malicious = is_malicious or self.detect_port_scan(packet)
            is_malicious = is_malicious or self.detect_suspicious_content(packet)
            is_malicious = is_malicious or self.detect_malicious_port(packet)
            is_malicious = is_malicious or self.detect_brute_force(packet)
            is_malicious = is_malicious or self.detect_data_exfiltration(packet)
            
            if not is_malicious and self.model_trained:
                is_anomaly, anomaly_score = self.predict_anomaly(packet)
                if is_anomaly:
                    self.register_malicious_traffic(
                        packet, 
                        f"Anomalous traffic (score: {anomaly_score:.2f})", 
                        min(10.0, max(5.0, abs(anomaly_score) * 2)),
                        "ML-based"
                    )
                    is_malicious = True
            
            self.update_ml_model(packet)
            
            if not is_malicious:
                self.register_normal_traffic(packet)
            
            return is_malicious
        except Exception as e:
            self.logger.error(f"Error processing packet: {str(e)}")
            return False

    def packet_processing_loop(self):
        try:
            while self.is_running:
                if self.packet_queue:
                    packet = self.packet_queue.popleft()
                    self.process_packet(packet)
                else:
                    time.sleep(0.01)
        except Exception as e:
            self.logger.error(f"Error in packet processing loop: {str(e)}")

    def packet_capture_callback(self, packet):
        try:
            self.thread_pool.submit(self.process_packet, packet)
        except Exception as e:
            self.logger.error(f"Error in packet capture callback: {str(e)}")

    def detect_internal_networks(self):
        try:
            interfaces = netifaces.interfaces()
            for interface in interfaces:
                if interface == 'lo':
                    continue
                    
                addrs = netifaces.ifaddresses(interface)
                if netifaces.AF_INET in addrs:
                    for addr in addrs[netifaces.AF_INET]:
                        if 'addr' in addr and 'netmask' in addr:
                            ip = addr['addr']
                            netmask = addr['netmask']
                            
                            ip_int = int.from_bytes(socket.inet_aton(ip), byteorder='big')
                            mask_int = int.from_bytes(socket.inet_aton(netmask), byteorder='big')
                            network_int = ip_int & mask_int
                            network_addr = socket.inet_ntoa(network_int.to_bytes(4, byteorder='big'))
                            
                            mask_bits = bin(mask_int).count('1')
                            cidr = f"{network_addr}/{mask_bits}"
                            
                            self.internal_subnets.add(cidr)
                            self.add_alert(f"🌐 Detected internal network: {cidr}", "LOW")
            
            if not self.internal_subnets:
                self.internal_subnets.add("192.168.0.0/16")
                self.internal_subnets.add("10.0.0.0/8")
                self.internal_subnets.add("172.16.0.0/12")
                
            self.logger.info(f"Detected internal networks: {self.internal_subnets}")
        except Exception as e:
            self.logger.error(f"Error detecting internal networks: {str(e)}")
            self.internal_subnets.add("192.168.0.0/16")
            self.internal_subnets.add("10.0.0.0/8")
            self.internal_subnets.add("172.16.0.0/12")

    def generate_report(self):
        try:
            total_ips = len(self.unique_ips)
            malicious_ips = set([t['source_ip'] for t in self.malicious_traffic])
            normal_ips = total_ips - len(malicious_ips)
            
            current_time = datetime.now()
            uptime_seconds = (current_time - self.start_time).total_seconds()
            
            protocol_percentage = {}
            total_packets = sum(self.protocol_stats.values())
            for protocol, count in self.protocol_stats.items():
                if total_packets > 0:
                    protocol_percentage[protocol] = (count / total_packets) * 100
                else:
                    protocol_percentage[protocol] = 0
            
            severity_counts = {"HIGH": 0, "MEDIUM": 0, "LOW": 0}
            for alert in self.alerts:
                severity = alert['severity']
                if severity in severity_counts:
                    severity_counts[severity] += 1
            
            top_threat_ips = sorted(
                [(ip, score) for ip, score in self.threat_scores.items()],
                key=lambda x: x[1],
                reverse=True
            )[:10]
            
            threat_types = {}
            for traffic in self.malicious_traffic:
                reason = traffic.get('reason', 'Unknown')
                threat_types[reason] = threat_types.get(reason, 0) + 1
            
            detection_methods = {}
            for traffic in self.malicious_traffic:
                method = traffic.get('detection_method', 'Rule-based')
                detection_methods[method] = detection_methods.get(method, 0) + 1
            
            report = {
                "timestamp": current_time.isoformat(),
                "uptime": self.get_uptime(),
                "uptime_seconds": uptime_seconds,
                "packets_analyzed": self.packets_analyzed,
                "packets_per_second": self.get_packets_per_second(),
                "ip_statistics": {
                    "total_unique_ips": total_ips,
                    "malicious_ips": len(malicious_ips),
                    "normal_ips": normal_ips,
                    "malicious_percentage": (len(malicious_ips) / max(1, total_ips)) * 100
                },
                "traffic_statistics": {
                    "malicious_traffic": len(self.malicious_traffic),
                    "normal_traffic": len(self.normal_traffic),
                    "total_traffic": len(self.malicious_traffic) + len(self.normal_traffic),
                    "malicious_percentage": (len(self.malicious_traffic) / max(1, len(self.malicious_traffic) + len(self.normal_traffic))) * 100
                },
                "protocol_statistics": {
                    "counts": dict(self.protocol_stats),
                    "percentages": protocol_percentage
                },
                "alert_statistics": {
                    "total_alerts": len(self.alerts),
                    "severity_breakdown": severity_counts,
                    "alerts_per_minute": (len(self.alerts) / max(1, uptime_seconds / 60))
                },
                "top_threats": [{"ip": ip, "score": score} for ip, score in top_threat_ips],
                "threat_types": threat_types,
                "detection_methods": detection_methods,
                "ml_model": {
                    "trained": self.model_trained,
                    "version": self.model_version - 1 if self.model_trained else 0,
                    "training_progress": f"{len(self.training_data)}/{self.training_threshold}"
                }
            }
            
            return report
        except Exception as e:
            self.logger.error(f"Error generating report: {str(e)}")
            return {"error": str(e)}

    def display_dashboard(self):
        try:
            layout = Layout()
            
            layout.split(
                Layout(name="header", size=8),
                Layout(name="main", ratio=1)
            )
            
            layout["main"].split_row(
                Layout(name="left", ratio=3),
                Layout(name="right", ratio=2)
            )
            
            layout["left"].split(
                Layout(name="stats", size=10),
                Layout(name="alerts", ratio=1)
            )
            
            layout["right"].split(
                Layout(name="threats", ratio=1),
                Layout(name="traffic", ratio=1)
            )
            
            header_panel = Panel(
                self.get_enhanced_banner(),
                box=box.ROUNDED,
                border_style="bright_blue",
                padding=(0, 2)
            )
            layout["header"].update(header_panel)
            
            system_stats = self.get_system_stats()
            
            stats_table = Table(show_header=False, box=box.SIMPLE)
            stats_table.add_column("Stat", style="bright_cyan", width=20)
            stats_table.add_column("Value", style="bright_white")
            
            stats_table.add_row("Status", Text("🟢 Running", style="bright_green"))
            stats_table.add_row("Uptime", self.get_uptime())
            stats_table.add_row("Packets Analyzed", f"{self.packets_analyzed:,}")
            stats_table.add_row("Packets/Second", f"{self.get_packets_per_second():.2f}")
            stats_table.add_row("Unique IPs", f"{len(self.unique_ips):,}")
            
            cpu_style = self.get_status_style(system_stats['cpu'])
            mem_style = self.get_status_style(system_stats['memory'])
            
            stats_table.add_row("CPU Usage", Text(f"{system_stats['cpu']:.1f}%", style=cpu_style))
            stats_table.add_row("Memory Usage", Text(f"{system_stats['memory']:.1f}%", style=mem_style))
            
            ml_status = "🧠 Trained" if self.model_trained else f"🔄 Training ({len(self.training_data)}/{self.training_threshold})"
            ml_style = "bright_green" if self.model_trained else "bright_yellow"
            stats_table.add_row("ML Model", Text(ml_status, style=ml_style))
            
            stats_panel = Panel(
                stats_table,
                title="System Statistics",
                title_align="center",
                border_style="cyan",
                box=box.ROUNDED
            )
            layout["stats"].update(stats_panel)
            
            alerts_table = Table(box=box.SIMPLE)
            alerts_table.add_column("Time", style="bright_blue", width=10)
            alerts_table.add_column("Severity", style="bright_white", width=8)
            alerts_table.add_column("Message", style="bright_white")
            
            for alert in self.alerts[-10:]:
                time_str = alert["timestamp"].strftime("%H:%M:%S")
                severity = alert["severity"]
                message = alert["message"]
                
                severity_style = "bright_red" if severity == "HIGH" else "bright_yellow" if severity == "MEDIUM" else "bright_green"
                alerts_table.add_row(time_str, Text(severity, style=severity_style), message)
            
            alerts_panel = Panel(
                alerts_table,
                title=f"Recent Alerts ({len(self.alerts)} total)",
                title_align="center",
                border_style="yellow",
                box=box.ROUNDED
            )
            layout["alerts"].update(alerts_panel)
            
            threats_table = Table(box=box.SIMPLE)
            threats_table.add_column("IP Address", style="bright_red")
            threats_table.add_column("Score", justify="right", style="bright_white")
            
            top_threats = sorted(
                [(ip, score) for ip, score in self.threat_scores.items() if score > 0],
                key=lambda x: x[1],
                reverse=True
            )[:10]
            
            for ip, score in top_threats:
                score_style = "bright_red" if score > self.threat_score_threshold else "bright_yellow"
                threats_table.add_row(ip, Text(f"{score:.1f}", style=score_style))
            
            threat_panel = Panel(
                threats_table,
                title="Top Threats",
                title_align="center",
                border_style="red",
                box=box.ROUNDED
            )
            layout["threats"].update(threat_panel)
            
            traffic_table = Table(box=box.SIMPLE)
            traffic_table.add_column("Protocol", style="bright_magenta")
            traffic_table.add_column("Count", justify="right", style="bright_white")
            traffic_table.add_column("%", justify="right", style="bright_green")
            
            total_packets = sum(self.protocol_stats.values())
            for protocol, count in sorted(self.protocol_stats.items(), key=lambda x: x[1], reverse=True):
                percentage = (count / max(1, total_packets)) * 100
                traffic_table.add_row(protocol, f"{count:,}", f"{percentage:.1f}%")
            
            traffic_panel = Panel(
                traffic_table,
                title="Protocol Statistics",
                title_align="center",
                border_style="magenta",
                box=box.ROUNDED
            )
            layout["traffic"].update(traffic_panel)
            
            return layout
        except Exception as e:
            self.logger.error(f"Error displaying dashboard: {str(e)}")
            return Text(f"Error displaying dashboard: {str(e)}")

    def start_sniffing(self, interface=None):
        try:
            self.show_enhanced_startup_animation()
            self.detect_internal_networks()
            
            self.packet_processing_thread = threading.Thread(target=self.packet_processing_loop)
            self.packet_processing_thread.daemon = True
            self.packet_processing_thread.start()
            
            interfaces_text = "all interfaces" if interface is None else interface
            self.add_alert(f"🚀 Starting packet capture on {interfaces_text}", "LOW")
            self.logger.info(f"Starting packet capture on {interfaces_text}")
            
            with Live(self.display_dashboard(), refresh_per_second=2) as live:
                try:
                    scapy.sniff(
                        iface=interface,
                        prn=self.packet_capture_callback,
                        store=False
                    )
                except KeyboardInterrupt:
                    self.logger.info("Packet capture stopped by user")
                    self.is_running = False
                except Exception as e:
                    self.logger.error(f"Error in packet capture: {str(e)}")
                    self.add_alert(f"❌ Error in packet capture: {str(e)}", "HIGH")
                    
                while self.is_running:
                    live.update(self.display_dashboard())
                    time.sleep(0.5)
                    
            return True
            
        except Exception as e:
            self.logger.error(f"Error starting packet capture: {str(e)}")
            self.add_alert(f"❌ Error starting packet capture: {str(e)}", "HIGH")
            return False
            
    def stop(self):
        self.logger.info("Stopping Nexus NIDS")
        self.is_running = False
        if self.thread_pool:
            self.thread_pool.shutdown(wait=False)
        self.add_alert("🛑 Stopping Nexus NIDS", "LOW")

if __name__ == "__main__":
    try:
        nids = AdvancedNexusNIDS()
        nids.start_sniffing()
    except KeyboardInterrupt:
        print("\nShutting down Nexus NIDS...")
    except Exception as e:
        print(f"Error: {str(e)}")
