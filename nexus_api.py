from flask import Flask, jsonify, request
import threading

class NexusAPI:
    def __init__(self, nids_instance):
        self.nids = nids_instance  # Reference to the NIDS instance
        self.app = Flask(__name__)
        self.setup_routes()

    def setup_routes(self):
        """Set up API routes"""
        @self.app.route('/api/status', methods=['GET'])
        def get_status():
            system_stats = self.nids.get_system_stats()
            return jsonify({
                'status': 'running',
                'uptime': self.nids.get_uptime(),
                'packets_analyzed': self.nids.packets_analyzed,
                'packets_per_second': self.nids.get_packets_per_second(),
                'alerts_count': len(self.nids.alerts),
                'malicious_traffic_count': len(self.nids.malicious_traffic),
                'normal_traffic_count': len(self.nids.normal_traffic),
                'unique_ips': len(self.nids.unique_ips),
                'cpu_usage': system_stats['cpu'],
                'memory_usage': system_stats['memory'],
                'ml_model_trained': self.nids.model_trained
            })
        
        @self.app.route('/api/alerts', methods=['GET'])
        def get_alerts():
            limit = request.args.get('limit', default=50, type=int)
            return jsonify([
                {
                    'timestamp': alert['timestamp'].isoformat(),
                    'message': alert['message'],
                    'severity': alert['severity']
                }
                for alert in self.nids.alerts[-limit:]
            ])
        
        @self.app.route('/api/traffic/malicious', methods=['GET'])
        def get_malicious_traffic():
            limit = request.args.get('limit', default=50, type=int)
            return jsonify([
                {
                    'timestamp': traffic['timestamp'].isoformat(),
                    'source_ip': traffic['source_ip'],
                    'dest_ip': traffic['dest_ip'],
                    'protocol': traffic['protocol'],
                    'threat_score': traffic['threat_score']
                }
                for traffic in self.nids.malicious_traffic[-limit:]
            ])
        
        @self.app.route('/api/stats/protocol', methods=['GET'])
        def get_protocol_stats():
            return jsonify(dict(self.nids.protocol_stats))
        
        @self.app.route('/api/report', methods=['GET'])
        def get_report():
            return jsonify(self.nids.generate_report())

    def start_api(self):
        """Start the API server in a background thread"""
        api_port = 5000
        api_thread = threading.Thread(
            target=lambda: self.app.run(host='0.0.0.0', port=api_port, debug=False),
            daemon=True
        )
        api_thread.start()
        self.nids.add_alert(f"🌐 REST API started on port {api_port}", "LOW")
