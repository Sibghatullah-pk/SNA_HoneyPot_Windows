"""
Sentinel Honeypot - Main Application
Web dashboard for monitoring network attacks and honeypot activity
"""
from flask import Flask, render_template, jsonify, request
from flask_socketio import SocketIO, emit
import threading
import json
from datetime import datetime
import os
from logger_module import HoneypotLogger
from honeypot_server import HoneypotServer
from network_scanner import NetworkScanner

app = Flask(__name__)
app.config['SECRET_KEY'] = 'sentinel-honeypot-secret-key-2025'
socketio = SocketIO(app, cors_allowed_origins="*")

# Initialize components
logger = HoneypotLogger()
honeypot = None
scanner = None

# Store recent attacks for dashboard
recent_attacks = []
attack_stats = {
    'total_attacks': 0,
    'unique_ips': set(),
    'port_scans': 0,
    'connection_attempts': 0
}


@app.route('/')
def index():
    """Main dashboard page"""
    return render_template('index.html')


@app.route('/live')
def live():
    """Live monitoring page"""
    return render_template('live.html')


@app.route('/analytics')
def analytics():
    """Analytics and statistics page"""
    return render_template('analytics.html')


@app.route('/api/stats')
def get_stats():
    """Get current statistics"""
    try:
        return jsonify({
            'total_attacks': attack_stats['total_attacks'],
            'unique_ips': len(attack_stats['unique_ips']),
            'port_scans': attack_stats['port_scans'],
            'connection_attempts': attack_stats['connection_attempts'],
            'recent_attacks': recent_attacks[-50:]  # Last 50 attacks
        }), 200
    except Exception as e:
        print(f"[!] Error fetching stats: {e}")
        return jsonify({
            'total_attacks': 0,
            'unique_ips': 0,
            'port_scans': 0,
            'connection_attempts': 0,
            'recent_attacks': []
        }), 200


@app.route('/api/start_honeypot', methods=['POST'])
def start_honeypot():
    """Start the honeypot server"""
    global honeypot
    try:
        if honeypot is None or not honeypot.is_running:
            data = request.json or {}
            ports = data.get('ports', [22, 23, 80, 443, 3306, 8080])
            
            print(f"[*] Starting honeypot on ports: {ports}")
            honeypot = HoneypotServer(ports=ports, callback=on_attack_detected)
            honeypot.start()
            
            print("[✓] Honeypot started successfully")
            return jsonify({'status': 'success', 'message': 'Honeypot started successfully'}), 200
        else:
            return jsonify({'status': 'info', 'message': 'Honeypot already running'}), 200
    except PermissionError as e:
        error_msg = 'Permission denied. Run as Administrator to use privileged ports (< 1024)'
        print(f"[!] Permission Error: {error_msg}")
        return jsonify({'status': 'error', 'message': error_msg}), 403
    except Exception as e:
        error_msg = f'Failed to start: {str(e)}'
        print(f"[!] Error: {error_msg}")
        return jsonify({'status': 'error', 'message': error_msg}), 500


@app.route('/api/stop_honeypot', methods=['POST'])
def stop_honeypot():
    """Stop the honeypot server"""
    global honeypot
    try:
        if honeypot and honeypot.is_running:
            print("[*] Stopping honeypot...")
            honeypot.stop()
            print("[✓] Honeypot stopped successfully")
            return jsonify({'status': 'success', 'message': 'Honeypot stopped successfully'}), 200
        else:
            return jsonify({'status': 'info', 'message': 'Honeypot not running'}), 200
    except Exception as e:
        error_msg = f'Failed to stop: {str(e)}'
        print(f"[!] Error: {error_msg}")
        return jsonify({'status': 'error', 'message': error_msg}), 500


@app.route('/api/scan_network', methods=['POST'])
def scan_network():
    """Perform network scan"""
    global scanner
    try:
        data = request.json or {}
        target = data.get('target', '192.168.1.0/24')
        
        scanner = NetworkScanner()
        results = scanner.scan(target)
        
        return jsonify({'status': 'success', 'results': results})
    except Exception as e:
        return jsonify({'status': 'error', 'message': str(e)})


def on_attack_detected(attack_data):
    """Callback when an attack is detected"""
    global recent_attacks, attack_stats
    
    # Update statistics
    attack_stats['total_attacks'] += 1
    attack_stats['unique_ips'].add(attack_data.get('source_ip', 'unknown'))
    
    if attack_data.get('type') == 'port_scan':
        attack_stats['port_scans'] += 1
    else:
        attack_stats['connection_attempts'] += 1
    
    # Add timestamp
    attack_data['timestamp'] = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    
    # Store attack
    recent_attacks.append(attack_data)
    if len(recent_attacks) > 1000:
        recent_attacks.pop(0)
    
    # Log to file
    logger.log_attack(attack_data)
    
    # Emit to connected clients via WebSocket
    socketio.emit('new_attack', attack_data)


@socketio.on('connect')
def handle_connect():
    """Handle client connection"""
    emit('connection_response', {'status': 'connected'})


@socketio.on('disconnect')
def handle_disconnect():
    """Handle client disconnection"""
    pass


if __name__ == '__main__':
    print("=" * 60)
    print("🛡️  SENTINEL HONEYPOT SYSTEM")
    print("=" * 60)
    print(f"Starting web dashboard on http://localhost:5000")
    print("Press CTRL+C to stop")
    print("=" * 60)
    
    # Create necessary directories
    os.makedirs('database', exist_ok=True)
    os.makedirs('logs', exist_ok=True)
    
    socketio.run(app, host='0.0.0.0', port=5000, debug=True, allow_unsafe_werkzeug=True)
