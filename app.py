"""
Sentinel Honeypot - Main Application
Complete web dashboard for monitoring network attacks
"""
from flask import Flask, render_template, jsonify, request, Response, session, redirect, url_for
from flask_socketio import SocketIO, emit
from datetime import datetime
import os
import socket
import json

from logger_module import HoneypotLogger
from honeypot_server import HoneypotServer
from network_scanner import NetworkScanner

# Initialize Flask
app = Flask(__name__)
app.config['SECRET_KEY'] = 'sentinel-honeypot-secret-2025'
# Admin password (env override recommended)
app.config['ADMIN_PASSWORD'] = os.environ.get('SENTINEL_ADMIN_PW', 'admin123')
socketio = SocketIO(app, cors_allowed_origins="*", async_mode='threading')

# Components
logger = HoneypotLogger()
honeypot = None
scanner = None

# In-memory stats (for real-time dashboard)
recent_attacks = []
attack_stats = {
    'total_attacks': 0,
    'unique_ips': set(),
    'port_scans': 0,
    'connection_attempts': 0
}


# ============== WEB ROUTES ==============

@app.route('/')
def index():
    """Main dashboard"""
    return render_template('index.html')


@app.route('/live')
def live():
    """Live monitoring page"""
    return render_template('live.html')


@app.route('/analytics')
def analytics():
    """Analytics page"""
    return render_template('analytics.html')


# ============== API ROUTES ==============

@app.route('/api/stats')
def get_stats():
    """Get real-time statistics"""
    try:
        # Get from database for persistence
        db_stats = logger.get_statistics()
        
        return jsonify({
            'total_attacks': db_stats.get('total_attacks', attack_stats['total_attacks']),
            'unique_ips': db_stats.get('unique_ips', len(attack_stats['unique_ips'])),
            'port_scans': attack_stats['port_scans'],
            'connection_attempts': attack_stats['connection_attempts'],
            'recent_attacks': recent_attacks[-50:],
            'attacks_by_port': db_stats.get('attacks_by_port', {}),
            'attacks_by_type': db_stats.get('attacks_by_type', {}),
            'attacks_by_severity': db_stats.get('attacks_by_severity', {}),
            'top_attackers': db_stats.get('top_attackers', []),
            'hourly_attacks': db_stats.get('hourly_attacks', {}),
            'pending_alerts': db_stats.get('pending_alerts', 0)
        })
    except Exception as e:
        print(f"[!] Stats error: {e}")
        return jsonify({
            'total_attacks': 0,
            'unique_ips': 0,
            'port_scans': 0,
            'connection_attempts': 0,
            'recent_attacks': []
        })


@app.route('/api/start_honeypot', methods=['POST'])
def start_honeypot():
    """Start the honeypot server"""
    global honeypot
    try:
        if honeypot is None or not honeypot.is_running:
            data = request.json or {}
            use_high_ports = data.get('use_high_ports', True)
            
            if use_high_ports:
                ports = data.get('ports', [2222, 2323, 8000, 8443, 33060, 8080, 2121])
            else:
                ports = data.get('ports', [22, 23, 80, 443, 3306, 8080])
            
            honeypot = HoneypotServer(
                ports=ports, 
                callback=on_attack_detected,
                use_high_ports=use_high_ports
            )
            honeypot.start()
            
            return jsonify({
                'status': 'success',
                'message': 'Honeypot started!',
                'ports': ports
            })
        else:
            return jsonify({'status': 'info', 'message': 'Already running'})
            
    except PermissionError:
        return jsonify({
            'status': 'error',
            'message': 'Permission denied. Use high ports or run as Administrator.'
        }), 403
    except Exception as e:
        return jsonify({'status': 'error', 'message': str(e)}), 500


@app.route('/api/stop_honeypot', methods=['POST'])
def stop_honeypot():
    """Stop the honeypot server"""
    global honeypot
    try:
        if honeypot and honeypot.is_running:
            honeypot.stop()
            return jsonify({'status': 'success', 'message': 'Honeypot stopped'})
        return jsonify({'status': 'info', 'message': 'Not running'})
    except Exception as e:
        return jsonify({'status': 'error', 'message': str(e)}), 500


@app.route('/api/attack_info')
def get_attack_info():
    """Get target info for team attacks"""
    hostname = socket.gethostname()
    ips = []
    
    try:
        for info in socket.getaddrinfo(hostname, None, socket.AF_INET):
            ip = info[4][0]
            if ip not in ips and not ip.startswith('127.'):
                ips.append(ip)
    except:
        pass
    
    if not ips:
        try:
            ips = [socket.gethostbyname(hostname)]
        except:
            ips = ['127.0.0.1']
    
    return jsonify({
        'honeypot_status': 'running' if (honeypot and honeypot.is_running) else 'stopped',
        'target_ips': ips,
        'hostname': hostname,
        'ports': {
            'high_ports': {
                '2222': 'SSH - ssh user@IP -p 2222',
                '2323': 'Telnet - telnet IP 2323',
                '8000': 'HTTP - curl http://IP:8000',
                '8443': 'HTTPS - curl https://IP:8443 -k',
                '33060': 'MySQL - mysql -h IP -P 33060',
                '8080': 'Proxy - curl http://IP:8080',
                '2121': 'FTP - ftp IP 2121'
            }
        },
        'attack_commands': [
            f'nmap -sV -p 2222,2323,8000,8443,33060,8080,2121 {ips[0] if ips else "TARGET_IP"}',
            f'telnet {ips[0] if ips else "TARGET_IP"} 2323',
            f'curl http://{ips[0] if ips else "TARGET_IP"}:8000',
            f'nc {ips[0] if ips else "TARGET_IP"} 2222'
        ]
    })


@app.route('/api/clear_stats', methods=['POST'])
def clear_stats():
    """Clear all statistics"""
    global recent_attacks, attack_stats
    
    recent_attacks = []
    attack_stats = {
        'total_attacks': 0,
        'unique_ips': set(),
        'port_scans': 0,
        'connection_attempts': 0
    }
    
    logger.clear_all_data()
    
    return jsonify({'status': 'success', 'message': 'All data cleared'})


@app.route('/api/scan_network', methods=['POST'])
def scan_network():
    """Scan network"""
    global scanner
    try:
        data = request.json or {}
        target = data.get('target', '127.0.0.1')
        
        scanner = NetworkScanner()
        results = scanner.scan(target)
        
        return jsonify({'status': 'success', 'results': results})
    except Exception as e:
        return jsonify({'status': 'error', 'message': str(e)}), 500


@app.route('/api/export/<format>')
def export_data(format):
    """Export attack data"""
    try:
        data = logger.export_attacks(format=format)
        
        if format == 'json':
            return Response(
                data,
                mimetype='application/json',
                headers={'Content-Disposition': 'attachment;filename=attacks.json'}
            )
        elif format == 'csv':
            return Response(
                data,
                mimetype='text/csv',
                headers={'Content-Disposition': 'attachment;filename=attacks.csv'}
            )
        else:
            return jsonify({'status': 'error', 'message': 'Invalid format'})
    except Exception as e:
        return jsonify({'status': 'error', 'message': str(e)}), 500


@app.route('/api/alerts')
def get_alerts():
    """Get alerts"""
    alerts = logger.get_alerts(limit=50)
    return jsonify({'alerts': alerts})


@app.route('/api/database/attacks')
def get_db_attacks():
    """Get attacks from database"""
    limit = request.args.get('limit', 100, type=int)
    attacks = logger.get_recent_attacks(limit=limit)
    return jsonify({'attacks': attacks, 'count': len(attacks)})


# ============== ADMIN PORTAL ==============


@app.route('/admin_portal')
def admin_portal():
    """Unrestricted admin portal for full visibility"""
    if not session.get('admin_authenticated'):
        return redirect(url_for('admin_login'))
    return render_template('admin.html')



@app.route('/admin_login', methods=['GET', 'POST'])
def admin_login():
    """Simple password form for admin portal"""
    if request.method == 'POST':
        data = request.form or {}
        pw = data.get('password', '')
        if pw and pw == app.config.get('ADMIN_PASSWORD'):
            session['admin_authenticated'] = True
            return redirect(url_for('admin_portal'))
        else:
            return render_template('admin_login.html', error='Invalid password')
    return render_template('admin_login.html')


@app.route('/admin_logout')
def admin_logout():
    session.pop('admin_authenticated', None)
    return redirect(url_for('admin_login'))


@app.route('/api/admin/ack_alert', methods=['POST'])
def ack_alert():
    data = request.json or {}
    alert_id = data.get('id')
    if not alert_id:
        return jsonify({'status': 'error', 'message': 'Missing id'}), 400

    ok = logger.acknowledge_alert(alert_id)
    if ok:
        return jsonify({'status': 'success', 'message': 'Alert acknowledged'})
    return jsonify({'status': 'error', 'message': 'Failed to acknowledge'}), 500


@app.route('/api/admin/delete_attack', methods=['POST'])
def api_delete_attack():
    data = request.json or {}
    attack_id = data.get('id')
    if not attack_id:
        return jsonify({'status': 'error', 'message': 'Missing id'}), 400

    ok = logger.delete_attack(attack_id)
    if ok:
        return jsonify({'status': 'success', 'message': 'Attack deleted'})
    return jsonify({'status': 'error', 'message': 'Failed to delete attack'}), 500


@app.route('/api/admin/logs')
def admin_logs():
    """Return last N lines from the JSON log file"""
    lines = request.args.get('lines', 200, type=int)
    out = []
    try:
        with open(logger.log_file, 'r', encoding='utf-8') as f:
            all_lines = f.readlines()
            out = [l.strip() for l in all_lines[-lines:]]
    except Exception as e:
        print(f"[!] Error reading logs: {e}")
    return jsonify({'lines': out})


# ============== FAKE TRAP ENDPOINTS ==============

@app.route('/admin')
@app.route('/admin/')
@app.route('/administrator')
@app.route('/wp-admin')
@app.route('/wp-login.php')
@app.route('/phpmyadmin')
@app.route('/phpMyAdmin')
@app.route('/.env')
@app.route('/config.php')
@app.route('/backup.sql')
@app.route('/api/v1/users')
@app.route('/api/v1/admin')
def trap_endpoint():
    """Trap endpoint for malicious scanners"""
    trap_data = {
        'type': 'trap_access',
        'source_ip': request.remote_addr,
        'source_port': 0,
        'target_port': 5000,
        'service': 'HTTP-Trap',
        'timestamp': datetime.now().isoformat(),
        'severity': 'high',
        'payload': f"Path: {request.path}, Method: {request.method}",
        'user_agent': request.headers.get('User-Agent', ''),
        'connection_id': 0
    }
    
    # Log the trap access
    logger.log_attack(trap_data)
    
    # Update stats
    attack_stats['total_attacks'] += 1
    attack_stats['unique_ips'].add(request.remote_addr)
    recent_attacks.append(trap_data)
    
    # Emit to dashboard
    socketio.emit('new_attack', trap_data)
    
    print(f"\n🪤 TRAP TRIGGERED: {request.remote_addr} accessed {request.path}")
    
    # Return fake response
    return jsonify({'error': 'Access denied'}), 403


# ============== WEBSOCKET HANDLERS ==============

@socketio.on('connect')
def handle_connect():
    """Client connected"""
    emit('connection_response', {'status': 'connected', 'timestamp': datetime.now().isoformat()})


@socketio.on('disconnect')
def handle_disconnect():
    """Client disconnected"""
    pass


# ============== CALLBACK ==============

def on_attack_detected(attack_data):
    """Callback when attack is detected by honeypot"""
    global recent_attacks, attack_stats
    
    # Update in-memory stats
    attack_stats['total_attacks'] += 1
    attack_stats['unique_ips'].add(attack_data.get('source_ip', 'unknown'))
    
    if attack_data.get('type') == 'port_scan':
        attack_stats['port_scans'] += 1
    else:
        attack_stats['connection_attempts'] += 1
    
    # Store in memory
    attack_data['timestamp'] = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    recent_attacks.append(attack_data)
    
    if len(recent_attacks) > 1000:
        recent_attacks.pop(0)
    
    # Log to database
    logger.log_attack(attack_data)
    
    # Emit to all connected clients
    socketio.emit('new_attack', attack_data)


# ============== MAIN ==============

if __name__ == '__main__':
    print("\n" + "="*60)
    print("🛡️  SENTINEL HONEYPOT SYSTEM")
    print("="*60)
    print("Dashboard: http://localhost:5000")
    print("="*60)
    print("\nPress CTRL+C to stop\n")
    
    # Create directories
    os.makedirs('database', exist_ok=True)
    os.makedirs('logs', exist_ok=True)
    
    # Run
    socketio.run(
        app, 
        host='0.0.0.0', 
        port=5000, 
        debug=True, 
        allow_unsafe_werkzeug=True
    )
