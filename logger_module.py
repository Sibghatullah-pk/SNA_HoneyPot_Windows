"""
Logger Module - Enhanced Honeypot Event Logger
Handles logging to SQLite database, JSON files, and provides analytics
"""
import json
import sqlite3
from datetime import datetime, timedelta
import os
import threading
import urllib.request
import urllib.parse


class HoneypotLogger:
    """
    Enhanced logger with:
    - Thread-safe SQLite operations
    - JSON file logging
    - Real-time statistics
    - Export capabilities
    - Alert detection
    """
    
    def __init__(self, db_path='database/honeypot.db', log_file='logs/honeypot.log'):
        """Initialize logger with database and file paths"""
        self.db_path = db_path
        self.log_file = log_file
        self.lock = threading.Lock()
        self._init_database()
        self._ensure_log_dir()
    
    def _ensure_log_dir(self):
        """Ensure log directory exists"""
        os.makedirs(os.path.dirname(self.log_file), exist_ok=True)
    
    def _init_database(self):
        """Initialize SQLite database with comprehensive schema"""
        os.makedirs(os.path.dirname(self.db_path), exist_ok=True)
        
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        # Main attacks table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS attacks (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp TEXT NOT NULL,
                type TEXT NOT NULL DEFAULT 'connection_attempt',
                source_ip TEXT NOT NULL,
                source_port INTEGER,
                target_port INTEGER,
                simulated_port INTEGER,
                service TEXT,
                payload TEXT,
                payload_size INTEGER DEFAULT 0,
                severity TEXT DEFAULT 'low',
                user_agent TEXT,
                connection_id INTEGER,
                created_at TEXT DEFAULT CURRENT_TIMESTAMP
            )
        ''')
        
        # IP tracking table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS ip_tracking (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                ip_address TEXT UNIQUE NOT NULL,
                first_seen TEXT NOT NULL,
                last_seen TEXT NOT NULL,
                total_attacks INTEGER DEFAULT 1,
                threat_level TEXT DEFAULT 'low',
                asn TEXT,
                org TEXT,
                country TEXT,
                is_vpn INTEGER DEFAULT 0
            )
        ''')
        
        # Alerts table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS alerts (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp TEXT NOT NULL,
                alert_type TEXT NOT NULL,
                source_ip TEXT,
                message TEXT NOT NULL,
                severity TEXT DEFAULT 'medium',
                is_acknowledged INTEGER DEFAULT 0,
                attack_id INTEGER
            )
        ''')
        
        # Create indexes
        cursor.execute('CREATE INDEX IF NOT EXISTS idx_attacks_timestamp ON attacks(timestamp)')
        cursor.execute('CREATE INDEX IF NOT EXISTS idx_attacks_source_ip ON attacks(source_ip)')
        cursor.execute('CREATE INDEX IF NOT EXISTS idx_attacks_severity ON attacks(severity)')
        # Ensure attack enrichment columns exist (for older DBs)
        try:
            cols = [c[1] for c in cursor.execute("PRAGMA table_info(attacks)").fetchall()]
            if 'asn' not in cols:
                cursor.execute('ALTER TABLE attacks ADD COLUMN asn TEXT')
            if 'org' not in cols:
                cursor.execute('ALTER TABLE attacks ADD COLUMN org TEXT')
            if 'country' not in cols:
                cursor.execute('ALTER TABLE attacks ADD COLUMN country TEXT')
            if 'is_vpn' not in cols:
                cursor.execute('ALTER TABLE attacks ADD COLUMN is_vpn INTEGER DEFAULT 0')
        except Exception:
            pass
        
        conn.commit()
        conn.close()
        print("[✓] Database initialized")
    
    def _get_connection(self):
        """Get database connection"""
        return sqlite3.connect(self.db_path, check_same_thread=False)
    
    def log_attack(self, attack_data):
        """Log attack to database and file"""
        with self.lock:
            try:
                conn = self._get_connection()
                cursor = conn.cursor()
                
                timestamp = attack_data.get('timestamp', datetime.now().isoformat())
                source_ip = attack_data.get('source_ip', 'unknown')
                
                cursor.execute('''
                    INSERT INTO attacks (
                        timestamp, type, source_ip, source_port, target_port,
                        simulated_port, service, payload, payload_size, severity,
                        user_agent, connection_id
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                ''', (
                    timestamp,
                    attack_data.get('type', 'connection_attempt'),
                    source_ip,
                    attack_data.get('source_port'),
                    attack_data.get('target_port'),
                    attack_data.get('simulated_port'),
                    attack_data.get('service', 'unknown'),
                    attack_data.get('payload', '')[:5000],
                    attack_data.get('payload_size', 0),
                    attack_data.get('severity', 'low'),
                    attack_data.get('user_agent', ''),
                    attack_data.get('connection_id')
                ))
                
                attack_id = cursor.lastrowid

                # Enrich IP information (ASN, org, country, vpn guess)
                try:
                    enrich = self._enrich_ip(source_ip)
                    if enrich:
                        cursor.execute('''
                            UPDATE attacks SET asn = ?, org = ?, country = ?, is_vpn = ? WHERE id = ?
                        ''', (enrich.get('asn'), enrich.get('org'), enrich.get('country'), 1 if enrich.get('is_vpn') else 0, attack_id))
                        # Update ip_tracking with enrichment
                        cursor.execute('''
                            UPDATE ip_tracking SET asn = ?, org = ?, country = ?, is_vpn = ? WHERE ip_address = ?
                        ''', (enrich.get('asn'), enrich.get('org'), enrich.get('country'), 1 if enrich.get('is_vpn') else 0, source_ip))
                except Exception as e:
                    print(f"[!] Enrichment error: {e}")
                
                # Update IP tracking
                cursor.execute('''
                    INSERT INTO ip_tracking (ip_address, first_seen, last_seen, total_attacks)
                    VALUES (?, ?, ?, 1)
                    ON CONFLICT(ip_address) DO UPDATE SET
                        last_seen = ?,
                        total_attacks = total_attacks + 1,
                        threat_level = CASE
                            WHEN total_attacks + 1 >= 50 THEN 'critical'
                            WHEN total_attacks + 1 >= 20 THEN 'high'
                            WHEN total_attacks + 1 >= 5 THEN 'medium'
                            ELSE 'low'
                        END
                ''', (source_ip, timestamp, timestamp, timestamp))
                
                # Create alert for high severity
                if attack_data.get('severity') == 'high':
                    cursor.execute('''
                        INSERT INTO alerts (timestamp, alert_type, source_ip, message, severity, attack_id)
                        VALUES (?, ?, ?, ?, ?, ?)
                    ''', (
                        timestamp,
                        attack_data.get('type', 'unknown'),
                        source_ip,
                        f"High severity attack from {source_ip}",
                        'high',
                        attack_id
                    ))
                
                conn.commit()
                conn.close()
                
                # Log to file
                self._log_to_file(attack_data)
                
                return attack_id
                
            except Exception as e:
                print(f"[!] Logging error: {e}")
                return None
    
    def _log_to_file(self, attack_data):
        """Log attack to JSON file"""
        try:
            with open(self.log_file, 'a', encoding='utf-8') as f:
                f.write(json.dumps(attack_data, default=str) + '\n')
        except Exception as e:
            print(f"[!] File logging error: {e}")

    def _enrich_ip(self, ip):
        """Perform lightweight IP enrichment using ipinfo.io (no API key required for basic info).
        Returns dict with keys: asn, org, country, is_vpn
        """
        if not ip or ip.startswith('127.'):
            return None
        try:
            token = os.environ.get('IPINFO_TOKEN', '')
            url = f"https://ipinfo.io/{urllib.parse.quote(ip)}/json"
            if token:
                url += f"?token={urllib.parse.quote(token)}"
            req = urllib.request.Request(url, headers={'User-Agent': 'Sentinel/1.0'})
            with urllib.request.urlopen(req, timeout=5) as resp:
                data = json.load(resp)
            res = {
                'asn': None,
                'org': None,
                'country': data.get('country'),
                'is_vpn': False
            }
            # ipinfo returns 'org' like 'AS15169 Google LLC' — parse ASN
            org = data.get('org')
            if org:
                res['org'] = org
                parts = org.split(' ', 1)
                if parts and parts[0].upper().startswith('AS'):
                    res['asn'] = parts[0].upper()

            # Basic heuristic for VPN/hosting providers
            host_providers = ['amazon', 'google', 'digitalocean', 'linode', 'cloudflare', 'ovh', 'aws', 'microsoft', 'hetzner', 'vpn']
            if res['org']:
                lower = res['org'].lower()
                if any(p in lower for p in host_providers):
                    res['is_vpn'] = True

            return res
        except Exception:
            return None
    
    def get_recent_attacks(self, limit=100):
        """Get recent attacks"""
        try:
            conn = self._get_connection()
            cursor = conn.cursor()
            
            cursor.execute('''
                SELECT id, timestamp, type, source_ip, source_port, target_port,
                       service, payload, severity, connection_id
                FROM attacks 
                ORDER BY timestamp DESC 
                LIMIT ?
            ''', (limit,))
            
            columns = ['id', 'timestamp', 'type', 'source_ip', 'source_port', 
                      'target_port', 'service', 'payload', 'severity', 'connection_id']
            attacks = [dict(zip(columns, row)) for row in cursor.fetchall()]
            
            conn.close()
            return attacks
            
        except Exception as e:
            print(f"[!] Error retrieving attacks: {e}")
            return []
    
    def get_statistics(self):
        """Get comprehensive statistics"""
        try:
            conn = self._get_connection()
            cursor = conn.cursor()
            
            stats = {}
            
            cursor.execute('SELECT COUNT(*) FROM attacks')
            stats['total_attacks'] = cursor.fetchone()[0]
            
            cursor.execute('SELECT COUNT(DISTINCT source_ip) FROM attacks')
            stats['unique_ips'] = cursor.fetchone()[0]
            
            cursor.execute('''
                SELECT type, COUNT(*) as count FROM attacks 
                GROUP BY type ORDER BY count DESC
            ''')
            stats['attacks_by_type'] = dict(cursor.fetchall())
            
            cursor.execute('''
                SELECT target_port, COUNT(*) as count FROM attacks 
                GROUP BY target_port ORDER BY count DESC LIMIT 10
            ''')
            stats['attacks_by_port'] = dict(cursor.fetchall())
            
            cursor.execute('''
                SELECT severity, COUNT(*) as count FROM attacks GROUP BY severity
            ''')
            stats['attacks_by_severity'] = dict(cursor.fetchall())
            
            cursor.execute('''
                SELECT source_ip, COUNT(*) as count FROM attacks 
                GROUP BY source_ip ORDER BY count DESC LIMIT 10
            ''')
            stats['top_attackers'] = [{'ip': r[0], 'count': r[1]} for r in cursor.fetchall()]
            
            cursor.execute('''
                SELECT strftime('%H', timestamp) as hour, COUNT(*) as count
                FROM attacks WHERE timestamp >= datetime('now', '-24 hours')
                GROUP BY hour ORDER BY hour
            ''')
            stats['hourly_attacks'] = dict(cursor.fetchall())
            
            cursor.execute('SELECT COUNT(*) FROM alerts WHERE is_acknowledged = 0')
            stats['pending_alerts'] = cursor.fetchone()[0]
            
            conn.close()
            return stats
            
        except Exception as e:
            print(f"[!] Error getting statistics: {e}")
            return {}
    
    def get_alerts(self, limit=50):
        """Get unacknowledged alerts"""
        try:
            conn = self._get_connection()
            cursor = conn.cursor()
            
            cursor.execute('''
                SELECT id, timestamp, alert_type, source_ip, message, severity
                FROM alerts WHERE is_acknowledged = 0
                ORDER BY timestamp DESC LIMIT ?
            ''', (limit,))
            
            columns = ['id', 'timestamp', 'alert_type', 'source_ip', 'message', 'severity']
            alerts = [dict(zip(columns, row)) for row in cursor.fetchall()]
            
            conn.close()
            return alerts
            
        except Exception as e:
            print(f"[!] Error getting alerts: {e}")
            return []
    
    def export_attacks(self, format='json'):
        """Export all attacks"""
        try:
            conn = self._get_connection()
            cursor = conn.cursor()
            cursor.execute('SELECT * FROM attacks ORDER BY timestamp DESC')
            
            columns = [d[0] for d in cursor.description]
            attacks = [dict(zip(columns, row)) for row in cursor.fetchall()]
            conn.close()
            
            if format == 'json':
                return json.dumps(attacks, indent=2, default=str)
            elif format == 'csv':
                if not attacks:
                    return ''
                lines = [','.join(columns)]
                for a in attacks:
                    lines.append(','.join(str(a.get(c, '')).replace(',', ';') for c in columns))
                return '\n'.join(lines)
            return attacks
            
        except Exception as e:
            print(f"[!] Export error: {e}")
            return None
    
    def clear_all_data(self):
        """Clear all data"""
        try:
            conn = self._get_connection()
            cursor = conn.cursor()
            cursor.execute('DELETE FROM attacks')
            cursor.execute('DELETE FROM ip_tracking')
            cursor.execute('DELETE FROM alerts')
            conn.commit()
            conn.close()
            
            with open(self.log_file, 'w') as f:
                f.write('')
            
            print("[✓] All data cleared")
            return True
        except Exception as e:
            print(f"[!] Error clearing data: {e}")
            return False

    def acknowledge_alert(self, alert_id):
        """Mark an alert as acknowledged"""
        try:
            conn = self._get_connection()
            cursor = conn.cursor()
            cursor.execute('UPDATE alerts SET is_acknowledged = 1 WHERE id = ?', (alert_id,))
            conn.commit()
            conn.close()
            return True
        except Exception as e:
            print(f"[!] Error acknowledging alert: {e}")
            return False

    def delete_attack(self, attack_id):
        """Delete an attack record by id"""
        try:
            conn = self._get_connection()
            cursor = conn.cursor()
            cursor.execute('DELETE FROM attacks WHERE id = ?', (attack_id,))
            conn.commit()
            conn.close()
            return True
        except Exception as e:
            print(f"[!] Error deleting attack id {attack_id}: {e}")
            return False
