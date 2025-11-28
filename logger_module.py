"""
Logger Module - Handles logging of honeypot events
"""
import json
import sqlite3
from datetime import datetime
import os


class HoneypotLogger:
    def __init__(self, db_path='database/honeypot_logs.db', log_file='logs/honeypot.log'):
        """Initialize logger"""
        self.db_path = db_path
        self.log_file = log_file
        self._init_database()
    
    def _init_database(self):
        """Initialize SQLite database"""
        os.makedirs(os.path.dirname(self.db_path), exist_ok=True)
        
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        # Create attacks table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS attacks (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp TEXT NOT NULL,
                type TEXT NOT NULL,
                source_ip TEXT NOT NULL,
                source_port INTEGER,
                target_port INTEGER,
                service TEXT,
                payload TEXT,
                severity TEXT DEFAULT 'medium'
            )
        ''')
        
        conn.commit()
        conn.close()
    
    def log_attack(self, attack_data):
        """Log attack to database and file"""
        try:
            # Log to database
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            
            cursor.execute('''
                INSERT INTO attacks (timestamp, type, source_ip, source_port, 
                                   target_port, service, payload, severity)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            ''', (
                attack_data.get('timestamp', datetime.now().isoformat()),
                attack_data.get('type', 'unknown'),
                attack_data.get('source_ip', 'unknown'),
                attack_data.get('source_port'),
                attack_data.get('target_port'),
                attack_data.get('service', 'unknown'),
                attack_data.get('payload', ''),
                attack_data.get('severity', 'medium')
            ))
            
            conn.commit()
            conn.close()
            
            # Log to file
            os.makedirs(os.path.dirname(self.log_file), exist_ok=True)
            with open(self.log_file, 'a') as f:
                f.write(json.dumps(attack_data) + '\n')
        
        except Exception as e:
            print(f"[!] Logging error: {e}")
    
    def get_recent_attacks(self, limit=100):
        """Get recent attacks from database"""
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            
            cursor.execute('''
                SELECT * FROM attacks 
                ORDER BY timestamp DESC 
                LIMIT ?
            ''', (limit,))
            
            attacks = cursor.fetchall()
            conn.close()
            
            return attacks
        except Exception as e:
            print(f"[!] Error retrieving attacks: {e}")
            return []
    
    def get_statistics(self):
        """Get attack statistics"""
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            
            # Total attacks
            cursor.execute('SELECT COUNT(*) FROM attacks')
            total = cursor.fetchone()[0]
            
            # Unique IPs
            cursor.execute('SELECT COUNT(DISTINCT source_ip) FROM attacks')
            unique_ips = cursor.fetchone()[0]
            
            # Top attackers
            cursor.execute('''
                SELECT source_ip, COUNT(*) as count 
                FROM attacks 
                GROUP BY source_ip 
                ORDER BY count DESC 
                LIMIT 10
            ''')
            top_attackers = cursor.fetchall()
            
            # Top targeted ports
            cursor.execute('''
                SELECT target_port, COUNT(*) as count 
                FROM attacks 
                GROUP BY target_port 
                ORDER BY count DESC 
                LIMIT 10
            ''')
            top_ports = cursor.fetchall()
            
            conn.close()
            
            return {
                'total_attacks': total,
                'unique_ips': unique_ips,
                'top_attackers': top_attackers,
                'top_ports': top_ports
            }
        except Exception as e:
            print(f"[!] Error getting statistics: {e}")
            return {}
