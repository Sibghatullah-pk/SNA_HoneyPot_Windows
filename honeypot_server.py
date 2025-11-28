"""
Honeypot Server - Enhanced Vulnerable Service Simulator
Listens on multiple ports and logs connection attempts with detailed analysis
"""
import socket
import threading
import time
from datetime import datetime
import re


class HoneypotServer:
    """
    Enhanced Honeypot Server with:
    - High port support (no admin needed)
    - Multiple service simulation
    - Payload analysis and attack classification
    - Severity detection
    - User-agent extraction
    """
    
    def __init__(self, ports=None, callback=None, use_high_ports=True):
        """Initialize honeypot server"""
        
        # Port mapping (high port -> standard port it simulates)
        self.high_port_map = {
            2222: 22,    # SSH
            2323: 23,    # Telnet  
            8000: 80,    # HTTP
            8443: 443,   # HTTPS
            33060: 3306, # MySQL
            8080: 8080,  # HTTP Proxy
            2121: 21,    # FTP
            6379: 6379,  # Redis
            27017: 27017 # MongoDB
        }
        
        # Default ports
        if ports is None:
            if use_high_ports:
                self.ports = [2222, 2323, 8000, 8443, 33060, 8080, 2121]
            else:
                self.ports = [22, 23, 80, 443, 3306, 8080]
        else:
            self.ports = ports
            
        self.callback = callback
        self.is_running = False
        self.threads = []
        self.sockets = []
        self.connection_count = 0
        self.lock = threading.Lock()
        
        # Service banners
        self.banners = {
            # SSH
            22: b"SSH-2.0-OpenSSH_7.4p1 Ubuntu-10\r\n",
            2222: b"SSH-2.0-OpenSSH_7.4p1 Ubuntu-10\r\n",
            # Telnet
            23: b"\r\n\r\nWelcome to Microsoft Telnet Service\r\n\r\nlogin: ",
            2323: b"\r\n\r\nWelcome to Microsoft Telnet Service\r\n\r\nlogin: ",
            # HTTP
            80: b"HTTP/1.1 200 OK\r\nServer: Apache/2.4.41 (Ubuntu)\r\nContent-Type: text/html\r\n\r\n<html><head><title>Welcome</title></head><body><h1>It works!</h1></body></html>",
            8000: b"HTTP/1.1 200 OK\r\nServer: Apache/2.4.41 (Ubuntu)\r\nContent-Type: text/html\r\n\r\n<html><head><title>Welcome</title></head><body><h1>It works!</h1></body></html>",
            # HTTPS
            443: b"HTTP/1.1 200 OK\r\nServer: nginx/1.18.0\r\n\r\n",
            8443: b"HTTP/1.1 200 OK\r\nServer: nginx/1.18.0\r\n\r\n",
            # MySQL
            3306: b"J\x00\x00\x00\x0a5.7.32-0ubuntu0.18.04.1\x00",
            33060: b"J\x00\x00\x00\x0a5.7.32-0ubuntu0.18.04.1\x00",
            # FTP
            21: b"220 Microsoft FTP Service\r\n",
            2121: b"220 Microsoft FTP Service\r\n",
            # HTTP Proxy / Tomcat
            8080: b"HTTP/1.1 200 OK\r\nServer: Apache-Coyote/1.1\r\nContent-Type: text/html\r\n\r\n<html><body><h1>Apache Tomcat</h1></body></html>",
            # Redis
            6379: b"-ERR unknown command\r\n",
            # MongoDB
            27017: b""
        }
    
    def start(self):
        """Start honeypot on all configured ports"""
        print(f"\n{'='*60}")
        print(f"🛡️  STARTING HONEYPOT SERVER")
        print(f"{'='*60}")
        print(f"Ports: {self.ports}")
        print(f"{'='*60}\n")
        
        self.is_running = True
        
        for port in self.ports:
            thread = threading.Thread(target=self._listen_on_port, args=(port,), daemon=True)
            thread.start()
            self.threads.append(thread)
            time.sleep(0.1)
    
    def stop(self):
        """Stop all honeypot listeners"""
        print("\n[*] Stopping Honeypot...")
        self.is_running = False
        
        for sock in self.sockets:
            try:
                sock.close()
            except:
                pass
        
        self.sockets.clear()
        self.threads.clear()
        print("[✓] Honeypot stopped")
    
    def _listen_on_port(self, port):
        """Listen on a specific port"""
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            sock.settimeout(1)
            sock.bind(('0.0.0.0', port))
            sock.listen(10)
            self.sockets.append(sock)
            
            service = self._get_service_name(port)
            print(f"[✓] Listening on port {port} ({service})")
            
            while self.is_running:
                try:
                    client_socket, address = sock.accept()
                    thread = threading.Thread(
                        target=self._handle_connection,
                        args=(client_socket, address, port),
                        daemon=True
                    )
                    thread.start()
                except socket.timeout:
                    continue
                except Exception as e:
                    if self.is_running:
                        print(f"[!] Error on port {port}: {e}")
                    break
        
        except OSError as e:
            if "Address already in use" in str(e) or "10048" in str(e):
                print(f"[!] Port {port} already in use - skipping")
            else:
                print(f"[!] Failed to bind port {port}: {e}")
        except Exception as e:
            print(f"[!] Failed to bind port {port}: {e}")
    
    def _handle_connection(self, client_socket, address, port):
        """Handle incoming connection"""
        try:
            with self.lock:
                self.connection_count += 1
                conn_id = self.connection_count
            
            source_ip = address[0]
            source_port = address[1]
            service = self._get_service_name(port)
            simulated = self.high_port_map.get(port, port)
            
            # Initialize attack data
            attack_data = {
                'type': 'connection_attempt',
                'source_ip': source_ip,
                'source_port': source_port,
                'target_port': port,
                'simulated_port': simulated,
                'service': service,
                'timestamp': datetime.now().isoformat(),
                'severity': 'low',
                'payload': '',
                'payload_size': 0,
                'user_agent': '',
                'connection_id': conn_id
            }
            
            # Print detection
            print(f"\n{'='*60}")
            print(f"🚨 ATTACK #{conn_id} DETECTED")
            print(f"   From: {source_ip}:{source_port}")
            print(f"   To: Port {port} ({service})")
            print(f"   Time: {attack_data['timestamp']}")
            
            # Send banner
            if port in self.banners:
                try:
                    client_socket.send(self.banners[port])
                except:
                    pass
            
            # Receive data
            client_socket.settimeout(5)
            received = b''
            try:
                while len(received) < 10000:
                    chunk = client_socket.recv(4096)
                    if not chunk:
                        break
                    received += chunk
            except socket.timeout:
                pass
            except:
                pass
            
            # Analyze payload
            if received:
                payload = received.decode('utf-8', errors='ignore')[:2000]
                attack_data['payload'] = payload
                attack_data['payload_size'] = len(received)
                attack_data['user_agent'] = self._extract_user_agent(payload)
                attack_data['severity'] = self._analyze_severity(payload, port)
                attack_data['type'] = self._detect_attack_type(payload, port)
                
                print(f"   Payload: {payload[:80]}..." if len(payload) > 80 else f"   Payload: {payload}")
            
            print(f"   Type: {attack_data['type']}")
            print(f"   Severity: {attack_data['severity'].upper()}")
            print(f"{'='*60}")
            
            # Callback
            if self.callback:
                self.callback(attack_data)
            
            client_socket.close()
        
        except Exception as e:
            print(f"[!] Connection error: {e}")
    
    def _extract_user_agent(self, payload):
        """Extract User-Agent from HTTP payload"""
        match = re.search(r'User-Agent:\s*([^\r\n]+)', payload, re.IGNORECASE)
        return match.group(1).strip() if match else ''
    
    def _analyze_severity(self, payload, port):
        """Analyze payload for severity"""
        pl = payload.lower()
        
        # High severity
        high = ['root', 'admin', '/etc/passwd', '/etc/shadow', 'union select',
                'drop table', 'rm -rf', 'wget ', 'curl ', 'nc -e', 'bash -i',
                '<script', 'javascript:', 'eval(', 'exec(']
        if any(x in pl for x in high):
            return 'high'
        
        # Medium severity
        medium = ['password', 'login', 'user', 'pass', 'auth', 'select ', '../']
        if any(x in pl for x in medium):
            return 'medium'
        
        return 'low'
    
    def _detect_attack_type(self, payload, port):
        """Detect attack type"""
        pl = payload.lower()
        
        if any(x in pl for x in ['select', 'union', 'drop', 'insert', 'update', 'delete']):
            return 'sql_injection'
        elif any(x in pl for x in ['<script', 'javascript:', 'onerror', 'onload']):
            return 'xss_attempt'
        elif '../' in payload or '..\\' in payload:
            return 'directory_traversal'
        elif any(x in pl for x in ['wget', 'curl', 'nc ', 'bash']):
            return 'command_injection'
        elif port in [22, 2222, 23, 2323, 21, 2121]:
            return 'brute_force'
        elif port in [80, 8000, 443, 8443, 8080]:
            return 'web_scan'
        elif port in [3306, 33060]:
            return 'database_probe'
        
        return 'connection_attempt'
    
    def _get_service_name(self, port):
        """Get service name for port"""
        services = {
            21: 'FTP', 2121: 'FTP',
            22: 'SSH', 2222: 'SSH',
            23: 'Telnet', 2323: 'Telnet',
            80: 'HTTP', 8000: 'HTTP',
            443: 'HTTPS', 8443: 'HTTPS',
            3306: 'MySQL', 33060: 'MySQL',
            8080: 'HTTP-Proxy',
            6379: 'Redis',
            27017: 'MongoDB'
        }
        return services.get(port, f'Port-{port}')


if __name__ == '__main__':
    def callback(data):
        print(f"Logged: {data['source_ip']} -> {data['target_port']}")
    
    hp = HoneypotServer(callback=callback)
    hp.start()
    
    try:
        print("\nHoneypot running. Press Ctrl+C to stop.\n")
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        hp.stop()
