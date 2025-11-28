"""
Honeypot Server - Simulates vulnerable services
Listens on multiple ports and logs connection attempts
"""
import socket
import threading
import time
from datetime import datetime


class HoneypotServer:
    def __init__(self, ports=None, callback=None):
        """Initialize honeypot server"""
        self.ports = ports or [22, 23, 80, 443, 3306, 8080]
        self.callback = callback
        self.is_running = False
        self.threads = []
        self.sockets = []
        
        # Service banners
        self.banners = {
            22: b"SSH-2.0-OpenSSH_7.4\r\n",
            23: b"Welcome to Telnet Service\r\nLogin: ",
            80: b"HTTP/1.1 200 OK\r\nServer: Apache/2.4.41\r\n\r\n",
            443: b"HTTP/1.1 200 OK\r\nServer: nginx/1.18.0\r\n\r\n",
            3306: b"MySQL Server 5.7.32\r\n",
            8080: b"HTTP/1.1 200 OK\r\nServer: Tomcat/9.0\r\n\r\n"
        }
    
    def start(self):
        """Start honeypot on all configured ports"""
        print(f"\n[*] Starting Honeypot on ports: {self.ports}")
        self.is_running = True
        
        for port in self.ports:
            thread = threading.Thread(target=self._listen_on_port, args=(port,), daemon=True)
            thread.start()
            self.threads.append(thread)
            time.sleep(0.1)  # Small delay between port bindings
    
    def stop(self):
        """Stop all honeypot listeners"""
        print("\n[*] Stopping Honeypot...")
        self.is_running = False
        
        # Close all sockets
        for sock in self.sockets:
            try:
                sock.close()
            except:
                pass
        
        self.sockets.clear()
        print("[✓] Honeypot stopped")
    
    def _listen_on_port(self, port):
        """Listen on a specific port"""
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            sock.settimeout(1)  # Timeout for accept()
            sock.bind(('0.0.0.0', port))
            sock.listen(5)
            self.sockets.append(sock)
            
            print(f"[✓] Honeypot listening on port {port}")
            
            while self.is_running:
                try:
                    client_socket, address = sock.accept()
                    # Handle connection in separate thread
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
        
        except Exception as e:
            print(f"[!] Failed to bind port {port}: {e}")
    
    def _handle_connection(self, client_socket, address, port):
        """Handle incoming connection"""
        try:
            source_ip = address[0]
            source_port = address[1]
            
            # Log the attack
            attack_data = {
                'type': 'connection_attempt',
                'source_ip': source_ip,
                'source_port': source_port,
                'target_port': port,
                'service': self._get_service_name(port),
                'timestamp': datetime.now().isoformat()
            }
            
            print(f"[!] Attack detected from {source_ip}:{source_port} -> Port {port}")
            
            # Send banner
            if port in self.banners:
                client_socket.send(self.banners[port])
            
            # Try to receive data
            client_socket.settimeout(5)
            try:
                data = client_socket.recv(4096)
                if data:
                    attack_data['payload'] = data.decode('utf-8', errors='ignore')[:500]
            except:
                pass
            
            # Callback to notify main app
            if self.callback:
                self.callback(attack_data)
            
            client_socket.close()
        
        except Exception as e:
            pass
    
    def _get_service_name(self, port):
        """Get service name for port"""
        services = {
            22: 'SSH',
            23: 'Telnet',
            80: 'HTTP',
            443: 'HTTPS',
            3306: 'MySQL',
            8080: 'HTTP-Proxy'
        }
        return services.get(port, f'Port-{port}')


if __name__ == '__main__':
    # Test the honeypot
    def test_callback(data):
        print(f"Attack: {data}")
    
    honeypot = HoneypotServer(ports=[8022, 8023, 8080], callback=test_callback)
    honeypot.start()
    
    try:
        print("Honeypot running... Press CTRL+C to stop")
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        honeypot.stop()
