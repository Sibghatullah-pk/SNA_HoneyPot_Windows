"""
Network Scanner - Scans network for active hosts and open ports
"""
import socket
import threading
from concurrent.futures import ThreadPoolExecutor
import time


class NetworkScanner:
    def __init__(self):
        """Initialize network scanner"""
        self.timeout = 1
        self.max_workers = 50
    
    def scan(self, target):
        """Scan a network or host"""
        print(f"\n[*] Scanning: {target}")
        
        # Check if single host or network
        if '/' in target:
            return self.scan_network(target)
        else:
            return self.scan_host(target)
    
    def scan_host(self, host, ports=None):
        """Scan a single host for open ports"""
        if ports is None:
            # Common ports
            ports = [21, 22, 23, 25, 53, 80, 110, 143, 443, 445, 
                    3306, 3389, 5432, 5900, 8080, 8443]
        
        results = {
            'host': host,
            'open_ports': [],
            'scan_time': time.time()
        }
        
        print(f"[*] Scanning {host}...")
        
        with ThreadPoolExecutor(max_workers=self.max_workers) as executor:
            futures = {executor.submit(self._check_port, host, port): port 
                      for port in ports}
            
            for future in futures:
                port = futures[future]
                if future.result():
                    service = self._get_service(port)
                    results['open_ports'].append({
                        'port': port,
                        'service': service
                    })
                    print(f"  [+] Port {port} ({service}) - OPEN")
        
        return results
    
    def scan_network(self, network):
        """Scan a network range for active hosts"""
        # Simple implementation - scan 192.168.1.0/24 as example
        base_ip = '.'.join(network.split('.')[:-1])
        
        results = {
            'network': network,
            'active_hosts': [],
            'scan_time': time.time()
        }
        
        print(f"[*] Scanning network {network}...")
        
        active_hosts = []
        with ThreadPoolExecutor(max_workers=self.max_workers) as executor:
            futures = {executor.submit(self._ping_host, f"{base_ip}.{i}"): i 
                      for i in range(1, 255)}
            
            for future in futures:
                host = future.result()
                if host:
                    active_hosts.append(host)
                    print(f"  [+] Active host: {host}")
        
        # Scan each active host for open ports
        for host in active_hosts:
            host_info = self.scan_host(host, ports=[22, 80, 443, 3389, 8080])
            results['active_hosts'].append(host_info)
        
        return results
    
    def _check_port(self, host, port):
        """Check if a port is open"""
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(self.timeout)
            result = sock.connect_ex((host, port))
            sock.close()
            return result == 0
        except:
            return False
    
    def _ping_host(self, host):
        """Check if host is active (using port 80 as a simple check)"""
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(0.5)
            result = sock.connect_ex((host, 80))
            sock.close()
            if result == 0:
                return host
            # Try port 443 as well
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(0.5)
            result = sock.connect_ex((host, 443))
            sock.close()
            if result == 0:
                return host
        except:
            pass
        return None
    
    def _get_service(self, port):
        """Get service name for port"""
        services = {
            21: 'FTP',
            22: 'SSH',
            23: 'Telnet',
            25: 'SMTP',
            53: 'DNS',
            80: 'HTTP',
            110: 'POP3',
            143: 'IMAP',
            443: 'HTTPS',
            445: 'SMB',
            3306: 'MySQL',
            3389: 'RDP',
            5432: 'PostgreSQL',
            5900: 'VNC',
            8080: 'HTTP-Alt',
            8443: 'HTTPS-Alt'
        }
        return services.get(port, f'Port-{port}')


if __name__ == '__main__':
    scanner = NetworkScanner()
    results = scanner.scan_host('127.0.0.1')
    print(f"\nResults: {results}")
