# 🛡️ Sentinel Honeypot System

A comprehensive security monitoring and honeypot system for detecting and analyzing network attacks in real-time.

## What is This?

A security monitoring and honeypot system that detects, logs, and analyzes network attacks in real-time. It simulates vulnerable services to attract attackers and study their behavior, providing insights into cyber threat patterns and attack methodologies.

## Attack
# SSH probe
echo "root:password" | nc 127.0.0.1 2222

# Telnet probe  
echo "admin" | nc 127.0.0.1 2323

# HTTP request to honeypot
curl http://127.0.0.1:8000

# Trap endpoint (high severity!)
curl http://127.0.0.1:5000/admin
curl http://127.0.0.1:5000/.env

## Features

- **Real-time Attack Detection**: Monitor incoming connection attempts and port scans
- **Web Dashboard**: Beautiful web interface for monitoring security events
- **Live Feed**: Real-time attack notifications via WebSockets
- **Analytics**: Detailed charts and statistics about attack patterns
- **Network Scanner**: Built-in network scanning capabilities
- **Database Logging**: All attacks are logged to SQLite database
- **Multiple Port Support**: Simulate multiple vulnerable services (SSH, Telnet, HTTP, MySQL, etc.)
- **Multi-threaded Architecture**: Handle thousands of simultaneous connections
- **Service Simulation**: Authentic service banners to deceive automated scanners

## Technology Stack

### Backend
- **Python 3.13** - Core programming language
- **Flask 3.1** - Web framework for the dashboard
- **Flask-SocketIO 5.5** - Real-time bidirectional communication (WebSocket)
- **SQLite3** - Database for storing attack logs
- **Socket Programming** - Low-level network communication for honeypot listeners
- **Threading** - Concurrent connection handling

### Frontend
- **HTML5/CSS3** - User interface structure and styling
- **JavaScript (Vanilla)** - Client-side interactivity
- **Chart.js 4.4** - Data visualization and charts
- **Socket.IO Client** - Real-time updates from server

## Quick Start

### 1. Install Python Dependencies

```powershell
cd "s:\SNA\SNA_HoneyPot_Windows"
python -m venv venv
.\venv\Scripts\Activate.ps1
pip install flask flask-socketio
```

### 2. Run the Application

```powershell
python app.py
```

### 3. Access the Dashboard

Open your browser and navigate to: `http://localhost:5000`

## Usage

1. **Start Honeypot**: Click the "Start Honeypot" button on the dashboard
2. **Monitor Attacks**: Watch real-time attacks in the Live Monitor tab
3. **View Analytics**: Check the Analytics tab for attack patterns and statistics
4. **Network Scanning**: Use the built-in scanner to scan your network

## Architecture & How It Works

### System Components

#### 1. Main Application (`app.py`)
- Flask web server runs on port 5000
- Serves the dashboard interface
- Handles REST API endpoints for controlling the honeypot
- Manages WebSocket connections for real-time updates
- Coordinates between honeypot server, logger, and network scanner

**Key Endpoints:**
- `GET /` - Main dashboard
- `GET /live` - Live monitoring page
- `GET /analytics` - Analytics and charts
- `POST /api/start_honeypot` - Start honeypot listeners
- `POST /api/stop_honeypot` - Stop honeypot
- `GET /api/stats` - Get current statistics
- `POST /api/scan_network` - Perform network scan

#### 2. Honeypot Server (`honeypot_server.py`)
**How it works:**
- Creates socket listeners on multiple ports (22, 23, 80, 443, 3306, 8080)
- Each port simulates a different service (SSH, Telnet, HTTP, MySQL, etc.)
- When someone connects:
  1. Accepts the connection
  2. Sends a fake service banner (e.g., "SSH-2.0-OpenSSH_7.4")
  3. Captures the source IP, port, and any data sent
  4. Logs the attack details
  5. Closes the connection
- Uses **multi-threading** to handle multiple connections simultaneously
- Non-blocking architecture with socket timeouts

**Service Simulation Example:**
```python
banners = {
    22: b"SSH-2.0-OpenSSH_7.4\r\n",
    23: b"Welcome to Telnet Service\r\nLogin: ",
    80: b"HTTP/1.1 200 OK\r\nServer: Apache/2.4.41\r\n\r\n",
    443: b"HTTP/1.1 200 OK\r\nServer: nginx/1.18.0\r\n\r\n",
    3306: b"MySQL Server 5.7.32\r\n",
    8080: b"HTTP/1.1 200 OK\r\nServer: Tomcat/9.0\r\n\r\n"
}
```

#### 3. Logger Module (`logger_module.py`)
**Dual logging system:**
- **SQLite Database**: Structured storage with schema for attacks table
  - Tracks: ID, timestamp, type, source IP, source port, target port, service, payload, severity
  - Enables complex queries and analytics
- **File Logging**: JSON formatted logs in `logs/honeypot.log`
  - Human-readable format for quick inspection
  - Backup logging mechanism

#### 4. Network Scanner (`network_scanner.py`)
- Port scanning using TCP connect scans
- Thread pool executor for concurrent scanning (50 workers)
- Can scan single hosts or network ranges (CIDR notation)
- Identifies open ports and service types
- Timeout-based detection (1 second per port)

#### 5. Real-time Communication
**WebSocket Flow:**
```
Attack Detected → honeypot_server.py
       ↓
Callback → app.py (on_attack_detected)
       ↓
Socket.emit('new_attack') → All connected browsers
       ↓
JavaScript updates UI in real-time
```

### Data Flow Example

1. **Attacker scans your network** → finds open port 22
2. **Connects to port 22** → Honeypot accepts connection
3. **Receives SSH banner** → Thinks it's a real SSH server
4. **Sends login attempt** → Honeypot captures credentials/payload
5. **Connection logged** → Database + File + Dashboard update
6. **Real-time alert** → Your browser shows the attack instantly via WebSocket

### Multi-threaded Architecture

```
Main Thread (Flask App)
    ├─→ Port 22 Listener Thread
    │      └─→ Connection Handler Thread 1
    │      └─→ Connection Handler Thread 2
    ├─→ Port 23 Listener Thread
    │      └─→ Connection Handler Thread 3
    ├─→ Port 80 Listener Thread
    └─→ ... (more ports)
```

Each port has its own listening thread, and each incoming connection is spawned in a separate thread. This prevents blocking and allows handling thousands of simultaneous connections.

## Why This Design?

### Socket Programming vs. Libraries
- Direct socket control for precise monitoring
- Can simulate any service behavior
- Low overhead, high performance
- Complete control over responses

### Flask + SocketIO
- Easy web interface development
- Real-time updates without polling
- RESTful API for programmatic access
- Cross-platform compatibility

### SQLite
- No separate database server needed
- Perfect for single-machine deployment
- Fast queries for analytics
- Lightweight and portable

### Threading
- Handle multiple attackers simultaneously
- Non-blocking I/O operations
- Scalable to hundreds of connections
- Efficient resource utilization

## Security Considerations

- Honeypot runs in isolated environment
- No actual vulnerabilities - just simulated responses
- Doesn't execute attacker code
- Logs everything for forensic analysis
- Safe for research and educational purposes

## Default Ports

The honeypot listens on the following ports by default:
- **22** (SSH) - Simulates OpenSSH server
- **23** (Telnet) - Simulates Telnet service
- **80** (HTTP) - Simulates Apache web server
- **443** (HTTPS) - Simulates nginx web server
- **3306** (MySQL) - Simulates MySQL database
- **8080** (HTTP-Alt) - Simulates Tomcat server

## Dashboard Features

### Main Dashboard
- Control panel to start/stop honeypot
- Real-time statistics cards (Total Attacks, Unique IPs, Port Scans, Connections)
- Recent attacks table with source IP, port, service, and type
- Attack timeline chart showing patterns over time

### Live Monitor
- Real-time attack feed with WebSocket updates
- Connection status indicator
- Attack source distribution chart
- Color-coded alerts (info, warning, danger)

### Analytics
- Attacks by port (bar chart)
- Attack types distribution (pie chart)
- Hourly attack pattern (line chart)
- Top attackers list
- Built-in network scanner interface

## Potential Enhancements

You can extend this system with:
- **AI/ML** for attack pattern recognition and anomaly detection
- **GeoIP lookup** to map attacker locations on a world map
- **Email/SMS alerts** for critical attacks
- **Integration with SIEM** systems (Splunk, ELK Stack)
- **Docker deployment** for complete isolation
- **Distributed honeypots** across multiple machines
- **Advanced payloads** to deceive sophisticated attackers
- **Automatic IP blocking** via firewall integration
- **Threat intelligence** integration (VirusTotal, AbuseIPDB)
- **Export reports** in PDF/CSV formats

## Technical Implementation Details

### Connection Handling
```python
# Each port listener
sock.bind(('0.0.0.0', port))  # Listen on all interfaces
sock.listen(5)                 # Queue up to 5 connections
sock.settimeout(1)             # Non-blocking with timeout

# Each connection
thread = threading.Thread(target=handle_connection, daemon=True)
```

### Attack Detection
```python
attack_data = {
    'type': 'connection_attempt',
    'source_ip': address[0],
    'source_port': address[1],
    'target_port': port,
    'service': get_service_name(port),
    'timestamp': datetime.now().isoformat(),
    'payload': received_data[:500]  # First 500 bytes
}
```

### Real-time Updates
```python
# Server side
socketio.emit('new_attack', attack_data)

// Client side
socket.on('new_attack', function(data) {
    updateDashboard(data);
    showNotification(data);
});
```

## Requirements

- **Python 3.8+** (Tested with Python 3.13)
- **Windows 10/11** (or Linux/macOS with minor modifications)
- **Administrator privileges** (for binding to low ports < 1024)
- **Modern web browser** (Chrome, Firefox, Edge)
- **Network access** (for incoming connections)

## Troubleshooting

### Port Already in Use
If you get "Address already in use" error:
```powershell
# Find process using the port
netstat -ano | findstr :22

# Kill the process
taskkill /PID <process_id> /F
```

### Permission Denied (Ports < 1024)
Run PowerShell as Administrator to bind to privileged ports (22, 23, 80, 443).

### No Attacks Detected
- Ensure firewall allows incoming connections
- Check if ports are accessible from external network
- Try testing locally: `telnet localhost 22`

## Testing the Honeypot

### Local Testing
```powershell
# Test SSH port
telnet localhost 22

# Test HTTP port
curl http://localhost:80

# Test with Nmap
nmap -p 22,23,80,443,3306,8080 localhost
```

### Network Testing
Replace `localhost` with your machine's IP address and test from another device on the network.

## Security Note

⚠️ **WARNING**: This is a honeypot system designed for educational and research purposes. 

- Do not use on production systems without proper authorization
- Running a honeypot may attract malicious activity
- Ensure proper network isolation and monitoring
- Review local laws regarding honeypot deployment
- Never connect honeypots to critical infrastructure
- Implement proper access controls and monitoring

## Use Cases

1. **Security Research** - Study attack patterns and methodologies
2. **Network Security Training** - Hands-on cybersecurity education
3. **Threat Intelligence** - Collect data on emerging threats
4. **Penetration Testing** - Simulate vulnerable systems for testing
5. **Incident Response Training** - Practice detecting and responding to attacks

## License

For educational and research purposes only. Not intended for production use.

## Credits

Built with ❤️ for cybersecurity education and research.

## Detection Types Implemented

Sentinel includes heuristics and pattern matching to classify common attack vectors and assign severity levels. Current detections include:

- connection_attempt — basic TCP connect to a simulated port (low)
- brute_force — repeated credential attempts on SSH/Telnet ports (medium)
- web_scan — repeated or automated HTTP probes (low)
- sql_injection — detection of SQL keywords and typical payloads in URLs or POST bodies (high)
- xss_attempt — detection of script tags or suspicious HTML in parameters (high)
- directory_traversal — use of `..` sequences in paths (high)
- command_injection — detection of shell metacharacters and common patterns (high)
- database_probe — connection attempts to MySQL-like ports (medium)
- trap_access — access of trap endpoints like `/admin`, `/.env`, `/phpmyadmin` (high)

These classifications are produced by the analysis engine and saved in `attacks.type` and `attacks.severity`.

## How to Test Each Attack Vector

Run these commands from another machine on the same network (replace `TARGET` with your honeypot IP, e.g., `192.168.100.9`):

- SSH/Telnet brute-force (simulate multiple attempts):
  - Attempt simple connection: `nc TARGET 2222` or `telnet TARGET 2323`
  - Simulate password attempt stream:
    ```powershell
    for ($i=0; $i -lt 10; $i++) { echo "root:password$i" | nc TARGET 2222 }
    ```

- SQL Injection (HTTP):
  ```bash
  curl "http://TARGET:8000/?id=1' OR '1'='1"
  ```

- Cross-Site Scripting (XSS):
  ```bash
  curl "http://TARGET:8000/?q=<script>alert(1)</script>"
  ```

- Directory Traversal:
  ```bash
  curl "http://TARGET:8000/../../etc/passwd"
  ```

- Command Injection (HTTP payload):
  ```bash
  curl "http://TARGET:8000/?cmd=;cat /etc/passwd"
  ```

- Port Scanning (Nmap):
  ```bash
  nmap -sV -p 2222,2323,8000,8443,33060,8080,2121 TARGET
  ```

- Trap Endpoints (high severity):
  ```bash
  curl http://TARGET:5000/admin
  curl http://TARGET:5000/.env
  curl http://TARGET:5000/phpmyadmin
  ```

After running tests check the admin portal (`/admin_portal`) or tail `logs/honeypot.log` to see entries and severities.

## IP Enrichment & VPN Detection (details)

The logger performs lightweight enrichment via `ipinfo.io` for ASN, organization and country. It uses a small heuristic to mark hosts likely owned by cloud providers or VPN/hosting companies. This helps flag suspicious sources but is not definitive.

To enable improved detection you can:

1. Provide an `IPINFO_TOKEN` environment variable for higher-rate ipinfo access:

```powershell
setx IPINFO_TOKEN "your_token_here"
```

2. Integrate MaxMind GeoIP2 by installing `geoip2` and downloading the GeoLite2 database (requires updating `logger_module.py` to use it).

3. Use AbuseIPDB or other reputation services (requires API key) for stronger VPN/proxy detection.

## Auto-blocking (optional)

Auto-blocking is not enabled by default. If you opt in in the future, Sentinel can call Windows PowerShell to add firewall rules for 'critical' IPs. That action requires Administrator privileges and explicit opt-in.

Example PowerShell command (admin):

```powershell
New-NetFirewallRule -DisplayName "SentinelBlock_<IP>" -Direction Inbound -RemoteAddress <IP> -Action Block
```

## README Updates

This README includes quick test commands, detection types, enrichment notes, and recommended next steps for production hardening and VPN/proxy detection.
