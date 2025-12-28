# 🛡️ Sentinel Honeypot System - Complete Guide

## Quick Start (30 Seconds)

& 'S:\SNA\SNA_HoneyPot_Windows\venv\Scripts\python.exe' app.py
```powershell
# 1. Open PowerShell and navigate to project
cd "S:\SNA\SNA_HoneyPot_Windows"

# 2. Activate virtual environment
.\venv\Scripts\Activate.ps1

# 3. Run the application
python app.py

# 4. Open browser
# Go to: http://localhost:5000
```

---

## 📊 System Architecture

```
┌─────────────────────────────────────────────────────────────────┐
│                    SENTINEL HONEYPOT SYSTEM                      │
├─────────────────────────────────────────────────────────────────┤
│                                                                  │
│  ┌──────────────┐    ┌──────────────┐    ┌──────────────────┐  │
│  │   Browser    │◄──►│  Flask App   │◄──►│  SQLite Database │  │
│  │  Dashboard   │    │  (Port 5000) │    │  (honeypot.db)   │  │
│  └──────────────┘    └──────┬───────┘    └──────────────────┘  │
│         ▲                   │                                   │
│         │            WebSocket                                  │
│         │           (Real-time)                                 │
│         │                   │                                   │
│         ▼                   ▼                                   │
│  ┌──────────────────────────────────────────────────────────┐  │
│  │                   HONEYPOT SERVER                         │  │
│  │  ┌────────┐ ┌────────┐ ┌────────┐ ┌────────┐ ┌────────┐ │  │
│  │  │Port    │ │Port    │ │Port    │ │Port    │ │Port    │ │  │
│  │  │2222    │ │2323    │ │8000    │ │8443    │ │33060   │ │  │
│  │  │(SSH)   │ │(Telnet)│ │(HTTP)  │ │(HTTPS) │ │(MySQL) │ │  │
│  │  └────────┘ └────────┘ └────────┘ └────────┘ └────────┘ │  │
│  └──────────────────────────────────────────────────────────┘  │
│                            ▲                                    │
│                            │                                    │
│                    ATTACKERS CONNECT HERE                       │
│                                                                  │
└─────────────────────────────────────────────────────────────────┘
```

---

## 🎯 For Attack Team - How to Attack

### Step 1: Get Target Information
After starting the honeypot, the dashboard shows:
- **Target IP**: Your machine's IP address
- **Open Ports**: List of honeypot ports

### Step 2: Attack Commands

```bash
# Replace <TARGET_IP> with the IP shown on dashboard

# 1. Port Scan with Nmap
nmap -sV -p 2222,2323,8000,8443,33060,8080,2121 <TARGET_IP>

# 2. Connect to SSH (Port 2222)
ssh root@<TARGET_IP> -p 2222
# Try passwords: admin, root, password, 123456
curl.exe -I -X HEAD "http://127.0.0.1:5000/admin" -o NUL -w "TRAP_HEAD:%{http_code}\n"; curl.exe -s "http://127.0.0.1:8000/?q=<script>alert(1)</script>" -o NUL -w "XSS_8000:%{http_code}\n"; curl.exe -s "http://127.0.0.1:8080/?q=test" -o NUL -w "ATTACK_8080:%{http_code}\n"; curl.exe -k -s "https://127.0.0.1:8443/?q=test" -o NUL -w "ATTACK_8443:%{http_code}\n"; curl.exe -s http://127.0.0.1:5000/api/stats -o stats_after_attack.json; type stats_after_attack.json; echo; Get-Content -Path .\logs\honeypot.log -Tail 20
# 3. Connect to Telnet (Port 2323)
telnet <TARGET_IP> 2323
# Enter any username/password

# 4. HTTP Request (Port 8000)
curl http://<TARGET_IP>:8000
curl http://<TARGET_IP>:8000/admin
curl http://<TARGET_IP>:8000/wp-admin

# 5. SQL Injection Test (Port 8000)
curl "http://<TARGET_IP>:8000/?id=1' OR '1'='1"

# 6. XSS Test
curl "http://<TARGET_IP>:8000/?q=<script>alert(1)</script>"

# 7. Directory Traversal
curl "http://<TARGET_IP>:8000/../../etc/passwd"

# 8. MySQL Connection (Port 33060)
mysql -h <TARGET_IP> -P 33060 -u root -p

# 9. Netcat Connection
nc <TARGET_IP> 2222
nc <TARGET_IP> 2323

# 10. FTP Connection (Port 2121)
ftp <TARGET_IP> 2121

# 11. Trap Endpoints (triggers high-severity alerts)
curl http://<TARGET_IP>:5000/admin
curl http://<TARGET_IP>:5000/wp-admin
curl http://<TARGET_IP>:5000/.env
curl http://<TARGET_IP>:5000/phpmyadmin
```

### Step 3: Watch the Dashboard
- Go to **Live Monitor** tab to see attacks in real-time
- Check **Analytics** tab for statistics

---

## 📁 Project Structure

```
SNA_HoneyPot_Windows/
│
├── app.py                 # Main Flask application
├── honeypot_server.py     # Multi-port honeypot listener
├── logger_module.py       # Database & logging module
├── network_scanner.py     # Network scanning utility
├── requirements.txt       # Python dependencies
├── GUIDE.md              # This file
│
├── database/
│   └── honeypot.db       # SQLite database (auto-created)
│
├── logs/
│   └── honeypot.log      # JSON log file (auto-created)
│
├── static/
│   ├── css/
│   │   └── style.css     # Dashboard styles
│   └── js/
│       └── dashboard.js  # Frontend JavaScript
│
├── templates/
│   ├── base.html         # Base template
│   ├── index.html        # Main dashboard
│   ├── live.html         # Live monitor
│   └── analytics.html    # Analytics page
│
└── venv/                 # Python virtual environment
```

---

## 🔌 API Endpoints

### Dashboard Routes
| Endpoint | Method | Description |
|----------|--------|-------------|
| `/` | GET | Main dashboard |
| `/live` | GET | Live attack monitor |
| `/analytics` | GET | Charts & statistics |

### API Routes
| Endpoint | Method | Description |
|----------|--------|-------------|
| `/api/stats` | GET | Get real-time statistics |
| `/api/start_honeypot` | POST | Start honeypot server |
| `/api/stop_honeypot` | POST | Stop honeypot server |
| `/api/attack_info` | GET | Get target info for attacks |
| `/api/clear_stats` | POST | Clear all data |
| `/api/scan_network` | POST | Scan a network/host |
| `/api/export/json` | GET | Export data as JSON |
| `/api/export/csv` | GET | Export data as CSV |
| `/api/alerts` | GET | Get security alerts |
| `/api/database/attacks` | GET | Get all attacks from DB |

### Trap Endpoints (Trigger Alerts)
| Endpoint | Purpose |
|----------|---------|
| `/admin` | Admin panel trap |
| `/wp-admin` | WordPress trap |
| `/phpmyadmin` | phpMyAdmin trap |
| `/.env` | Environment file trap |
| `/config.php` | Config file trap |

---

## 🗄️ Database Schema

### attacks table
```sql
CREATE TABLE attacks (
    id INTEGER PRIMARY KEY,
    timestamp TEXT,
    type TEXT,           -- connection_attempt, sql_injection, xss_attempt, etc.
    source_ip TEXT,
    source_port INTEGER,
    target_port INTEGER,
    simulated_port INTEGER,
    service TEXT,        -- SSH, HTTP, MySQL, etc.
    payload TEXT,        -- Captured data
    payload_size INTEGER,
    severity TEXT,       -- low, medium, high
    user_agent TEXT,
    connection_id INTEGER,
    created_at TEXT
);
```

### ip_tracking table
```sql
CREATE TABLE ip_tracking (
    id INTEGER PRIMARY KEY,
    ip_address TEXT UNIQUE,
    first_seen TEXT,
    last_seen TEXT,
    total_attacks INTEGER,
    threat_level TEXT    -- low, medium, high, critical
);
```

### alerts table
```sql
CREATE TABLE alerts (
    id INTEGER PRIMARY KEY,
    timestamp TEXT,
    alert_type TEXT,
    source_ip TEXT,
    message TEXT,
    severity TEXT,
    is_acknowledged INTEGER,
    attack_id INTEGER
);
```

---

## 🔧 Configuration

### Honeypot Ports (No Admin Required)
| Port | Service | Simulates |
|------|---------|-----------|
| 2222 | SSH | Port 22 |
| 2323 | Telnet | Port 23 |
| 8000 | HTTP | Port 80 |
| 8443 | HTTPS | Port 443 |
| 33060 | MySQL | Port 3306 |
| 8080 | HTTP Proxy | Tomcat |
| 2121 | FTP | Port 21 |

### Admin Ports (Require Administrator)
| Port | Service |
|------|---------|
| 22 | SSH |
| 23 | Telnet |
| 80 | HTTP |
| 443 | HTTPS |
| 3306 | MySQL |

---

## 🚀 Running the System

### Method 1: Standard (High Ports)
```powershell
# No admin required
.\venv\Scripts\Activate.ps1
python app.py
```

### Method 2: Low Ports (Admin Required)
```powershell
# Run PowerShell as Administrator
.\venv\Scripts\Activate.ps1
python app.py
# Then modify start request to use low ports
```

### Method 3: Background Service
```powershell
# Run in background
Start-Process python -ArgumentList "app.py" -WindowStyle Hidden
```

---

## 📈 Attack Types Detected

| Type | Description | Severity |
|------|-------------|----------|
| `connection_attempt` | Basic connection | Low |
| `brute_force` | SSH/Telnet login attempts | Medium |
| `web_scan` | HTTP scanning | Low |
| `sql_injection` | SQL injection attempt | High |
| `xss_attempt` | Cross-site scripting | High |
| `directory_traversal` | Path traversal attack | High |
| `command_injection` | OS command injection | High |
| `database_probe` | MySQL/DB scanning | Medium |
| `trap_access` | Trap endpoint accessed | High |

---

## 🔒 Security Features

1. **Multi-threaded Architecture**: Handle multiple attackers simultaneously
2. **Payload Analysis**: Automatic attack type classification
3. **Severity Detection**: Low/Medium/High based on payload content
4. **IP Tracking**: Track repeat offenders
5. **Alert System**: High-severity alerts for dangerous attacks
6. **Trap Endpoints**: Fake admin pages to catch scanners
7. **Real-time Updates**: WebSocket notifications
8. **Data Export**: JSON/CSV export for analysis
9. **User-Agent Logging**: Track attacker tools

---

## 🐛 Troubleshooting

### Port Already in Use
```powershell
# Find process using port
netstat -ano | findstr :8000

# Kill process
taskkill /PID <PID> /F
```

### Database Locked
```powershell
# Delete and recreate
Remove-Item database/honeypot.db
python app.py
```

### Module Not Found
```powershell
# Reinstall dependencies
pip install flask flask-socketio
```

### Can't Access Dashboard
- Check firewall settings
- Try: http://127.0.0.1:5000
- Check if port 5000 is free

---

## 📋 Summary

| Component | Technology | Purpose |
|-----------|------------|---------|
| Backend | Python + Flask | Web server & API |
| Real-time | Flask-SocketIO | WebSocket updates |
| Database | SQLite | Attack logging |
| Frontend | HTML/CSS/JS | Dashboard UI |
| Charts | Chart.js | Visualization |
| Honeypot | Python Sockets | Port listeners |

### What Happens When Attacked:
1. Attacker connects to honeypot port
2. Honeypot sends fake service banner
3. Attacker sends payload (login, commands, etc.)
4. System analyzes payload for attack type & severity
5. Attack logged to database & JSON file
6. WebSocket sends alert to dashboard
7. Dashboard updates in real-time

---

## 👥 Team Instructions

### Defender (Run Dashboard)
1. Start system: `python app.py`
2. Open: http://localhost:5000
3. Click "Start Honeypot"
4. Watch Live Monitor

### Attacker (Run Attacks)
1. Get target IP from dashboard
2. Use attack commands above
3. Try different techniques
4. Watch dashboard react

### Analyst (Review Data)
1. Go to Analytics tab
2. Check attack patterns
3. Export data (JSON/CSV)
4. Review top attackers

---

**Built for SNA Project - Cybersecurity Education & Research** 🛡️
