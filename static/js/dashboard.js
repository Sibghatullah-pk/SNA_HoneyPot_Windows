// Socket.IO connection
const socket = io();

// Chart configuration
let attackChart;
let chartData = {
    labels: [],
    data: []
};

// Initialize
document.addEventListener('DOMContentLoaded', function () {
    initializeChart();
    setupEventListeners();
    loadStats();
    loadAttackInfo();

    // Refresh stats every 3 seconds
    setInterval(loadStats, 3000);
    // Refresh attack info every 10 seconds
    setInterval(loadAttackInfo, 10000);
});

// Event Listeners
function setupEventListeners() {
    document.getElementById('startBtn').addEventListener('click', startHoneypot);
    document.getElementById('stopBtn').addEventListener('click', stopHoneypot);

    // Clear stats button
    const clearBtn = document.getElementById('clearBtn');
    if (clearBtn) {
        clearBtn.addEventListener('click', clearStats);
    }

    socket.on('connect', function () {
        console.log('Connected to server');
        document.getElementById('status').style.background = '#00c851';
    });

    socket.on('disconnect', function () {
        console.log('Disconnected from server');
    });

    socket.on('new_attack', function (data) {
        console.log('New attack received:', data);
        addAttackToTable(data);
        updateStats();
        updateChart();
        // Show notification
        showAttackNotification(data);
    });
}

// Load Attack Info for Team
function loadAttackInfo() {
    fetch('/api/attack_info')
        .then(response => response.json())
        .then(data => {
            const targetIPElement = document.getElementById('targetIP');
            if (targetIPElement && data.target_ips) {
                targetIPElement.textContent = data.target_ips.join(' or ');
            }
            // Update status
            if (data.honeypot_status === 'running') {
                document.getElementById('status').textContent = 'Running';
                document.getElementById('status').style.background = '#00c851';
            }
        })
        .catch(error => console.error('Error loading attack info:', error));
}

// Show attack notification
function showAttackNotification(attack) {
    // Create notification element
    const notification = document.createElement('div');
    notification.className = 'attack-notification';
    notification.style.cssText = `
        position: fixed;
        top: 80px;
        right: 20px;
        background: linear-gradient(135deg, #ff416c 0%, #ff4b2b 100%);
        color: white;
        padding: 15px 20px;
        border-radius: 10px;
        box-shadow: 0 4px 15px rgba(255, 65, 108, 0.4);
        z-index: 9999;
        animation: slideIn 0.3s ease-out;
        max-width: 350px;
    `;
    notification.innerHTML = `
        <strong>🚨 Attack Detected!</strong><br>
        <small>From: ${attack.source_ip}:${attack.source_port || 'N/A'}<br>
        Port: ${attack.target_port} (${attack.service || 'Unknown'})<br>
        Type: ${attack.type || 'connection_attempt'}</small>
    `;

    document.body.appendChild(notification);

    // Remove after 5 seconds
    setTimeout(() => {
        notification.style.animation = 'slideOut 0.3s ease-in';
        setTimeout(() => notification.remove(), 300);
    }, 5000);
}

// Clear Stats
function clearStats() {
    if (!confirm('Clear all attack statistics?')) return;

    fetch('/api/clear_stats', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' }
    })
        .then(response => response.json())
        .then(data => {
            if (data.status === 'success') {
                // Reset UI
                document.getElementById('totalAttacks').textContent = '0';
                document.getElementById('uniqueIps').textContent = '0';
                document.getElementById('portScans').textContent = '0';
                document.getElementById('connections').textContent = '0';
                document.getElementById('attacksBody').innerHTML = '<tr><td colspan="5" class="no-data">No attacks detected yet</td></tr>';
                chartData.labels = [];
                chartData.data = [];
                attackChart.update();
                alert('Statistics cleared!');
            }
        })
        .catch(error => alert('Error clearing stats: ' + error));
}

// Start Honeypot
function startHoneypot() {
    console.log('Starting honeypot...');
    const startBtn = document.getElementById('startBtn');
    startBtn.disabled = true;
    startBtn.textContent = 'Starting...';

    fetch('/api/start_honeypot', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({})
    })
        .then(response => {
            console.log('Response status:', response.status);
            return response.json();
        })
        .then(data => {
            console.log('Response data:', data);
            if (data.status === 'success' || data.status === 'info') {
                document.getElementById('status').textContent = 'Running';
                document.getElementById('status').style.background = '#00c851';
                alert(data.message || 'Honeypot started successfully!');
            } else {
                alert('Error: ' + data.message);
            }
        })
        .catch(error => {
            console.error('Error starting honeypot:', error);
            alert('Failed to start honeypot: ' + error.message);
        })
        .finally(() => {
            startBtn.disabled = false;
            startBtn.textContent = 'Start Honeypot';
        });
}

// Stop Honeypot
function stopHoneypot() {
    console.log('Stopping honeypot...');
    const stopBtn = document.getElementById('stopBtn');
    stopBtn.disabled = true;
    stopBtn.textContent = 'Stopping...';

    fetch('/api/stop_honeypot', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({})
    })
        .then(response => {
            console.log('Response status:', response.status);
            return response.json();
        })
        .then(data => {
            console.log('Response data:', data);
            if (data.status === 'success' || data.status === 'info') {
                document.getElementById('status').textContent = 'Stopped';
                document.getElementById('status').style.background = '#333';
                alert(data.message || 'Honeypot stopped successfully!');
            } else {
                alert('Error: ' + data.message);
            }
        })
        .catch(error => {
            console.error('Error stopping honeypot:', error);
            alert('Failed to stop honeypot: ' + error.message);
        })
        .finally(() => {
            stopBtn.disabled = false;
            stopBtn.textContent = 'Stop Honeypot';
        });
}

// Load Statistics
function loadStats() {
    fetch('/api/stats')
        .then(response => response.json())
        .then(data => {
            document.getElementById('totalAttacks').textContent = data.total_attacks || 0;
            document.getElementById('uniqueIps').textContent = data.unique_ips || 0;
            document.getElementById('portScans').textContent = data.port_scans || 0;
            document.getElementById('connections').textContent = data.connection_attempts || 0;

            if (data.recent_attacks && data.recent_attacks.length > 0) {
                updateAttacksTable(data.recent_attacks);
            }
        })
        .catch(error => {
            console.error('Error loading stats:', error);
        });
}

// Update Attacks Table
function updateAttacksTable(attacks) {
    const tbody = document.getElementById('attacksBody');
    tbody.innerHTML = '';

    attacks.slice(-20).reverse().forEach(attack => {
        addAttackToTable(attack);
    });
}

function addAttackToTable(attack) {
    const tbody = document.getElementById('attacksBody');

    // Remove "no data" message if present
    if (tbody.querySelector('.no-data')) {
        tbody.innerHTML = '';
    }

    const row = tbody.insertRow(0);
    row.innerHTML = `
        <td>${attack.timestamp || 'N/A'}</td>
        <td>${attack.source_ip || 'Unknown'}</td>
        <td>${attack.target_port || 'N/A'}</td>
        <td>${attack.service || 'Unknown'}</td>
        <td><span class="badge">${attack.type || 'Unknown'}</span></td>
    `;

    // Keep only last 20 rows
    while (tbody.rows.length > 20) {
        tbody.deleteRow(tbody.rows.length - 1);
    }
}

// Initialize Chart
function initializeChart() {
    const ctx = document.getElementById('attackChart').getContext('2d');
    attackChart = new Chart(ctx, {
        type: 'line',
        data: {
            labels: chartData.labels,
            datasets: [{
                label: 'Attacks Over Time',
                data: chartData.data,
                borderColor: '#00d9ff',
                backgroundColor: 'rgba(0, 217, 255, 0.1)',
                tension: 0.4,
                fill: true
            }]
        },
        options: {
            responsive: true,
            maintainAspectRatio: false,
            scales: {
                y: {
                    beginAtZero: true,
                    ticks: {
                        color: '#e0e0e0'
                    }
                },
                x: {
                    ticks: {
                        color: '#e0e0e0'
                    }
                }
            },
            plugins: {
                legend: {
                    labels: {
                        color: '#e0e0e0'
                    }
                }
            }
        }
    });
}

// Update Chart
function updateChart() {
    const now = new Date().toLocaleTimeString();
    chartData.labels.push(now);
    chartData.data.push((chartData.data[chartData.data.length - 1] || 0) + 1);

    // Keep only last 20 data points
    if (chartData.labels.length > 20) {
        chartData.labels.shift();
        chartData.data.shift();
    }

    attackChart.update();
}

function updateStats() {
    loadStats();
}
