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

    // Refresh stats every 5 seconds
    setInterval(loadStats, 5000);
});

// Event Listeners
function setupEventListeners() {
    document.getElementById('startBtn').addEventListener('click', startHoneypot);
    document.getElementById('stopBtn').addEventListener('click', stopHoneypot);

    socket.on('connect', function () {
        console.log('Connected to server');
    });

    socket.on('new_attack', function (data) {
        addAttackToTable(data);
        updateStats();
        updateChart();
    });
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
