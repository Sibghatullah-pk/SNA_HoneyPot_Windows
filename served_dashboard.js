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
    // signal that dashboard JS loaded and attached handlers
    try { window.__dashboard_js_loaded = true } catch (e) { }
});

// Client-side pagination state
let attacksList = [];
let attacksPage = 1;
const attacksPerPage = 10;

function renderAttacksPage(page) {
    const tbody = document.getElementById('attacksBody');
    tbody.innerHTML = '';
    if (!attacksList || attacksList.length === 0) {
        tbody.innerHTML = `<tr><td colspan="5" class="no-data" data-label="Info">No attacks detected yet</td></tr>`;
        document.getElementById('attacksPager').innerHTML = '';
        return;
    }
    const start = (page - 1) * attacksPerPage;
    const slice = attacksList.slice(start, start + attacksPerPage);
    slice.forEach(attack => {
        const row = document.createElement('tr');
        row.innerHTML = `
            <td data-label="Time">${attack.timestamp || 'N/A'}</td>
            <td data-label="Source IP"><span class="ip-text">${attack.source_ip || 'Unknown'}</span> <button class="copy-btn" data-clip="${attack.source_ip}">Copy</button></td>
            <td data-label="Target Port">${attack.target_port || 'N/A'}</td>
            <td data-label="Service">${attack.service || 'Unknown'}</td>
            <td data-label="Type"><span class="badge ${attack.type || ''}">${attack.type || 'Unknown'}</span></td>
        `;
        tbody.appendChild(row);
    });
    renderPager();
    // attach copy handlers
    document.querySelectorAll('.copy-btn[data-clip]').forEach(b => {
        b.addEventListener('click', () => { navigator.clipboard.writeText(b.getAttribute('data-clip') || ''); b.textContent = 'Copied'; setTimeout(() => b.textContent = 'Copy', 900) })
    });
}

function renderPager() {
    const total = attacksList.length;
    const pages = Math.max(1, Math.ceil(total / attacksPerPage));
    const holder = document.getElementById('attacksPager');
    holder.innerHTML = '';
    for (let i = 1; i <= pages; i++) {
        const btn = document.createElement('button');
        btn.textContent = i;
        if (i === attacksPage) btn.classList.add('active');
        btn.addEventListener('click', () => { attacksPage = i; renderAttacksPage(i); });
        holder.appendChild(btn);
    }
}

// Event Listeners
function setupEventListeners() {
    document.getElementById('startBtn').addEventListener('click', startHoneypot);
    document.getElementById('stopBtn').addEventListener('click', stopHoneypot);

    // Clear stats button
    const clearBtn = document.getElementById('clearBtn');
    if (clearBtn) {
        clearBtn.addEventListener('click', clearStats);
    }
    // Copy attack commands
    const copyCmdBtn = document.getElementById('copyCommands');
    if (copyCmdBtn) {
        copyCmdBtn.addEventListener('click', () => {
            const txt = document.getElementById('attackCommands').innerText.trim();
            navigator.clipboard.writeText(txt || '');
            copyCmdBtn.textContent = 'Copied';
            setTimeout(() => copyCmdBtn.textContent = 'Copy', 900);
        });
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

    // optimistic UI update
    try {
        const statusEl = document.getElementById('status');
        if (statusEl) { statusEl.textContent = 'Starting'; statusEl.style.background = '#ffc857'; }
    } catch (e) { console.warn('Status element update failed', e) }

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
                const statusEl = document.getElementById('status');
                if (statusEl) { statusEl.textContent = 'Running'; statusEl.style.background = '#00c851'; }
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

    // optimistic UI update
    try {
        const statusEl = document.getElementById('status');
        if (statusEl) { statusEl.textContent = 'Stopping'; statusEl.style.background = '#ff9fa8'; }
    } catch (e) { console.warn('Status element update failed', e) }

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
                const statusEl = document.getElementById('status');
                if (statusEl) { statusEl.textContent = 'Stopped'; statusEl.style.background = '#333'; }
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
            // Animate counters for nicer UX
            animateCounter(document.getElementById('totalAttacks'), data.total_attacks || 0);
            animateCounter(document.getElementById('uniqueIps'), data.unique_ips || 0);
            animateCounter(document.getElementById('portScans'), data.port_scans || 0);
            animateCounter(document.getElementById('connections'), data.connection_attempts || 0);

            if (data.recent_attacks && data.recent_attacks.length > 0) {
                // update local list and render page 1
                attacksList = data.recent_attacks.slice().reverse(); // most recent first
                attacksPage = 1;
                renderAttacksPage(attacksPage);
            } else {
                attacksList = [];
                renderAttacksPage(1);
            }
        })
        .catch(error => {
            console.error('Error loading stats:', error);
        });
}

// Animate numeric change inside an element
function animateCounter(el, target) {
    if (!el) return;
    const start = parseInt(el.textContent.replace(/[^0-9]/g, '')) || 0;
    const end = parseInt(target) || 0;
    if (start === end) { el.textContent = String(end); return; }
    const duration = 600;
    const startTime = performance.now();
    el.classList.add('animate');
    function step(now) {
        const t = Math.min(1, (now - startTime) / duration);
        const value = Math.floor(start + (end - start) * easeOutCubic(t));
        el.textContent = value;
        if (t < 1) requestAnimationFrame(step);
        else { el.textContent = String(end); el.classList.remove('animate'); }
    }
    requestAnimationFrame(step);
}

function easeOutCubic(t) { return 1 - Math.pow(1 - t, 3); }

// Update Attacks Table
function updateAttacksTable(attacks) {
    // kept for backward compatibility — replace by pagination
    attacksList = attacks.slice().reverse();
    attacksPage = 1;
    renderAttacksPage(attacksPage);
}

function addAttackToTable(attack) {
    // When real-time attack arrives, prepend to the list and refresh current page
    attacksList.unshift(attack);
    if (attacksList.length > 1000) attacksList.pop();
    renderAttacksPage(attacksPage);
}

// Initialize Chart
function initializeChart() {
    const ctx = document.getElementById('attackChart').getContext('2d');
    // read CSS variables for theme-aware colors
    const css = getComputedStyle(document.documentElement);
    const accent = css.getPropertyValue('--accent')?.trim() || '#00d9ff';
    const chartGrid = css.getPropertyValue('--chart-grid')?.trim() || 'rgba(255,255,255,0.06)';
    const chartText = css.getPropertyValue('--chart-text')?.trim() || 'rgba(230,247,255,0.9)';

    // create gradient fill for the dataset
    const gradient = ctx.createLinearGradient(0, 0, 0, ctx.canvas.height);
    // try parse accent to RGBA fallback
    gradient.addColorStop(0, accent.replace(')', ', 0.18)').replace('rgb', 'rgba'));
    gradient.addColorStop(1, accent.replace(')', ', 0.02)').replace('rgb', 'rgba'));

    // plugin to draw a neon glow line behind the dataset
    const neonPlugin = {
        id: 'neonGlow',
        afterDraw: (chart) => {
            const dataset = chart.data.datasets[0];
            const meta = chart.getDatasetMeta(0);
            if (!meta || !meta.data) return;
            const points = meta.data;
            const ctx2 = chart.ctx;
            ctx2.save();
            ctx2.beginPath();
            ctx2.lineWidth = 4;
            ctx2.strokeStyle = accent;
            ctx2.shadowBlur = 18;
            ctx2.shadowColor = accent;
            for (let i = 0; i < points.length; i++) {
                const p = points[i].getProps ? points[i].getProps(['x', 'y'], true) : { x: points[i].x, y: points[i].y };
                if (i === 0) ctx2.moveTo(p.x, p.y);
                else ctx2.lineTo(p.x, p.y);
            }
            ctx2.stroke();
            ctx2.restore();
        }
    };

    // helper: convert common accent formats to rgba with alpha
    function parseAccentToRgba(accentStr, alpha) {
        if (!accentStr) return `rgba(0,217,255,${alpha})`;
        accentStr = accentStr.trim();
        if (accentStr.startsWith('#')) {
            let c = accentStr.slice(1);
            if (c.length === 3) c = c.split('').map(ch => ch + ch).join('');
            const num = parseInt(c, 16);
            const r = (num >> 16) & 255;
            const g = (num >> 8) & 255;
            const b = num & 255;
            return `rgba(${r}, ${g}, ${b}, ${alpha})`;
        }
        if (accentStr.startsWith('rgb(')) return accentStr.replace('rgb(', 'rgba(').replace(')', `, ${alpha})`);
        if (accentStr.startsWith('rgba(')) return accentStr.replace(/rgba\(([^)]+)\)/, function (m, grp) { const parts = grp.split(','); parts[3] = String(alpha); return `rgba(${parts.join(',')})`; });
        return accentStr;
    }

    // build gradient safely
    const gradientSafe = ctx.createLinearGradient(0, 0, 0, ctx.canvas.height);
    gradientSafe.addColorStop(0, parseAccentToRgba(accent, 0.18));
    gradientSafe.addColorStop(1, parseAccentToRgba(accent, 0.02));

    attackChart = new Chart(ctx, {
        type: 'line',
        data: {
            labels: chartData.labels,
            datasets: [{
                label: 'Attacks Over Time',
                data: chartData.data,
                borderColor: accent,
                backgroundColor: gradientSafe,
                tension: 0.35,
                fill: true,
                pointRadius: 3,
                pointBackgroundColor: accent
            }]
        },
        options: {
            responsive: true,
            maintainAspectRatio: false,
            interaction: { mode: 'nearest', intersect: false },
            hover: { mode: 'nearest', intersect: false },
            scales: {
                y: {
                    beginAtZero: true,
                    grid: { color: chartGrid },
                    ticks: { color: chartText }
                },
                x: {
                    grid: { color: chartGrid },
                    ticks: { color: chartText }
                }
            },
            plugins: {
                legend: {
                    labels: { color: chartText }
                },
                tooltip: {
                    titleColor: chartText,
                    bodyColor: chartText,
                    backgroundColor: 'rgba(0,0,0,0.7)'
                }
            }
        },
        plugins: [neonPlugin]
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

// UI debug helper: enable by adding ?ui_debug=1 to URL or set localStorage.uiDebug = '1'
(function () {
    try {
        const params = new URLSearchParams(window.location.search);
        const enabled = params.get('ui_debug') === '1' || localStorage.getItem('uiDebug') === '1';
        if (!enabled) return;
        console.info('UI debug: click logger enabled');
        document.addEventListener('click', function (e) {
            const t = e.target;
            console.info('UI debug click ->', { tag: t.tagName, id: t.id, class: t.className, rect: t.getBoundingClientRect() });
            // flash outline on target
            const outline = document.createElement('div');
            outline.style.position = 'fixed'; outline.style.left = t.getBoundingClientRect().left + 'px'; outline.style.top = t.getBoundingClientRect().top + 'px';
            outline.style.width = t.getBoundingClientRect().width + 'px'; outline.style.height = t.getBoundingClientRect().height + 'px';
            outline.style.border = '2px solid rgba(255,0,128,0.9)'; outline.style.zIndex = 99999; outline.style.pointerEvents = 'none';
            document.body.appendChild(outline);
            setTimeout(() => outline.remove(), 900);
        }, true);
    } catch (e) { console.warn('UI debug helper error', e) }
})();
