document.addEventListener('DOMContentLoaded', function () {
    loadStats();
    loadAttacks();
    loadAlerts();
    loadLogs();
    document.getElementById('exportJson').addEventListener('click', () => window.location = '/api/export/json');
    document.getElementById('exportCsv').addEventListener('click', () => window.location = '/api/export/csv');
    document.getElementById('clearAll').addEventListener('click', clearAllData);
    document.getElementById('reloadLogs').addEventListener('click', loadLogs);

    // Search and filter handlers
    const searchInput = document.getElementById('searchInput');
    const severityFilter = document.getElementById('severityFilter');
    if (searchInput) searchInput.addEventListener('input', debounce(() => { window.adminPage = 1; renderAdminPage(); }, 250));
    if (severityFilter) severityFilter.addEventListener('change', () => { window.adminPage = 1; renderAdminPage(); });
});

// Live socket for real-time admin updates
try {
    const adminSocket = io();
    adminSocket.on('connect', () => { console.log('Admin socket connected'); });
    adminSocket.on('new_attack', (attack) => {
        // Prepend new attack to UI
        const tbody = document.getElementById('attacksBody');
        if (tbody) {
            const tr = document.createElement('tr');
            tr.innerHTML = `<td>${attack.timestamp || new Date().toISOString()}</td><td>${attack.source_ip}</td><td>${attack.target_port}</td><td>${attack.service}</td><td><span class="badge">${attack.type}</span></td><td><button class="btn danger" data-id="${attack.id || ''}">Delete</button></td>`;
            tbody.insertBefore(tr, tbody.firstChild);
            // attach delete handler
            const btn = tr.querySelector('button[data-id]');
            if (btn) { btn.addEventListener('click', () => { const id = btn.getAttribute('data-id'); if (!confirm('Delete attack id ' + id + '?')) return; fetch('/api/admin/delete_attack', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ id: parseInt(id) }) }).then(r => r.json()).then(resp => { if (resp.status === 'success') { tr.remove(); loadStats(); alert('Deleted') } else alert('Failed: ' + resp.message) }) }) }
        }
        loadStats();
    });
} catch (e) { console.warn('Socket init failed for admin:', e) }

function loadStats() {
    fetch('/api/stats').then(r => r.json()).then(data => {
        document.getElementById('totalAttacks').textContent = data.total_attacks || 0;
        document.getElementById('uniqueIps').textContent = data.unique_ips || 0;
        document.getElementById('portScans').textContent = data.port_scans || 0;
        document.getElementById('connections').textContent = data.connection_attempts || 0;
    }).catch(e => console.error(e));
}

function loadAttacks() {
    fetch('/api/database/attacks?limit=200').then(r => r.json()).then(data => {
        const attacks = data.attacks || [];
        if (!attacks.length) {
            document.getElementById('attacksBody').innerHTML = '<tr><td colspan="6" class="small">No attacks</td></tr>';
            const pager = document.getElementById('attacksPager'); if (pager) pager.innerHTML = '';
            return;
        }
        // store and render
        window.adminAttacks = attacks.slice();
        window.adminPage = 1;
        renderAdminPage();
    }).catch(e => { console.error(e); document.getElementById('attacksBody').innerHTML = '<tr><td colspan="6" class="small">Error loading</td></tr>' });
}

function renderAdminPage() {
    const per = 15;
    // apply search and severity filter for deep dive
    let list = (window.adminAttacks || []).slice();
    const q = (document.getElementById('searchInput') && document.getElementById('searchInput').value || '').toLowerCase().trim();
    const sev = (document.getElementById('severityFilter') && document.getElementById('severityFilter').value) || '';
    if (q) { list = list.filter(a => (a.source_ip || '').toLowerCase().includes(q) || (a.type || '').toLowerCase().includes(q) || (a.service || '').toLowerCase().includes(q)); }
    if (sev) { list = list.filter(a => (a.severity || '').toLowerCase() === sev); }
    const page = window.adminPage || 1;
    const tbody = document.getElementById('attacksBody'); tbody.innerHTML = '';
    const start = (page - 1) * per; const slice = list.slice(start, start + per);
    slice.forEach(a => {
        const tr = document.createElement('tr');
        const sevClass = (a.severity || '').toLowerCase() === 'high' ? 'high' : (a.severity || '').toLowerCase() === 'medium' ? 'medium' : 'low';
        tr.innerHTML = `<td>${a.timestamp}</td><td><span class="ip-text">${a.source_ip}</span> <button class="copy-btn" data-clip="${a.source_ip}">Copy</button></td><td>${a.target_port}</td><td>${a.service}</td><td><span class="badge ${sevClass}">${a.type}</span></td><td><button class="action-btn warn" data-id="${a.id}">Delete</button> <button class="action-btn" data-expand="${a.id}">Details</button></td>`;
        tbody.appendChild(tr);
        // hidden detail row
        const detail = document.createElement('tr'); detail.className = 'detail-row'; detail.style.display = 'none'; detail.innerHTML = `<td colspan="6"><pre>${JSON.stringify(a, null, 2)}</pre></td>`; tbody.appendChild(detail);
    });
    // attach delete handlers
    tbody.querySelectorAll('button[data-id]').forEach(b => b.addEventListener('click', (ev) => {
        const id = ev.currentTarget.getAttribute('data-id');
        if (!confirm('Delete attack id ' + id + '?')) return;
        fetch('/api/admin/delete_attack', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ id: parseInt(id) }) })
            .then(r => r.json()).then(resp => { if (resp.status === 'success') { loadAttacks(); loadStats(); alert('Deleted') } else alert('Failed: ' + resp.message) })
    }));
    // attach expand/detail handlers
    tbody.querySelectorAll('button[data-expand]').forEach(b => b.addEventListener('click', (ev) => {
        const id = ev.currentTarget.getAttribute('data-expand');
        const tr = ev.currentTarget.closest('tr');
        const detail = tr.nextElementSibling;
        if (!detail) return;
        if (detail.style.display === 'none') { detail.style.display = 'table-row'; ev.currentTarget.textContent = 'Close'; }
        else { detail.style.display = 'none'; ev.currentTarget.textContent = 'Details'; }
    }));
    // attach copy handlers
    tbody.querySelectorAll('.copy-btn[data-clip]').forEach(b => b.addEventListener('click', () => { navigator.clipboard.writeText(b.getAttribute('data-clip') || ''); b.textContent = 'Copied'; setTimeout(() => b.textContent = 'Copy', 900) }));
    renderAdminPager();
}

// debounce helper
function debounce(fn, wait) { let t; return function (...args) { clearTimeout(t); t = setTimeout(() => fn.apply(this, args), wait); } }

function renderAdminPager() {
    const per = 15; const list = window.adminAttacks || []; const pages = Math.max(1, Math.ceil(list.length / per));
    const holder = document.getElementById('attacksPager'); if (!holder) return; holder.innerHTML = '';
    for (let i = 1; i <= pages; i++) { const btn = document.createElement('button'); btn.textContent = i; if (i === window.adminPage) btn.classList.add('active'); btn.addEventListener('click', () => { window.adminPage = i; renderAdminPage() }); holder.appendChild(btn) }
}

function loadAlerts() {
    fetch('/api/alerts').then(r => r.json()).then(data => {
        const el = document.getElementById('alertsList');
        el.innerHTML = '';
        if (!data.alerts || data.alerts.length === 0) { el.innerHTML = '<div class="small">No alerts</div>'; return }
        data.alerts.forEach(a => {
            const div = document.createElement('div');
            div.style.marginBottom = '8px';
            div.innerHTML = `<div style="display:flex;justify-content:space-between;align-items:center"><div><strong>${a.alert_type}</strong> <span class="small">${a.timestamp}</span><div class="small">${a.source_ip} — ${a.message}</div></div><div><button class="btn" data-ack="${a.id}">Acknowledge</button></div></div>`;
            el.appendChild(div);
        });
        el.querySelectorAll('button[data-ack]').forEach(b => b.addEventListener('click', (ev) => {
            const id = ev.currentTarget.getAttribute('data-ack');
            fetch('/api/admin/ack_alert', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ id: parseInt(id) }) })
                .then(r => r.json()).then(resp => { if (resp.status === 'success') { loadAlerts(); alert('Acknowledged') } else alert('Failed: ' + resp.message) })
        }));
    }).catch(e => { console.error(e); document.getElementById('alertsList').innerHTML = '<div class="small">Error loading alerts</div>' });
}

function loadLogs() {
    const lines = parseInt(document.getElementById('linesInput').value || 200);
    fetch('/api/admin/logs?lines=' + lines).then(r => r.json()).then(data => {
        const box = document.getElementById('logBox');
        box.textContent = '';
        (data.lines || []).reverse().forEach(l => { const p = document.createElement('div'); p.textContent = l; box.appendChild(p); });
        box.scrollTop = 0;
    }).catch(e => { console.error(e); document.getElementById('logBox').textContent = 'Error loading logs' });
}

function clearAllData() {
    if (!confirm('Clear ALL data (database + logs)?')) return;
    fetch('/api/clear_stats', { method: 'POST', headers: { 'Content-Type': 'application/json' } }).then(r => r.json()).then(resp => { if (resp.status === 'success') { loadAttacks(); loadAlerts(); loadLogs(); loadStats(); alert('Cleared') } else alert('Failed') }).catch(e => alert('Error: ' + e));
}
