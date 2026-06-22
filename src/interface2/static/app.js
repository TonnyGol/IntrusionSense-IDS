// State
let ws = null;
let isSniffing = false;
let stats = { total: 0, High: 0, Medium: 0, Low: 0, pkts: 0 };
let attackCounts = {};
let alertList = [];
let attackChart = null;

// Elements
const loginView = document.getElementById('login-view');
const mainLayout = document.getElementById('main-layout');
const btnLogin = document.getElementById('btn-login');
const loginError = document.getElementById('login-error');
const views = document.querySelectorAll('.content-view');
const navItems = document.querySelectorAll('.nav-item');
const clockDisplay = document.getElementById('clock-display');
const btnToggleSniffer = document.getElementById('btn-toggle-sniffer');

const statTotal = document.getElementById('stat-total');
const statHigh = document.getElementById('stat-high');
const statMedium = document.getElementById('stat-medium');
const statLow = document.getElementById('stat-low');
const statPkts = document.getElementById('stat-pkts');

const alertCountLabel = document.getElementById('alert-count');
const alertsTableBody = document.querySelector('#alerts-table tbody');
const liveLog = document.getElementById('live-log');

const snifferStatus = document.getElementById('sniffer-status');
const modelStatus = document.getElementById('model-status');
const monitorDot = document.getElementById('monitor-dot');
const monitorText = document.getElementById('monitor-text');

const SEVERITY_COLORS = {
    'High': '#ef4444',
    'Medium': '#f59e0b',
    'Low': '#22c55e'
};

const ATTACK_COLORS = {
    'DoS': '#ef4444',
    'DDoS': '#991b1b',
    'Brute Force': '#f59e0b',
    'Port Scanning': '#3b82f6',
    'Bots': '#a855f7',
    'Web Attacks': '#ec4899',
};

// Clock
setInterval(() => {
    const now = new Date();
    clockDisplay.textContent = now.toLocaleTimeString('en-US', { hour12: false });
}, 1000);

// Login Logic
btnLogin.addEventListener('click', async () => {
    const user = document.getElementById('username').value;
    const pass = document.getElementById('password').value;
    
    try {
        const res = await fetch('/api/login', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ username: user, password: pass })
        });
        const data = await res.json();
        
        if (data.success) {
            loginView.classList.remove('active');
            mainLayout.classList.add('active');
            initApp();
        } else {
            loginError.textContent = data.message;
        }
    } catch (e) {
        loginError.textContent = "Server connection failed.";
    }
});

// Navigation Logic
navItems.forEach(item => {
    item.addEventListener('click', (e) => {
        if (item.id === 'nav-settings') {
            alert('Settings modal would open here.');
            return;
        }
        navItems.forEach(nav => nav.classList.remove('active'));
        item.classList.add('active');
        
        const targetId = item.getAttribute('data-target');
        views.forEach(view => {
            view.classList.remove('active');
            if (view.id === targetId) view.classList.add('active');
        });
    });
});

// Init App
function initApp() {
    initChart();
    connectWebSocket();
    pollStatus();
    loadHistoricalLogs();
}

async function loadHistoricalLogs() {
    try {
        const res = await fetch('/api/historical_logs');
        const logs = await res.json();
        const tbody = document.querySelector('#historical-table tbody');
        if (tbody) {
            tbody.innerHTML = '';
            logs.reverse().forEach(log => {
                const tr = document.createElement('tr');
                tr.innerHTML = `
                    <td>${log.timestamp || log.time || ''}</td>
                    <td class="severity-${log.severity}">${log.severity}</td>
                    <td>${log.src_ip}</td>
                    <td>${log.dst_ip}</td>
                    <td>${log.attack_type}</td>
                    <td>${log.confidence}</td>
                `;
                tbody.appendChild(tr);
            });
        }
    } catch(e) {
        console.error("Failed to load historical logs", e);
    }
}

function initChart() {
    const ctx = document.getElementById('attackChart').getContext('2d');
    attackChart = new Chart(ctx, {
        type: 'pie',
        data: {
            labels: [],
            datasets: [{
                data: [],
                backgroundColor: [],
                borderWidth: 0
            }]
        },
        options: {
            responsive: true,
            maintainAspectRatio: false,
            plugins: {
                legend: {
                    position: 'right',
                    labels: { color: '#e2e8f0', font: { size: 12 } }
                }
            }
        }
    });
}

function updateChart() {
    const labels = Object.keys(attackCounts);
    const data = Object.values(attackCounts);
    const colors = labels.map(l => ATTACK_COLORS[l] || '#3b82f6');
    
    attackChart.data.labels = labels;
    attackChart.data.datasets[0].data = data;
    attackChart.data.datasets[0].backgroundColor = colors;
    attackChart.update();
}

// Sniffer Control
btnToggleSniffer.addEventListener('click', async () => {
    if (isSniffing) {
        const res = await fetch('/api/sniffer/stop', { method: 'POST' });
        const data = await res.json();
        if (data.success) {
            isSniffing = false;
            btnToggleSniffer.textContent = '▶ Start Sniffing';
            btnToggleSniffer.className = 'btn btn-start';
            snifferStatus.textContent = '● Stopped';
            snifferStatus.className = 'value status-stopped';
            monitorDot.className = 'dot status-stopped';
            monitorText.textContent = ' Idle';
            monitorText.className = 'text status-stopped';
            appendLog('Sniffer stopped.', 'warning');
        } else {
            alert('Failed to stop sniffer: ' + data.message);
        }
    } else {
        const res = await fetch('/api/sniffer/start', { method: 'POST' });
        const data = await res.json();
        if (data.success) {
            isSniffing = true;
            btnToggleSniffer.innerHTML = '■ Stop Sniffing';
            btnToggleSniffer.className = 'btn btn-stop';
            snifferStatus.textContent = '● Running';
            snifferStatus.className = 'value status-running';
            modelStatus.textContent = '● Loaded';
            modelStatus.className = 'value status-running';
            monitorDot.className = 'dot status-running';
            monitorText.textContent = ' Monitoring';
            monitorText.className = 'text status-running';
        } else {
            alert('Failed to start sniffer: ' + data.message);
        }
    }
});

// WebSocket
function connectWebSocket() {
    const protocol = window.location.protocol === 'https:' ? 'wss:' : 'ws:';
    ws = new WebSocket(`${protocol}//${window.location.host}/ws`);
    
    ws.onmessage = (event) => {
        const data = JSON.parse(event.data);
        if (data.type === 'alert') {
            handleAlert(data);
        } else if (data.type === 'log') {
            appendLog(data.message, data.level);
        }
    };
    
    ws.onclose = () => {
        setTimeout(connectWebSocket, 5000);
    };
}

function handleAlert(data) {
    const severity = getSeverity(data.attack_type);
    const time = new Date().toLocaleTimeString('en-US', { hour12: false });
    
    // Update Stats
    stats.total++;
    stats[severity]++;
    attackCounts[data.attack_type] = (attackCounts[data.attack_type] || 0) + 1;
    updateStatsUI();
    updateChart();
    
    // Update Table
    const emptyState = document.querySelector('.empty-state');
    if (emptyState) emptyState.remove();
    
    const tr = document.createElement('tr');
    tr.innerHTML = `
        <td>${time}</td>
        <td class="severity-${severity}">${severity}</td>
        <td>${data.src_ip}</td>
        <td>${data.dst_ip}</td>
        <td>${data.attack_type}</td>
        <td>${data.confidence}</td>
    `;
    alertsTableBody.insertBefore(tr, alertsTableBody.firstChild);
    
    // Update Traffic Monitor List
    const tl = document.getElementById('traffic-list');
    if (tl) {
        const li = document.createElement('li');
        li.style.padding = '8px';
        li.style.borderBottom = '1px solid var(--border)';
        li.textContent = `[${severity}] ${data.src_ip} - ${data.attack_type}`;
        li.onclick = () => {
            Array.from(tl.children).forEach(child => child.style.backgroundColor = 'transparent');
            li.style.backgroundColor = 'var(--active-nav)';
            document.getElementById('tm-title').textContent = `Alert Details`;
            document.getElementById('tm-info').textContent = `Time: ${time}\nSource: ${data.src_ip}\nDestination: ${data.dst_ip}\nType: ${data.attack_type}\nConfidence: ${data.confidence}`;
            document.getElementById('tm-mechanism').textContent = data.details?.rule_triggered ? `Detection Mechanism: ${data.details.rule_triggered}` : '';
            document.getElementById('tm-payload').textContent = data.details?.payloads ? data.details.payloads.join('\\n') : 'No payload captured for this flow.';
        };
        tl.insertBefore(li, tl.firstChild);
    }

    // Log
    appendLog(data.message, 'alert');
}

function getSeverity(attackType) {
    const map = {
        'DDoS': 'High', 'DoS': 'High', 'Bots': 'High',
        'Brute Force': 'Medium', 'Port Scanning': 'Medium',
        'Web Attacks': 'Low'
    };
    return map[attackType] || 'Medium';
}

function appendLog(msg, level) {
    const div = document.createElement('div');
    div.className = `log-entry ${level}`;
    div.textContent = msg;
    liveLog.appendChild(div);
    liveLog.scrollTop = liveLog.scrollHeight;
}

// Status Polling for Packet Count
async function pollStatus() {
    try {
        const res = await fetch('/api/status');
        const data = await res.json();
        if (data.is_sniffing) {
            stats.pkts = data.packet_count;
            statPkts.textContent = stats.pkts;
        }
    } catch(e) {}
    setTimeout(pollStatus, 500);
}

function updateStatsUI() {
    statTotal.textContent = stats.total;
    statHigh.textContent = stats.High;
    statMedium.textContent = stats.Medium;
    statLow.textContent = stats.Low;
    alertCountLabel.textContent = `${stats.total} alerts`;
}
