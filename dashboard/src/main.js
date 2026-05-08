const API = import.meta.env.VITE_API_URL;
const WS_URL = import.meta.env.VITE_WS_URL;

let ws;
let allItems = [];
let sortAsc = false;
let activeFilters = new Set();
let donutData = { threat: {}, benign: {} };

function renderDashboard(items) {
    const threats = items.filter(i => i.prediction == 1 || i.prediction === '1');
    const benign = items.filter(i => i.prediction == 0 || i.prediction === '0');
    const total = items.length;
    const avgScore = total > 0
        ? (items.reduce((s, i) => s + parseFloat(i.threat_score || 0), 0) / total)
        : 0;

    document.getElementById('total').textContent = total;
    document.getElementById('threats').textContent = threats.length;
    document.getElementById('benign').textContent = benign.length;
    document.getElementById('avg-score').textContent = (avgScore * 100).toFixed(0) + '%';

    // Count by attack type
    const typeCounts = {};
    threats.forEach(i => {
        const t = i.attack_type || i.label || 'Unknown';
        typeCounts[t] = (typeCounts[t] || 0) + 1;
    });
    typeCounts['BENIGN'] = benign.length;

    // Build donut tooltip data
    donutData.benign = { total: benign.length };
    donutData.threat = { total: threats.length };
    Object.entries(typeCounts).forEach(([type, count]) => {
        if (type !== 'BENIGN') donutData.threat[type] = count;
    });

    // Donut
    const circ = 2 * Math.PI * 60;
    const threatPct = total > 0 ? threats.length / total : 0;
    const benignPct = 1 - threatPct;
    document.getElementById('donut-threat').setAttribute('stroke-dasharray', `${threatPct * circ} ${circ}`);
    document.getElementById('donut-benign').setAttribute('stroke-dasharray', `${benignPct * circ} ${circ}`);
    document.getElementById('donut-benign').setAttribute('stroke-dashoffset', -(threatPct * circ));
    document.getElementById('threat-pct').textContent = (threatPct * 100).toFixed(0) + '%';

    // Legend
    const colors = { BENIGN: '#00ff88', DDoS: '#ff4444', DoS: '#ff6600', PortScan: '#ffaa00', BruteForce: '#cc44ff', WebAttack: '#ff44aa', Heartbleed: '#00ffff', Infiltration: '#ff8888' };

    const legendHtml = Object.entries(typeCounts).map(([type, count]) => {
        const color = colors[type] || '#888';
        return `
            <div class="legend-item" onclick="toggleFilter('${type}')" style="cursor:pointer;opacity:${activeFilters.size === 0 || activeFilters.has(type) ? 1 : 0.3};transition:opacity 0.2s;padding:4px 6px;border-radius:2px;${activeFilters.has(type) ? `background:${color}18;border:1px solid ${color}44` : 'border:1px solid transparent'}">
            <span class="legend-left"><span class="legend-dot" style="background:${color}"></span>${type}</span>
            <span class="legend-right">${count}</span>
            </div>`;
    }).join('');
    document.getElementById('legend').innerHTML = legendHtml;

    // Table
    const sortField = document.getElementById('sort-field').value;
    const filtered = activeFilters.size === 0
        ? items
        : items.filter(i => activeFilters.has(i.attack_type || i.label));

    const sorted = [...filtered].sort((a, b) => {
        let valA, valB;
        if (sortField === 'threat_score') {
            valA = parseFloat(a.threat_score || 0);
            valB = parseFloat(b.threat_score || 0);
        } else {
            valA = new Date(a.timestamp || 0).getTime();
            valB = new Date(b.timestamp || 0).getTime();
        }
        return sortAsc ? valA - valB : valB - valA;
    });

    const rows = sorted.map(item => {
        const score = parseFloat(item.threat_score || 0);
        const isAttack = item.prediction == 1 || item.prediction === '1';
        const label = item.attack_type || item.label || 'BENIGN';
        const pct = (score * 100).toFixed(1);
        const time = item.timestamp ? item.timestamp.replace('T', ' ').replace('Z', '') : '-';
        const color = colors[label] || '#888';
        return `
        <tr>
            <td style="color:var(--muted);font-size:11px">${time}</td>
            <td style="font-size:11px">${item.event_id}</td>
            <td>
            <span class="badge" style="background:${color}18;color:${color};border:1px solid ${color}44">
                ${isAttack ? '⚠ ' : ' '}${label}
            </span>
            </td>
            <td>
            <div class="score-bar">
                <div class="score-track">
                <div class="score-fill ${score > 0.5 ? 'high' : 'low'}" style="width:${pct}%;background:${color}"></div>
                </div>
                <span class="score-num">${pct}%</span>
            </div>
            </td>
        </tr>`;
    }).join('');

    document.getElementById('table-container').innerHTML = `
        <table>
        <thead>
            <tr>
            <th>Timestamp</th>
            <th>Event ID</th>
            <th>Attack Type</th>
            <th>Threat Score</th>
            </tr>
        </thead>
        <tbody>${rows}</tbody>
        </table>`;
}

function toggleSort() {
    sortAsc = !sortAsc;
    document.getElementById('sort-dir').textContent = sortAsc ? '↑' : '↓';
    renderDashboard(allItems);
}

function toggleFilter(type) {
    if (activeFilters.has(type)) {
        activeFilters.delete(type);
    } else {
        activeFilters.add(type);
    }
    renderDashboard(allItems);
}

function showDonutTooltip(event, slice) {
    const tooltip = document.getElementById('donut-tooltip');
    const data = donutData[slice];
    const color = slice === 'threat' ? 'var(--red)' : 'var(--green)';
    const title = slice === 'threat' ? 'Threats' : 'Benign';

    let rowsHtml = '';
    if (slice === 'benign') {
        rowsHtml = `<div class="tooltip-row"><span>BENIGN</span><span style="color:var(--green)">${data.total || 0}</span></div>`;
    } else {
        Object.entries(data).forEach(([type, count]) => {
            if (type === 'total') return;
            const c = { DDoS: '#ff4444', DoS: '#ff6600', PortScan: '#ffaa00', BruteForce: '#cc44ff', WebAttack: '#ff44aa', Heartbleed: '#00ffff', Infiltration: '#ff8888' }[type] || '#888';
            rowsHtml += `<div class="tooltip-row"><span style="color:${c}">${type}</span><span>${count}</span></div>`;
        });
    }

    tooltip.innerHTML = `
        <div class="tooltip-title" style="color:${color}">${title} - ${data.total || 0} events</div>
        ${rowsHtml}`;

    tooltip.classList.add('visible');
    moveTooltip(event);
}

function moveTooltip(event) {
    const tooltip = document.getElementById('donut-tooltip');
    tooltip.style.left = (event.clientX + 14) + 'px';
    tooltip.style.top = (event.clientY - 10) + 'px';
}

function hideDonutTooltip() {
    document.getElementById('donut-tooltip').classList.remove('visible');
}

function connectWebSocket() {
    ws = new WebSocket(WS_URL);

    ws.onopen = () => {
        console.log('WebSocket connected');
        document.querySelector('.status-pill').innerHTML =
            '<div class="pulse"></div>LIVE FEED';
    };

    ws.onmessage = (event) => {
        const newItem = JSON.parse(event.data);
        allItems.unshift(newItem);
        renderDashboard(allItems);

        if (newItem.prediction == 1) {
            document.body.style.boxShadow = 'inset 0 0 50px rgba(255,68,68,0.3)';
            setTimeout(() => document.body.style.boxShadow = '', 500);
        }
    };

    ws.onclose = () => {
        console.log('WebSocket closed, reconnecting...');
        document.querySelector('.status-pill').innerHTML =
            '<div class="pulse" style="background:var(--amber)"></div>RECONNECTING';
        setTimeout(connectWebSocket, 3000);
    };

    ws.onerror = (err) => console.error('WebSocket error:', err);
}

async function init() {
    try {
        const res = await fetch(API);
        const body = await res.json();
        if (body.body) {
            allItems = typeof body.body === 'string' ? JSON.parse(body.body) : body.body;
        } else if (Array.isArray(body)) {
            allItems = body;
        }
        renderDashboard(allItems);
    } catch (e) {
        console.error('Init error:', e);
    }
    connectWebSocket();
}

// Expose functions used by inline HTML onclick handlers
window.toggleSort = toggleSort;
window.toggleFilter = toggleFilter;
window.showDonutTooltip = showDonutTooltip;
window.hideDonutTooltip = hideDonutTooltip;

document.addEventListener('mousemove', (e) => {
    const tooltip = document.getElementById('donut-tooltip');
    if (tooltip.classList.contains('visible')) moveTooltip(e);
});

document.getElementById('sort-field').addEventListener('change', () => renderDashboard(allItems));

init();