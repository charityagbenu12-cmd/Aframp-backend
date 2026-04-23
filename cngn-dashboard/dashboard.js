/**
 * cNGN Transparency Dashboard
 * Pulls from PoR Engine API + Stellar Horizon. Falls back to mock data when offline.
 */

// ── Config ────────────────────────────────────────────────────────────────────
const CONFIG = {
  porApiBase: '/api/por',           // PoR Engine base URL
  stellarHorizon: 'https://horizon.stellar.org',
  cNGNAssetCode: 'cNGN',
  cNGNIssuer: 'GBBD47IF6LWK7P7MDEVSCWR7DPUWV3NY3DTQEVFL4NAT4AQH3ZLLFLA5', // replace with real issuer
  stellarExpertBase: 'https://stellar.expert/explorer/public',
  refreshInterval: 60 * 60 * 1000, // 60 min
};

// ── State ─────────────────────────────────────────────────────────────────────
let currency = 'NGN';
let usdRate = 1550;   // fallback NGN/USD rate; overwritten by API
let charts = {};
let pegRange = '24h';

// ── Formatters ────────────────────────────────────────────────────────────────
const fmt = (n) =>
  currency === 'NGN'
    ? '₦' + Number(n).toLocaleString('en-NG', { maximumFractionDigits: 0 })
    : '$' + (Number(n) / usdRate).toLocaleString('en-US', { maximumFractionDigits: 2 });

// ── Mock / fallback data ──────────────────────────────────────────────────────
function mockPoR() {
  return {
    usdRate: 1550,
    supply: 5_200_000_000,
    assets: 5_304_000_000,
    custodians: [
      { name: 'Zenith Bank',  amount: 2_100_000_000 },
      { name: 'UBA',          amount: 1_800_000_000 },
      { name: 'FirstBank',    amount: 1_404_000_000 },
    ],
    assetTypes: [
      { name: 'Cash at Hand',    amount: 4_200_000_000 },
      { name: 'Cash Equivalents (T-Bills)', amount: 1_104_000_000 },
    ],
    reports: [
      { title: 'Monthly Attestation – Mar 2026', date: '2026-04-01', type: 'Attestation', url: '#' },
      { title: 'Monthly Attestation – Feb 2026', date: '2026-03-01', type: 'Attestation', url: '#' },
      { title: 'Annual Audit Report 2025',        date: '2026-02-15', type: 'Audit',       url: '#' },
    ],
  };
}

function mockPegData(range) {
  const points = { '24h': 24, '7d': 7 * 24, '30d': 30 }[range];
  const now = Date.now();
  const step = { '24h': 3600e3, '7d': 3600e3, '30d': 86400e3 }[range];
  return Array.from({ length: points }, (_, i) => ({
    t: new Date(now - (points - i) * step).toISOString(),
    peg: +(1 + (Math.random() - 0.5) * 0.004).toFixed(4),
  }));
}

function mockActivity() {
  const types = ['mint', 'burn'];
  return Array.from({ length: 10 }, (_, i) => ({
    type: types[i % 2],
    amount: Math.round(Math.random() * 5_000_000 + 100_000),
    time: new Date(Date.now() - i * 8 * 60e3).toISOString(),
    txHash: Array.from({ length: 64 }, () => '0123456789abcdef'[Math.floor(Math.random() * 16)]).join(''),
  }));
}

// ── API fetchers ──────────────────────────────────────────────────────────────
async function fetchPoR() {
  try {
    const r = await fetch(`${CONFIG.porApiBase}/snapshot`);
    if (!r.ok) throw new Error();
    return r.json();
  } catch { return mockPoR(); }
}

async function fetchPegData(range) {
  try {
    const r = await fetch(`${CONFIG.porApiBase}/peg-history?range=${range}`);
    if (!r.ok) throw new Error();
    return r.json();
  } catch { return mockPegData(range); }
}

async function fetchActivity() {
  try {
    const url = `${CONFIG.stellarHorizon}/accounts/${CONFIG.cNGNIssuer}/operations?limit=10&order=desc`;
    const r = await fetch(url);
    if (!r.ok) throw new Error();
    const data = await r.json();
    return data._embedded.records
      .filter(op => ['payment', 'change_trust'].includes(op.type))
      .map(op => ({
        type: op.type === 'payment' && op.from === CONFIG.cNGNIssuer ? 'mint' : 'burn',
        amount: Math.round(parseFloat(op.amount || 0)),
        time: op.created_at,
        txHash: op.transaction_hash,
      }));
  } catch { return mockActivity(); }
}

// ── Gauge (half-doughnut) ─────────────────────────────────────────────────────
function drawGauge(ratio) {
  const pct = Math.min(ratio / 150, 1); // 150% = full arc
  const color = ratio >= 100 ? '#3fb950' : '#f85149';
  const ctx = document.getElementById('gaugeChart').getContext('2d');

  if (charts.gauge) charts.gauge.destroy();
  charts.gauge = new Chart(ctx, {
    type: 'doughnut',
    data: {
      datasets: [{
        data: [pct, 1 - pct],
        backgroundColor: [color, '#21262d'],
        borderWidth: 0,
        circumference: 180,
        rotation: 270,
      }],
    },
    options: { cutout: '72%', plugins: { legend: { display: false }, tooltip: { enabled: false } }, animation: { duration: 600 } },
  });
}

// ── Pie charts ────────────────────────────────────────────────────────────────
const PIE_COLORS = ['#3fb950', '#58a6ff', '#d2a8ff', '#ffa657', '#ff7b72'];

function drawPie(id, labels, data) {
  const ctx = document.getElementById(id).getContext('2d');
  if (charts[id]) charts[id].destroy();
  charts[id] = new Chart(ctx, {
    type: 'doughnut',
    data: {
      labels,
      datasets: [{ data, backgroundColor: PIE_COLORS, borderWidth: 2, borderColor: '#161b22' }],
    },
    options: {
      plugins: {
        legend: { position: 'bottom', labels: { color: '#8b949e', font: { size: 11 }, boxWidth: 12 } },
        tooltip: { callbacks: { label: (c) => ` ${fmt(c.raw)}` } },
      },
    },
  });
}

// ── Peg chart ─────────────────────────────────────────────────────────────────
function drawPegChart(data) {
  const ctx = document.getElementById('pegChart').getContext('2d');
  if (charts.peg) charts.peg.destroy();
  charts.peg = new Chart(ctx, {
    type: 'line',
    data: {
      labels: data.map(d => d.t),
      datasets: [{
        label: 'cNGN Peg',
        data: data.map(d => d.peg),
        borderColor: '#58a6ff',
        backgroundColor: 'rgba(88,166,255,.08)',
        borderWidth: 1.5,
        pointRadius: 0,
        fill: true,
        tension: 0.3,
      }, {
        label: 'Target (1.00)',
        data: data.map(() => 1),
        borderColor: '#3fb950',
        borderWidth: 1,
        borderDash: [4, 4],
        pointRadius: 0,
      }],
    },
    options: {
      scales: {
        x: { display: false },
        y: { ticks: { color: '#8b949e', font: { size: 11 } }, grid: { color: '#21262d' } },
      },
      plugins: { legend: { labels: { color: '#8b949e', font: { size: 11 }, boxWidth: 12 } } },
      animation: { duration: 400 },
    },
  });
}

// ── Activity feed ─────────────────────────────────────────────────────────────
function renderActivity(events) {
  const tbody = document.getElementById('activity-feed');
  tbody.innerHTML = events.map(e => {
    const short = e.txHash.slice(0, 8) + '…' + e.txHash.slice(-6);
    const txUrl = `${CONFIG.stellarExpertBase}/tx/${e.txHash}`;
    const ago = timeAgo(e.time);
    return `<tr>
      <td><span class="badge-${e.type}">${e.type.toUpperCase()}</span></td>
      <td>${fmt(e.amount)}</td>
      <td>${ago}</td>
      <td><a class="tx-link" href="${txUrl}" target="_blank" rel="noopener">${short}</a></td>
    </tr>`;
  }).join('');
}

function timeAgo(iso) {
  const s = Math.round((Date.now() - new Date(iso)) / 1000);
  if (s < 60) return `${s}s ago`;
  if (s < 3600) return `${Math.floor(s / 60)}m ago`;
  if (s < 86400) return `${Math.floor(s / 3600)}h ago`;
  return `${Math.floor(s / 86400)}d ago`;
}

// ── Reports ───────────────────────────────────────────────────────────────────
function renderReports(reports) {
  document.getElementById('reports-list').innerHTML = reports.map(r => `
    <div class="report-item">
      <div class="report-title">${r.title}</div>
      <div class="report-meta">${r.type} · ${r.date}</div>
      <a href="${r.url}" target="_blank" rel="noopener">⬇ Download PDF</a>
    </div>`).join('');
}

// ── Solvency stats ────────────────────────────────────────────────────────────
function renderSolvency(d) {
  const ratio = (d.assets / d.supply) * 100;
  document.getElementById('collat-ratio').textContent = ratio.toFixed(1) + '%';
  document.getElementById('collat-ratio').style.color = ratio >= 100 ? '#3fb950' : '#f85149';
  document.getElementById('supply-val').textContent = fmt(d.supply);
  document.getElementById('assets-val').textContent = fmt(d.assets);
  const surplus = d.assets - d.supply;
  const surplusEl = document.getElementById('surplus-val');
  surplusEl.textContent = (surplus >= 0 ? '+' : '') + fmt(surplus);
  surplusEl.style.color = surplus >= 0 ? '#3fb950' : '#f85149';
  document.getElementById('stellar-verify-btn').href =
    `${CONFIG.stellarExpertBase}/asset/${CONFIG.cNGNAssetCode}-${CONFIG.cNGNIssuer}`;
  drawGauge(ratio);
}

// ── Currency re-render (no re-fetch) ─────────────────────────────────────────
let _lastPoR = null;
let _lastActivity = null;

function setCurrency(c) {
  currency = c;
  document.getElementById('btn-ngn').classList.toggle('active', c === 'NGN');
  document.getElementById('btn-usd').classList.toggle('active', c === 'USD');
  if (_lastPoR) {
    renderSolvency(_lastPoR);
    drawPie('custodianChart', _lastPoR.custodians.map(x => x.name), _lastPoR.custodians.map(x => x.amount));
    drawPie('assetTypeChart', _lastPoR.assetTypes.map(x => x.name), _lastPoR.assetTypes.map(x => x.amount));
  }
  if (_lastActivity) renderActivity(_lastActivity);
}

// ── Peg range toggle ──────────────────────────────────────────────────────────
async function setPegRange(btn, range) {
  document.querySelectorAll('.tab').forEach(t => t.classList.remove('active'));
  btn.classList.add('active');
  pegRange = range;
  const data = await fetchPegData(range);
  drawPegChart(data);
}

// ── Main load ─────────────────────────────────────────────────────────────────
async function loadAll() {
  document.getElementById('last-updated').textContent = 'Refreshing…';

  const [por, activity, pegData] = await Promise.all([
    fetchPoR(),
    fetchActivity(),
    fetchPegData(pegRange),
  ]);

  usdRate = por.usdRate || usdRate;
  _lastPoR = por;
  _lastActivity = activity;

  renderSolvency(por);
  drawPie('custodianChart', por.custodians.map(x => x.name), por.custodians.map(x => x.amount));
  drawPie('assetTypeChart', por.assetTypes.map(x => x.name), por.assetTypes.map(x => x.amount));
  drawPegChart(pegData);
  renderActivity(activity);
  renderReports(por.reports);

  document.getElementById('last-updated').textContent =
    'Updated ' + new Date().toLocaleTimeString();
}

// ── Boot ──────────────────────────────────────────────────────────────────────
loadAll();
setInterval(loadAll, CONFIG.refreshInterval);
