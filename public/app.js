/* pharos-security-scan — dashboard frontend */

const $ = (id) => document.getElementById(id);

const VERDICT = {
  SAFE:     { c: '#16C784', bg: 'rgba(22,199,132,.10)',  br: 'rgba(22,199,132,.32)',  ico: '✓' },
  CAUTION:  { c: '#F5C451', bg: 'rgba(245,196,81,.10)',  br: 'rgba(245,196,81,.32)',  ico: '!' },
  DANGER:   { c: '#FF8A3D', bg: 'rgba(255,138,61,.10)',  br: 'rgba(255,138,61,.32)',  ico: '‼' },
  CRITICAL: { c: '#FF3B5C', bg: 'rgba(255,59,92,.10)',   br: 'rgba(255,59,92,.34)',   ico: '⛔' },
};

const CATS = [
  ['honeypot', 'Honeypot', 40],
  ['ownership_risk', 'Ownership', 25],
  ['tax_risk', 'Taxes', 20],
  ['source_risk', 'Source code', 10],
  ['holder_concentration', 'Holders', 10],
  ['malicious_flags', 'Threat intel', 100],
];

const GAUGE_CIRC = 327; // 2πr, r=52

let scanType = 'auto';
let lastScan = null;

// ─── Inputs ───
$('scanType').addEventListener('click', (e) => {
  const btn = e.target.closest('.seg');
  if (!btn) return;
  document.querySelectorAll('.seg').forEach((s) => s.classList.remove('active'));
  btn.classList.add('active');
  scanType = btn.dataset.val;
});

document.querySelectorAll('.ex-chip').forEach((chip) => {
  chip.addEventListener('click', () => {
    $('address').value = chip.dataset.addr;
    $('chain').value = chip.dataset.chain;
    setScanType(chip.dataset.type);
    scan();
  });
});

function setScanType(val) {
  scanType = val;
  document.querySelectorAll('.seg').forEach((s) => s.classList.toggle('active', s.dataset.val === val));
}

$('paste').addEventListener('click', async () => {
  try {
    const t = await navigator.clipboard.readText();
    if (t) $('address').value = t.trim();
  } catch { toast('Clipboard blocked — paste manually', true); }
});

$('scanBtn').addEventListener('click', scan);
$('address').addEventListener('keydown', (e) => { if (e.key === 'Enter') scan(); });
$('memoBtn').addEventListener('click', writeMemo);

// ─── Scan ───
async function scan() {
  const address = $('address').value.trim();
  const chain_id = $('chain').value;
  if (!/^0x[a-fA-F0-9]{40}$/.test(address)) { toast('Enter a valid 0x address (40 hex chars)', true); return; }

  setLoading(true);
  try {
    const res = await fetch('/api/scan', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ address, chain_id, scan_type: scanType }),
    });
    const json = await res.json();
    if (!json.success) { toast(json.error || 'Scan failed', true); return; }
    lastScan = json.data;
    render(json.data);
  } catch (err) {
    toast('Network error — is the server running?', true);
  } finally {
    setLoading(false);
  }
}

function setLoading(on) {
  const btn = $('scanBtn');
  btn.disabled = on;
  btn.querySelector('.cta-label').textContent = on ? 'Scanning…' : 'Scan address';
  btn.querySelector('.cta-spin').hidden = !on;
}

// ─── Render ───
function render(d) {
  $('emptyState').hidden = true;
  $('resultBody').hidden = false;

  const v = VERDICT[d.verdict] || VERDICT.CAUTION;
  const body = $('resultBody');
  body.style.setProperty('--vc', v.c);
  body.style.setProperty('--vc-bg', v.bg);
  body.style.setProperty('--vc-br', v.br);

  // gauge
  $('verdictWord').textContent = d.verdict;
  $('verdictTarget').textContent = short(d.address) + ' · ' + d.scan_type;
  const fill = $('gaugeFill');
  fill.style.setProperty('--vc', v.c);
  // reset then animate
  fill.style.strokeDashoffset = GAUGE_CIRC;
  animateNumber($('score'), 0, d.risk_score.total, 1000);
  requestAnimationFrame(() => requestAnimationFrame(() => {
    fill.style.strokeDashoffset = GAUGE_CIRC - (GAUGE_CIRC * d.risk_score.total) / 100;
  }));

  // action
  $('actionIco').textContent = v.ico;
  $('actionText').textContent = d.action_recommendation;
  $('summary').textContent = d.summary;

  // breakdown
  const bars = $('bars');
  bars.innerHTML = '';
  CATS.forEach(([key, name, max]) => {
    const val = d.risk_score.breakdown[key] || 0;
    const pct = Math.min(100, (val / max) * 100);
    const row = document.createElement('div');
    row.className = 'bar-row';
    row.innerHTML = `<span class="bar-name">${name}</span>
      <div class="bar-track"><div class="bar-fill" style="background:${val ? v.c : 'rgba(255,255,255,.18)'}"></div></div>
      <span class="bar-val">${val}</span>`;
    bars.appendChild(row);
    requestAnimationFrame(() => requestAnimationFrame(() => { row.querySelector('.bar-fill').style.width = pct + '%'; }));
  });

  // flags
  const flags = $('flags');
  flags.innerHTML = '';
  $('flagCount').textContent = d.flags.length;
  if (!d.flags.length) {
    flags.innerHTML = '<li class="flag sev-info">No flags raised.</li>';
  }
  d.flags.forEach((f) => {
    const li = document.createElement('li');
    li.className = 'flag ' + sev(f);
    li.textContent = f;
    flags.appendChild(li);
  });

  // reset memo
  $('memoOut').hidden = true;
  $('memoBtn').disabled = false;
  $('memoBtn').querySelector('svg').nextSibling.textContent = ' Preview on-chain memo';

  $('result').scrollIntoView({ behavior: 'smooth', block: 'nearest' });
}

function sev(flag) {
  if (flag.startsWith('🚨')) return 'sev-crit';
  if (flag.startsWith('⚠️')) return 'sev-warn';
  return 'sev-info';
}

// ─── Memo ───
async function writeMemo() {
  if (!lastScan) return;
  const btn = $('memoBtn');
  btn.disabled = true;
  try {
    const res = await fetch('/api/memo', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        address: lastScan.address,
        verdict: lastScan.verdict,
        risk_score: lastScan.risk_score.total,
        summary: lastScan.summary,
        network: lastScan.chain_id === '688688' ? 'atlantic-testnet' : 'mainnet',
      }),
    });
    const json = await res.json();
    if (!json.success) { toast(json.error || 'Memo failed', true); btn.disabled = false; return; }
    const m = json.data;
    const out = $('memoOut');
    out.hidden = false;
    out.innerHTML = `
      <div class="memo-line"><span class="memo-k">status</span><span class="memo-v ${m.sent ? 'ok' : ''}">${m.sent ? 'BROADCAST' : 'DRY RUN (no key)'}</span></div>
      <div class="memo-line"><span class="memo-k">network</span><span class="memo-v">${m.network} · ${m.chainId}</span></div>
      <div class="memo-line"><span class="memo-k">content_hash</span><span class="memo-v">${m.content_hash}</span></div>
      <div class="memo-line"><span class="memo-k">calldata</span><span class="memo-v">${m.data_hex.slice(0, 42)}…</span></div>
      ${m.tx_hash ? `<div class="memo-line"><span class="memo-k">tx</span><span class="memo-v ok">${m.tx_hash}</span></div>` : ''}`;
    toast(m.sent ? 'Memo written on-chain' : 'Audit memo previewed (dry run)');
  } catch {
    toast('Network error', true);
  } finally {
    btn.disabled = false;
  }
}

// ─── Utils ───
function short(a) { return a.slice(0, 8) + '…' + a.slice(-6); }

function animateNumber(el, from, to, dur) {
  const start = performance.now();
  function step(now) {
    const p = Math.min(1, (now - start) / dur);
    const eased = 1 - Math.pow(1 - p, 3);
    el.textContent = Math.round(from + (to - from) * eased);
    if (p < 1) requestAnimationFrame(step);
  }
  requestAnimationFrame(step);
}

// ─── Deep links: /?address=0x..&chain=1672&type=wallet[&run=1] ───
(function initFromQuery() {
  const q = new URLSearchParams(location.search);
  const addr = q.get('address');
  const chain = q.get('chain');
  const type = q.get('type');
  if (addr) $('address').value = addr.trim();
  if (chain) $('chain').value = chain;
  if (type) setScanType(type);
  if (addr && q.get('run') === '1') scan();
})();

let toastTimer;
function toast(msg, isErr) {
  let t = document.querySelector('.toast');
  if (!t) { t = document.createElement('div'); t.className = 'toast'; document.body.appendChild(t); }
  t.textContent = msg;
  t.classList.toggle('err', !!isErr);
  t.classList.add('show');
  clearTimeout(toastTimer);
  toastTimer = setTimeout(() => t.classList.remove('show'), 3200);
}
