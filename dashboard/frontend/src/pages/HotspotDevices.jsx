/**
 * HotspotDevices.jsx
 * Enterprise Hotspot Gateway — Connected Device Monitor
 *
 * Real-time device visibility via WebSocket (ws/devices/).
 * REST fallback + block/unblock controls via hotspot API.
 */
import React, {
  useState, useEffect, useRef, useCallback, useMemo
} from 'react';
import './css/HotspotDevices.css';

const ML_API = 'http://127.0.0.1:8000/model_app';
const WS_URL  = 'ws://127.0.0.1:8000/ws/devices/';

/* ── Utility helpers ────────────────────────────────────────────── */
const fmt = {
  bytes: (b) => {
    if (b == null) return '—';
    if (b < 1024)       return `${b} B`;
    if (b < 1048576)    return `${(b / 1024).toFixed(1)} KB`;
    if (b < 1073741824) return `${(b / 1048576).toFixed(2)} MB`;
    return `${(b / 1073741824).toFixed(2)} GB`;
  },
  bps: (bps) => {
    if (bps == null || bps === 0) return '0 bps';
    if (bps < 1024)       return `${Math.round(bps)} bps`;
    if (bps < 1048576)    return `${(bps / 1024).toFixed(1)} Kbps`;
    return `${(bps / 1048576).toFixed(2)} Mbps`;
  },
  ts: (unix) => {
    if (!unix) return '—';
    return new Date(unix * 1000).toLocaleTimeString();
  },
  ago: (unix) => {
    if (!unix) return '—';
    const s = Math.floor(Date.now() / 1000 - unix);
    if (s < 5)  return 'just now';
    if (s < 60) return `${s}s ago`;
    if (s < 3600) return `${Math.floor(s / 60)}m ago`;
    return `${Math.floor(s / 3600)}h ago`;
  },
  mac: (m) => (m && m !== '-' ? m.toUpperCase() : '—'),
};

/* ── Mini sparkline SVG ─────────────────────────────────────────── */
function Sparkline({ data = [], color = '#00f5d4', height = 36 }) {
  if (!data.length) return <svg width="100%" height={height} />;
  const vals = data.map(d => d.up + d.down);
  const max   = Math.max(...vals, 1);
  const w     = 120;
  const pts   = vals.map((v, i) => {
    const x = (i / (vals.length - 1 || 1)) * w;
    const y = height - Math.round((v / max) * (height - 4)) - 2;
    return `${x},${y}`;
  });
  return (
    <svg viewBox={`0 0 ${w} ${height}`} style={{ width: '100%', height }} preserveAspectRatio="none">
      <polyline
        fill="none"
        stroke={color}
        strokeWidth="1.5"
        strokeLinejoin="round"
        points={pts.join(' ')}
        style={{ filter: `drop-shadow(0 0 3px ${color}55)` }}
      />
    </svg>
  );
}

/* ── Threat gauge ring ──────────────────────────────────────────── */
function ThreatGauge({ score = 0 }) {
  const pct  = Math.min(100, Math.max(0, score));
  const r    = 18;
  const circ = 2 * Math.PI * r;
  const dash = circ * (pct / 100);
  const color = pct >= 70 ? '#ff4560' : pct >= 40 ? '#ffb800' : '#00f5d4';
  return (
    <div className="hd-gauge-wrap" title={`Threat score: ${pct.toFixed(0)}`}>
      <svg width="48" height="48" viewBox="0 0 44 44">
        <circle cx="22" cy="22" r={r} fill="none" stroke="rgba(255,255,255,0.07)" strokeWidth="4" />
        <circle
          cx="22" cy="22" r={r}
          fill="none" stroke={color} strokeWidth="4"
          strokeDasharray={`${dash} ${circ - dash}`}
          strokeDashoffset={circ / 4}
          strokeLinecap="round"
          style={{ filter: `drop-shadow(0 0 4px ${color}aa)`, transition: 'stroke-dasharray 0.6s ease' }}
        />
        <text x="22" y="27" textAnchor="middle" fill={color} fontSize="10" fontWeight="700"
          fontFamily="JetBrains Mono, monospace">
          {Math.round(pct)}
        </text>
      </svg>
    </div>
  );
}

/* ── Status badge ───────────────────────────────────────────────── */
function StatusBadge({ status }) {
  const map = {
    online:  { cls: 'hd-status-online',  label: 'ONLINE',  dot: true },
    offline: { cls: 'hd-status-offline', label: 'OFFLINE', dot: false },
    blocked: { cls: 'hd-status-blocked', label: 'BLOCKED', dot: false },
  };
  const cfg = map[status] || map.offline;
  return (
    <span className={`hd-status ${cfg.cls}`}>
      {cfg.dot && <span className="hd-status-dot" />}
      {cfg.label}
    </span>
  );
}

/* ── Port badges ────────────────────────────────────────────────── */
const PORT_LABELS = {
  80: 'HTTP', 443: 'HTTPS', 22: 'SSH', 21: 'FTP', 53: 'DNS',
  25: 'SMTP', 587: 'SMTP', 3389: 'RDP', 8080: 'HTTP-ALT', 3306: 'MySQL',
  5432: 'PG', 6379: 'Redis', 27017: 'Mongo', 1883: 'MQTT',
};
function PortBadges({ ports = [] }) {
  return (
    <div className="hd-ports">
      {ports.slice(0, 5).map(({ port, count }) => (
        <span key={port} className="hd-port-badge" title={`${count} pkts`}>
          {PORT_LABELS[port] || port}
        </span>
      ))}
    </div>
  );
}

/* ── Device type icons ─────────────────────────────────────────── */
const DEVICE_ICONS = {
  phone:   '📱',
  laptop:  '💻',
  iot:     '🔌',
  unknown: '📶',
};

/* ── Device Card ─────────────────────────────────────────────────── */
function DeviceCard({ device, onAction, actionPending }) {
  const [expanded, setExpanded] = useState(false);
  const bwRecent = (device.bw_history || []).slice(-30);
  const lastUp   = bwRecent[bwRecent.length - 1]?.up   || 0;
  const lastDown = bwRecent[bwRecent.length - 1]?.down  || 0;
  const isBlocked = device.status === 'blocked';
  const isOnline  = device.status === 'online';

  // Pick meaningful display name — hostname wins over raw IP
  const displayName = device.hostname && device.hostname !== device.ip
    ? device.hostname
    : (device.vendor ? `${device.vendor}-${device.ip.split('.').pop()}` : `Device-${device.ip.split('.').pop()}`);

  const typeIcon = isBlocked ? '🚫' : (DEVICE_ICONS[device.device_type] || '📶');

  return (
    <div className={`hd-card ${device.status} ${expanded ? 'expanded' : ''}`}>
      {/* Card header */}
      <div className="hd-card-top" onClick={() => setExpanded(e => !e)}>
        <div className="hd-card-left">
          <div className={`hd-device-icon ${device.status}`}>
            {typeIcon}
          </div>
          <div className="hd-card-info">
            <div className="hd-hostname">{displayName}</div>
            <div className="hd-ip-mac">
              <code className="hd-ip">{device.ip}</code>
              {device.vendor && (
                <span className="hd-vendor-badge">{device.vendor}</span>
              )}
              <span className="hd-mac">{fmt.mac(device.mac)}</span>
            </div>
          </div>
        </div>

        <div className="hd-card-mid">
          <StatusBadge status={device.status} />
          <ThreatGauge score={device.threat_score} />
        </div>

        <div className="hd-card-right">
          <div className="hd-bw-cell">
            <span className="hd-bw-label">↑</span>
            <span className="hd-bw-val">{fmt.bytes(device.bytes_up)}</span>
          </div>
          <div className="hd-bw-cell">
            <span className="hd-bw-label">↓</span>
            <span className="hd-bw-val">{fmt.bytes(device.bytes_down)}</span>
          </div>
          <div className="hd-sparkline-wrap">
            <Sparkline data={bwRecent} color={isBlocked ? '#ff4560' : isOnline ? '#00f5d4' : '#456070'} />
          </div>
        </div>

        <div className="hd-card-actions" onClick={e => e.stopPropagation()}>
          {isBlocked ? (
            <button
              className="hd-btn hd-btn-unblock"
              disabled={actionPending}
              onClick={() => onAction(device.ip, 'unblock')}
            >
              {actionPending ? '…' : '✓ Unblock'}
            </button>
          ) : (
            <button
              className="hd-btn hd-btn-block"
              disabled={actionPending}
              onClick={() => onAction(device.ip, 'block')}
            >
              {actionPending ? '…' : '⊘ Block'}
            </button>
          )}
          <button
            className="hd-btn hd-btn-expand"
            onClick={() => setExpanded(e => !e)}
            title={expanded ? 'Collapse' : 'Expand'}
          >
            {expanded ? '▲' : '▼'}
          </button>
        </div>
      </div>

      {/* Expanded detail panel */}
      {expanded && (
        <div className="hd-card-detail anim-fade-in">
          <div className="hd-detail-grid">
            <div className="hd-detail-block">
              <div className="hd-detail-title">Session Info</div>
              <div className="hd-detail-row"><span>First Seen</span><span>{fmt.ts(device.first_seen)}</span></div>
              <div className="hd-detail-row"><span>Last Active</span><span>{fmt.ago(device.last_seen)}</span></div>
              <div className="hd-detail-row"><span>Packets ↑</span><span>{(device.packets_up || 0).toLocaleString()}</span></div>
              <div className="hd-detail-row"><span>Packets ↓</span><span>{(device.packets_down || 0).toLocaleString()}</span></div>
            </div>

            <div className="hd-detail-block">
              <div className="hd-detail-title">Live Rate</div>
              <div className="hd-detail-row">
                <span>Upload</span>
                <span className="hd-rate-up">{fmt.bps(lastUp * 8)}</span>
              </div>
              <div className="hd-detail-row">
                <span>Download</span>
                <span className="hd-rate-down">{fmt.bps(lastDown * 8)}</span>
              </div>
              <div className="hd-detail-row">
                <span>Total</span>
                <span>{fmt.bytes((device.bytes_up || 0) + (device.bytes_down || 0))}</span>
              </div>
              <div className="hd-detail-row">
                <span>Threat lvl</span>
                <span style={{ color: device.threat_score > 70 ? '#ff4560' : device.threat_score > 40 ? '#ffb800' : '#00e676' }}>
                  {device.threat_score > 70 ? 'HIGH' : device.threat_score > 40 ? 'MEDIUM' : 'LOW'}
                </span>
              </div>
            </div>

            <div className="hd-detail-block hd-detail-chart">
              <div className="hd-detail-title">Bandwidth (60s)</div>
              <div className="hd-chart-row">
                <span className="hd-chart-label">↑</span>
                <Sparkline data={bwRecent.map(b => ({ up: b.up, down: 0 }))} color="#00f5d4" height={28} />
              </div>
              <div className="hd-chart-row">
                <span className="hd-chart-label">↓</span>
                <Sparkline data={bwRecent.map(b => ({ up: b.down, down: 0 }))} color="#7b2fff" height={28} />
              </div>
            </div>

            <div className="hd-detail-block">
              <div className="hd-detail-title">Top Ports</div>
              <PortBadges ports={device.top_ports || []} />
              {(!device.top_ports || !device.top_ports.length) && (
                <span className="hd-muted">No port data yet</span>
              )}
            </div>
          </div>
        </div>
      )}
    </div>
  );
}

/* ── Gateway KPI bar ─────────────────────────────────────────────── */
function GatewayKPIs({ stats, lastUpdate, wsConnected }) {
  return (
    <div className="hd-kpi-bar">
      <div className="hd-kpi">
        <div className="hd-kpi-value accent">{stats.total_devices ?? 0}</div>
        <div className="hd-kpi-label">Total Devices</div>
      </div>
      <div className="hd-kpi-sep" />
      <div className="hd-kpi">
        <div className="hd-kpi-value success">{stats.online_devices ?? 0}</div>
        <div className="hd-kpi-label">Online</div>
      </div>
      <div className="hd-kpi-sep" />
      <div className="hd-kpi">
        <div className="hd-kpi-value danger">{stats.blocked_devices ?? 0}</div>
        <div className="hd-kpi-label">Blocked</div>
      </div>
      <div className="hd-kpi-sep" />
      <div className="hd-kpi">
        <div className="hd-kpi-value">{fmt.bytes(stats.total_bytes_up)}</div>
        <div className="hd-kpi-label">Total Upload</div>
      </div>
      <div className="hd-kpi-sep" />
      <div className="hd-kpi">
        <div className="hd-kpi-value">{fmt.bytes(stats.total_bytes_down)}</div>
        <div className="hd-kpi-label">Total Download</div>
      </div>
      <div className="hd-kpi-sep" />
      <div className="hd-kpi">
        <div className="hd-kpi-value" style={{ fontFamily: 'JetBrains Mono, monospace', fontSize: '0.9rem' }}>
          {stats.gateway_ip || '192.168.137.1'}
        </div>
        <div className="hd-kpi-label">Gateway IP</div>
      </div>
      <div className="hd-kpi-sep" />
      <div className="hd-kpi hd-kpi-ws">
        <div className={`hd-ws-dot ${wsConnected ? 'live' : 'dead'}`} />
        <div className="hd-kpi-label">{wsConnected ? 'Live' : 'Polling'}</div>
        {lastUpdate && (
          <div className="hd-kpi-sub">{lastUpdate}</div>
        )}
      </div>
    </div>
  );
}

/* ── Toolbar / filters ──────────────────────────────────────────── */
function Toolbar({ search, setSearch, filter, setFilter, sortBy, setSortBy,
                   count, onRefresh, onScan, loading, scanning }) {
  return (
    <div className="hd-toolbar">
      <div className="hd-toolbar-left">
        <div className="hd-search-wrap">
          <span className="hd-search-icon">🔍</span>
          <input
            id="hd-search"
            className="hd-search"
            type="text"
            placeholder="Search IP, hostname, MAC…"
            value={search}
            onChange={e => setSearch(e.target.value)}
          />
          {search && (
            <button className="hd-search-clear" onClick={() => setSearch('')}>✕</button>
          )}
        </div>

        <div className="hd-filter-group">
          {['all', 'online', 'offline', 'blocked'].map(f => (
            <button
              key={f}
              id={`hd-filter-${f}`}
              className={`hd-filter-btn ${filter === f ? 'active' : ''}`}
              onClick={() => setFilter(f)}
            >
              {f === 'all' ? `All (${count})` : f.charAt(0).toUpperCase() + f.slice(1)}
            </button>
          ))}
        </div>
      </div>

      <div className="hd-toolbar-right">
        <select
          id="hd-sort"
          className="hd-sort-select"
          value={sortBy}
          onChange={e => setSortBy(e.target.value)}
        >
          <option value="status">Sort: Status</option>
          <option value="threat">Sort: Threat ↓</option>
          <option value="bw">Sort: Bandwidth ↓</option>
          <option value="last_seen">Sort: Last Active</option>
          <option value="ip">Sort: IP</option>
        </select>

        {/* Active scan button — runs ping sweep */}
        <button
          id="hd-scan"
          className={`hd-btn hd-btn-scan ${scanning ? 'scanning' : ''}`}
          onClick={onScan}
          disabled={scanning}
          title="Ping-sweep the subnet to find connected devices"
        >
          {scanning ? <><span className="hd-scan-spinner" />Scanning…</> : '⚡ Scan'}
        </button>

        <button
          id="hd-refresh"
          className={`hd-icon-btn ${loading ? 'spinning' : ''}`}
          onClick={onRefresh}
          title="Refresh device list"
        >
          ⟳
        </button>
      </div>
    </div>
  );
}

/* ── Block-all / unblock-all bulk actions ─────────────────────────── */
function BulkActions({ selected, onBulkBlock, onBulkUnblock, bulkPending }) {
  if (!selected.length) return null;
  return (
    <div className="hd-bulk-bar anim-fade-in">
      <span className="hd-bulk-count">{selected.length} selected</span>
      <button className="hd-btn hd-btn-block" onClick={onBulkBlock} disabled={bulkPending}>
        ⊘ Block All
      </button>
      <button className="hd-btn hd-btn-unblock" onClick={onBulkUnblock} disabled={bulkPending}>
        ✓ Unblock All
      </button>
    </div>
  );
}

/* ── Main page component ─────────────────────────────────────────── */
export default function HotspotDevices() {
  const [devices,       setDevices]       = useState([]);
  const [stats,         setStats]         = useState({});
  const [search,        setSearch]        = useState('');
  const [filter,        setFilter]        = useState('all');
  const [sortBy,        setSortBy]        = useState('status');
  const [actionPending, setActionPending] = useState({});   // ip → bool
  const [bulkPending,   setBulkPending]   = useState(false);
  const [selected,      setSelected]      = useState([]);
  const [wsConnected,   setWsConnected]   = useState(false);
  const [lastUpdate,    setLastUpdate]    = useState('');
  const [loading,       setLoading]       = useState(false);
  const [scanning,      setScanning]      = useState(false); // active ping sweep
  const [scanMsg,       setScanMsg]       = useState('');    // scan banner message
  const [toast,         setToast]         = useState(null);

  const wsRef      = useRef(null);
  const retryTimer = useRef(null);

  /* ── Toast helper ─────────────────────────────────────────────── */
  const showToast = useCallback((msg, type = 'success') => {
    setToast({ msg, type });
    setTimeout(() => setToast(null), 3000);
  }, []);

  /* ── Data ingestion ───────────────────────────────────────────── */
  const ingest = useCallback((data) => {
    if (data.devices !== undefined) setDevices(data.devices);
    if (data.stats   !== undefined) setStats(data.stats);
    setLastUpdate(new Date().toLocaleTimeString());
  }, []);

  /* ── REST fetch fallback ─────────────────────────────────────── */
  const fetchRest = useCallback(async () => {
    setLoading(true);
    try {
      const [dRes, sRes] = await Promise.all([
        fetch(`${ML_API}/hotspot/devices`),
        fetch(`${ML_API}/hotspot/stats`),
      ]);
      const dData = await dRes.json();
      const sData = await sRes.json();
      setDevices(dData.devices || []);
      setStats(sData);
      setLastUpdate(new Date().toLocaleTimeString());
    } catch (e) {
      console.warn('REST fetch failed:', e);
    }
    setLoading(false);
  }, []);

  /* ── Active ping sweep scan ──────────────────────────────────── */
  const runScan = useCallback(async () => {
    if (scanning) return;
    setScanning(true);
    setScanMsg('Pinging 192.168.137.0/24 subnet — this takes ~5 seconds…');
    try {
      const res  = await fetch(`${ML_API}/hotspot/scan`, { method: 'POST' });
      const data = await res.json();
      if (data.devices !== undefined) setDevices(data.devices);
      if (data.stats   !== undefined) setStats(data.stats);
      setLastUpdate(new Date().toLocaleTimeString());
      const found = data.count || 0;
      setScanMsg(
        found > 0
          ? `✓ Scan complete — ${found} device${found !== 1 ? 's' : ''} found`
          : '✓ Scan complete — no devices found. Make sure a device is connected to the hotspot.'
      );
    } catch (e) {
      setScanMsg('✗ Scan failed — is the Django server running?');
    }
    setScanning(false);
    setTimeout(() => setScanMsg(''), 6000);
  }, [scanning]);

  /* ── WebSocket connect / reconnect ───────────────────────────── */
  const connectWs = useCallback(() => {
    if (wsRef.current && wsRef.current.readyState <= 1) return;
    try {
      const ws = new WebSocket(WS_URL);
      ws.onopen  = () => { setWsConnected(true); };
      ws.onclose = () => {
        setWsConnected(false);
        retryTimer.current = setTimeout(connectWs, 4000);
      };
      ws.onerror = () => ws.close();
      ws.onmessage = (e) => {
        try { ingest(JSON.parse(e.data)); }
        catch {}
      };
      wsRef.current = ws;
    } catch {
      retryTimer.current = setTimeout(connectWs, 5000);
    }
  }, [ingest]);

  useEffect(() => {
    // On mount: quick REST fetch first, then trigger a scan automatically
    fetchRest().then(() => runScan());
    connectWs();
    // Poll REST as fallback when WS is down
    const poll = setInterval(() => {
      if (!wsRef.current || wsRef.current.readyState !== 1) fetchRest();
    }, 5000);
    return () => {
      clearInterval(poll);
      clearTimeout(retryTimer.current);
      wsRef.current?.close();
    };
  // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  /* ── Block / Unblock action ──────────────────────────────────── */
  const handleAction = useCallback(async (ip, action) => {
    setActionPending(prev => ({ ...prev, [ip]: true }));
    try {
      const res = await fetch(`${ML_API}/hotspot/devices/${ip}/action`, {
        method:  'POST',
        headers: { 'Content-Type': 'application/json' },
        body:    JSON.stringify({ action }),
      });
      const data = await res.json();
      if (data.status === action + 'd' || data.status === action) {
        showToast(`${ip} ${action}ed successfully`, action === 'block' ? 'danger' : 'success');
        // Optimistic update
        setDevices(prev => prev.map(d =>
          d.ip === ip ? { ...d, status: action === 'block' ? 'blocked' : 'online' } : d
        ));
      } else {
        showToast(`Action failed: ${data.error || 'unknown'}`, 'danger');
      }
    } catch (e) {
      showToast(`Network error: ${e.message}`, 'danger');
    }
    setActionPending(prev => ({ ...prev, [ip]: false }));
  }, [showToast]);

  /* ── Bulk actions ─────────────────────────────────────────────── */
  const handleBulk = useCallback(async (action) => {
    setBulkPending(true);
    await Promise.all(selected.map(ip => handleAction(ip, action)));
    setSelected([]);
    setBulkPending(false);
  }, [selected, handleAction]);

  /* ── Filtering + sorting ─────────────────────────────────────── */
  const displayed = useMemo(() => {
    let list = [...devices];

    // Filter by status tab
    if (filter !== 'all') list = list.filter(d => d.status === filter);

    // Search
    if (search) {
      const q = search.toLowerCase();
      list = list.filter(d =>
        d.ip.includes(q) ||
        (d.hostname || '').toLowerCase().includes(q) ||
        (d.mac || '').toLowerCase().includes(q)
      );
    }

    // Sort
    list.sort((a, b) => {
      switch (sortBy) {
        case 'threat':    return (b.threat_score || 0) - (a.threat_score || 0);
        case 'bw':        return ((b.bytes_up || 0) + (b.bytes_down || 0)) - ((a.bytes_up || 0) + (a.bytes_down || 0));
        case 'last_seen': return (b.last_seen || 0) - (a.last_seen || 0);
        case 'ip':        return a.ip.localeCompare(b.ip, undefined, { numeric: true });
        default: {
          const order = { online: 0, offline: 1, blocked: 2 };
          const diff  = (order[a.status] ?? 9) - (order[b.status] ?? 9);
          return diff !== 0 ? diff : (b.last_seen || 0) - (a.last_seen || 0);
        }
      }
    });

    return list;
  }, [devices, filter, search, sortBy]);

  /* ── Render ──────────────────────────────────────────────────── */
  return (
    <div className="sf-page hd-page">
      {/* Page header */}
      <div className="hd-page-header">
        <div className="hd-page-title-wrap">
          <div className="hd-page-icon">📡</div>
          <div>
            <h1 className="hd-page-title">Hotspot Device Monitor</h1>
            <p className="hd-page-sub">
              Gateway <code>192.168.137.1</code> — Real-time client visibility &amp; access control
            </p>
          </div>
        </div>
        <div className="hd-header-badges">
          <span className={`hd-live-badge ${wsConnected ? 'live' : ''}`}>
            <span className="hd-live-dot" />
            {wsConnected ? 'LIVE' : 'POLLING'}
          </span>
        </div>
      </div>

      {/* KPI bar */}
      <GatewayKPIs stats={stats} lastUpdate={lastUpdate} wsConnected={wsConnected} />

      {/* Toolbar */}
      <Toolbar
        search={search} setSearch={setSearch}
        filter={filter} setFilter={setFilter}
        sortBy={sortBy} setSortBy={setSortBy}
        count={devices.length}
        onRefresh={fetchRest}
        onScan={runScan}
        loading={loading}
        scanning={scanning}
      />

      {/* Scan progress banner */}
      {scanMsg && (
        <div className={`hd-scan-banner anim-fade-in ${
          scanMsg.startsWith('✗') ? 'error' : scanMsg.startsWith('✓') ? 'done' : 'progress'
        }`}>
          {scanning && <span className="hd-scan-spinner" />}
          {scanMsg}
        </div>
      )}

      {/* Bulk actions bar */}
      <BulkActions
        selected={selected}
        onBulkBlock={() => handleBulk('block')}
        onBulkUnblock={() => handleBulk('unblock')}
        bulkPending={bulkPending}
      />

      {/* Device list */}
      {displayed.length === 0 ? (
        <div className="hd-empty">
          <div className="hd-empty-icon">📡</div>
          {scanning ? (
            <><strong>Scanning subnet…</strong><p>Pinging 192.168.137.0/24 to discover connected devices.</p></>
          ) : devices.length === 0 ? (
            <>
              <strong>No devices detected yet.</strong>
              <p>Make sure a device is connected to your Windows hotspot, then click <b>⚡ Scan</b> to discover it.</p>
              <div style={{ display: 'flex', gap: 10, marginTop: 8 }}>
                <button className="hd-btn hd-btn-scan" onClick={runScan} disabled={scanning}>
                  ⚡ Scan Now
                </button>
                <button className="hd-btn hd-btn-expand" onClick={fetchRest}>
                  ⟳ Refresh
                </button>
              </div>
            </>
          ) : (
            <><strong>No devices match your filter.</strong><p>Try adjusting the search or filter.</p></>
          )}
        </div>
      ) : (
        <div className="hd-device-list">
          {displayed.map(device => (
            <DeviceCard
              key={device.ip}
              device={device}
              onAction={handleAction}
              actionPending={actionPending[device.ip] || false}
            />
          ))}
        </div>
      )}

      {/* Toast notification */}
      {toast && (
        <div className={`hd-toast hd-toast-${toast.type} anim-fade-in`}>
          {toast.type === 'success' ? '✓' : '✗'} {toast.msg}
        </div>
      )}
    </div>
  );
}
