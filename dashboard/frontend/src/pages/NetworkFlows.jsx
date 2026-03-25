import React, { useState, useEffect, useCallback } from 'react';
import { useAuth } from '../context/AuthContext';

const ML_API = 'http://127.0.0.1:8000/model_app';

const ATTACK_OPTIONS = ['', 'DoS', 'DDoS', 'PortScan', 'BruteForce', 'Botnet', 'Infiltration', 'Heartbleed', 'Normal', 'Anomaly'];
const SEV_OPTIONS    = ['', 'High', 'Medium', 'Low'];

export default function NetworkFlows() {
  const { user } = useAuth();
  const [flows, setFlows]     = useState([]);
  const [total, setTotal]     = useState(0);
  const [page, setPage]       = useState(1);
  const [loading, setLoading] = useState(false);
  const [filters, setFilters] = useState({ attack_type: '', severity: '' });
  const [dlLoading, setDlLoading] = useState(false);
  const LIMIT = 50;

  const fetchFlows = useCallback(async (pg = 1, flt = filters) => {
    setLoading(true);
    try {
      const params = new URLSearchParams({ page: pg, limit: LIMIT });
      if (flt.attack_type) params.set('attack_type', flt.attack_type);
      if (flt.severity)    params.set('severity', flt.severity);
      const r = await fetch(`${ML_API}/flows?${params}`);
      const d = await r.json();
      setFlows(d.flows || []);
      setTotal(d.total || 0);
    } catch {}
    setLoading(false);
  }, []);

  useEffect(() => { fetchFlows(1, filters); }, []);

  const applyFilters = () => { setPage(1); fetchFlows(1, filters); };

  const downloadCSV = async () => {
    setDlLoading(true);
    try {
      const params = new URLSearchParams();
      if (filters.attack_type) params.set('attack_type', filters.attack_type);
      if (filters.severity)    params.set('severity', filters.severity);
      const r = await fetch(`${ML_API}/flows/download?${params}`);
      const blob = await r.blob();
      const url  = URL.createObjectURL(blob);
      const a    = document.createElement('a');
      a.href = url; a.download = 'secureflow_flows.csv'; a.click();
      URL.revokeObjectURL(url);
    } catch {}
    setDlLoading(false);
  };

  const totalPages = Math.max(1, Math.ceil(total / LIMIT));
  const changePage = (pg) => { setPage(pg); fetchFlows(pg, filters); };

  const sevColor = (s) => ({ High: 'var(--danger)', Medium: 'var(--warning)', Low: 'var(--success)' }[s] || 'var(--text-muted)');

  return (
    <div className="sf-page anim-fade-in">
      {/* Header */}
      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start', flexWrap: 'wrap', gap: 12, marginBottom: 24 }}>
        <div>
          <h2 style={{ fontSize: '1.4rem', fontWeight: 800, color: 'var(--text-primary)', margin: 0 }}>Network Flows</h2>
          <p style={{ color: 'var(--text-secondary)', fontSize: '0.85rem', marginTop: 4 }}>
            DB-stored classified flows · {total.toLocaleString()} total records
          </p>
        </div>
        <button className="sf-btn sf-btn-primary" onClick={downloadCSV} disabled={dlLoading}>
          {dlLoading ? '⏳ Preparing…' : '⬇ Download CSV'}
        </button>
      </div>

      {/* KPI */}
      <div className="sf-kpi-grid" style={{ marginBottom: 22 }}>
        <div className="sf-kpi-card"><span className="sf-kpi-label">Total Flows</span><span className="sf-kpi-value accent">{total.toLocaleString()}</span></div>
        <div className="sf-kpi-card"><span className="sf-kpi-label">Page</span><span className="sf-kpi-value">{page} / {totalPages}</span></div>
        <div className="sf-kpi-card"><span className="sf-kpi-label">Showing</span><span className="sf-kpi-value">{flows.length}</span></div>
      </div>

      {/* Filters */}
      <div className="sf-card" style={{ padding: '16px 20px', marginBottom: 20, display: 'flex', gap: 14, flexWrap: 'wrap', alignItems: 'flex-end' }}>
        <div style={{ flex: '1 1 160px' }}>
          <label className="sf-label">Attack Type</label>
          <select className="sf-select" value={filters.attack_type} onChange={e => setFilters(f => ({ ...f, attack_type: e.target.value }))}>
            {ATTACK_OPTIONS.map(o => <option key={o} value={o}>{o || 'All types'}</option>)}
          </select>
        </div>
        <div style={{ flex: '1 1 120px' }}>
          <label className="sf-label">Severity</label>
          <select className="sf-select" value={filters.severity} onChange={e => setFilters(f => ({ ...f, severity: e.target.value }))}>
            {SEV_OPTIONS.map(o => <option key={o} value={o}>{o || 'All'}</option>)}
          </select>
        </div>
        <button className="sf-btn sf-btn-ghost" onClick={applyFilters} disabled={loading}>
          {loading ? '…' : '🔍 Apply'}
        </button>
        <button className="sf-btn sf-btn-ghost" onClick={() => { setFilters({ attack_type: '', severity: '' }); setPage(1); fetchFlows(1, { attack_type: '', severity: '' }); }}>
          ✕ Clear
        </button>
        <button className="sf-btn sf-btn-ghost" onClick={() => fetchFlows(page, filters)} disabled={loading} style={{ marginLeft: 'auto' }}>
          ⟳ Refresh
        </button>
      </div>

      {/* Table */}
      <div className="sf-card" style={{ padding: 0, overflow: 'hidden' }}>
        <div className="sf-table-wrap">
          <table className="sf-table">
            <thead>
              <tr>
                <th>#</th>
                <th>Time</th>
                <th>Src IP : Port</th>
                <th>Dst IP : Port</th>
                <th>Proto</th>
                <th>Bytes ↑↓</th>
                <th>Pkts ↑↓</th>
                <th>Duration</th>
                <th>Attack Type</th>
                <th>Severity</th>
                <th>Confidence</th>
                <th>Sim</th>
              </tr>
            </thead>
            <tbody>
              {loading ? (
                <tr><td colSpan={12} style={{ textAlign: 'center', padding: '40px', color: 'var(--text-muted)' }}>Loading flows…</td></tr>
              ) : flows.length === 0 ? (
                <tr><td colSpan={12} style={{ textAlign: 'center', padding: '40px', color: 'var(--text-muted)' }}>No flows found. Start capture and trigger traffic to populate.</td></tr>
              ) : flows.map((f, i) => (
                <tr key={f.id}>
                  <td style={{ color: 'var(--text-muted)', fontSize: '0.75rem' }}>{(page - 1) * LIMIT + i + 1}</td>
                  <td style={{ fontSize: '0.78rem', color: 'var(--text-secondary)', whiteSpace: 'nowrap' }}>
                    {f.start_time ? new Date(f.start_time * 1000).toLocaleTimeString() : '—'}
                  </td>
                  <td><code>{f.src_ip || '—'}:{f.sport || '?'}</code></td>
                  <td><code>{f.dst_ip || '—'}:{f.dport || '?'}</code></td>
                  <td><span className="sf-pill sf-pill-live" style={{ fontSize: '0.68rem' }}>{f.protocol || '?'}</span></td>
                  <td style={{ fontSize: '0.8rem', color: 'var(--text-secondary)' }}>{(f.bytes_fwd || 0).toLocaleString()} / {(f.bytes_bwd || 0).toLocaleString()}</td>
                  <td style={{ fontSize: '0.8rem', color: 'var(--text-secondary)' }}>{f.packets_fwd || 0} / {f.packets_bwd || 0}</td>
                  <td style={{ fontSize: '0.8rem', color: 'var(--text-secondary)' }}>{f.flow_duration ? f.flow_duration.toFixed(2) + 's' : '—'}</td>
                  <td><span style={{ fontWeight: 700, fontSize: '0.82rem', color: f.attack_type === 'Normal' ? 'var(--success)' : 'var(--danger)' }}>{f.attack_type || '—'}</span></td>
                  <td><span style={{ fontWeight: 700, color: sevColor(f.severity), fontSize: '0.82rem' }}>{f.severity || '—'}</span></td>
                  <td style={{ fontSize: '0.8rem', color: 'var(--text-secondary)' }}>{f.confidence ? (f.confidence).toFixed(1) : '—'}</td>
                  <td>{f.is_simulated ? <span className="sf-pill sf-pill-medium" style={{ fontSize: '0.65rem' }}>SIM</span> : <span style={{ color: 'var(--text-muted)', fontSize: '0.75rem' }}>—</span>}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </div>

      {/* Pagination */}
      {totalPages > 1 && (
        <div className="sf-pagination">
          <button className="sf-page-btn" onClick={() => changePage(1)} disabled={page === 1}>«</button>
          <button className="sf-page-btn" onClick={() => changePage(page - 1)} disabled={page === 1}>‹</button>
          {[...Array(Math.min(7, totalPages))].map((_, i) => {
            const pg = Math.max(1, Math.min(page - 3 + i + (page < 4 ? 4 - page : 0), totalPages));
            if (pg < 1 || pg > totalPages) return null;
            return <button key={pg} className={`sf-page-btn ${pg === page ? 'active' : ''}`} onClick={() => changePage(pg)}>{pg}</button>;
          })}
          <button className="sf-page-btn" onClick={() => changePage(page + 1)} disabled={page === totalPages}>›</button>
          <button className="sf-page-btn" onClick={() => changePage(totalPages)} disabled={page === totalPages}>»</button>
        </div>
      )}
    </div>
  );
}
