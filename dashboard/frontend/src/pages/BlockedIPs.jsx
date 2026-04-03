import React, { useState, useEffect, useCallback } from 'react';
import { useAuth } from '../context/AuthContext';

const ML_API = 'http://127.0.0.1:8000/model_app';

export default function BlockedIPsPage() {
  const { user, isAdmin } = useAuth();
  const [blocked, setBlocked]   = useState([]);
  const [total, setTotal]       = useState(0);
  const [page, setPage]         = useState(1);
  const [loading, setLoading]   = useState(false);
  const [activeOnly, setActiveOnly] = useState(true);
  const [newIP, setNewIP]       = useState('');
  const [reason, setReason]     = useState('');
  const [opStatus, setOpStatus] = useState({});
  const LIMIT = 50;

  const fetchBlocked = useCallback(async (pg = 1, activeF = activeOnly) => {
    setLoading(true);
    try {
      const params = new URLSearchParams({ page: pg, limit: LIMIT, active: activeF });
      const r = await fetch(`${ML_API}/blocked_ips_db?${params}`);
      const d = await r.json();
      setBlocked(d.blocked_ips || []);
      setTotal(d.total || 0);
    } catch {}
    setLoading(false);
  }, []);

  useEffect(() => { fetchBlocked(1, activeOnly); }, []);

  const doAction = async (ip, action) => {
    setOpStatus(s => ({ ...s, [ip]: 'loading' }));
    try {
      const r = await fetch(`${ML_API}/blocked_ips_db`, {
        method: 'POST', headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ ip, action, reason, blocked_by: user?.username || 'dashboard', unblocked_by: user?.username || 'dashboard' }),
      });
      const d = await r.json();
      if (d.status === action + 'ed' || d.status === 'unblocked' || d.status === 'blocked') {
        setOpStatus(s => ({ ...s, [ip]: 'success' }));
        fetchBlocked(page, activeOnly);
      } else {
        setOpStatus(s => ({ ...s, [ip]: 'error' }));
      }
    } catch {
      setOpStatus(s => ({ ...s, [ip]: 'error' }));
    }
    setTimeout(() => setOpStatus(s => { const n = { ...s }; delete n[ip]; return n; }), 2500);
  };

  const addBlock = async (e) => {
    e.preventDefault();
    if (!newIP) return;
    await doAction(newIP, 'block');
    setNewIP(''); setReason('');
  };

  const statusIcon = (ip) => {
    const s = opStatus[ip];
    if (s === 'loading') return '⏳';
    if (s === 'success') return '✅';
    if (s === 'error')   return '❌';
    return null;
  };

  const totalPages = Math.max(1, Math.ceil(total / LIMIT));

  return (
    <div className="sf-page anim-fade-in">
      {/* Header */}
      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start', flexWrap: 'wrap', gap: 12, marginBottom: 24 }}>
        <div>
          <h2 style={{ fontSize: '1.4rem', fontWeight: 800, color: 'var(--text-primary)', margin: 0 }}>🔒 Blocked IPs</h2>
          <p style={{ color: 'var(--text-secondary)', fontSize: '0.85rem', marginTop: 4 }}>
            System-level firewall rules via <code style={{ fontSize: '0.8rem' }}>netsh advfirewall</code> · {total.toLocaleString()} records
          </p>
        </div>
        <button className="sf-btn sf-btn-ghost" onClick={() => fetchBlocked(page, activeOnly)} disabled={loading}>⟳ Refresh</button>
      </div>

      {/* KPI */}
      <div className="sf-kpi-grid" style={{ marginBottom: 22 }}>
        <div className="sf-kpi-card"><span className="sf-kpi-label">Total Blocks</span><span className="sf-kpi-value danger">{total}</span></div>
        <div className="sf-kpi-card"><span className="sf-kpi-label">Active Blocks</span><span className="sf-kpi-value warning">{blocked.filter(b => b.is_active).length}</span></div>
        <div className="sf-kpi-card"><span className="sf-kpi-label">Unblocked</span><span className="sf-kpi-value">{blocked.filter(b => !b.is_active).length}</span></div>
      </div>

      {/* Manual block form (admin only) */}
      {isAdmin && (
        <div className="sf-card" style={{ padding: '16px 20px', marginBottom: 20 }}>
          <div className="sf-panel-header" style={{ marginBottom: 14 }}>
            <div>
              <div className="sf-panel-title">Block an IP</div>
              <div className="sf-panel-subtitle">Instantly add a system-level firewall rule</div>
            </div>
          </div>
          <form onSubmit={addBlock} style={{ display: 'flex', gap: 10, flexWrap: 'wrap', alignItems: 'flex-end' }}>
            <div style={{ flex: '1 1 180px' }}>
              <label className="sf-label">IP Address</label>
              <input className="sf-input" type="text" placeholder="e.g. 192.168.1.1" value={newIP} onChange={e => setNewIP(e.target.value)} required pattern="\d+\.\d+\.\d+\.\d+" />
            </div>
            <div style={{ flex: '2 1 240px' }}>
              <label className="sf-label">Reason (optional)</label>
              <input className="sf-input" type="text" placeholder="e.g. Suspicious port scan detected" value={reason} onChange={e => setReason(e.target.value)} />
            </div>
            <button type="submit" className="sf-btn sf-btn-danger">🚫 Block IP</button>
          </form>
        </div>
      )}

      {/* Filter */}
      <div style={{ display: 'flex', gap: 10, alignItems: 'center', marginBottom: 16, flexWrap: 'wrap' }}>
        <label style={{ display: 'flex', alignItems: 'center', gap: 8, cursor: 'pointer', userSelect: 'none', fontSize: '0.84rem', color: 'var(--text-secondary)' }}>
          <input type="checkbox" checked={activeOnly} style={{ accentColor: 'var(--accent)' }}
            onChange={e => { setActiveOnly(e.target.checked); setPage(1); fetchBlocked(1, e.target.checked); }} />
          Show active blocks only
        </label>
      </div>

      {/* Table */}
      <div className="sf-card" style={{ padding: 0, overflow: 'hidden' }}>
        <div className="sf-table-wrap">
          <table className="sf-table">
            <thead>
              <tr>
                <th>IP Address</th>
                <th>Status</th>
                <th>Reason</th>
                <th>Blocked By</th>
                <th>Blocked At</th>
                <th>Unblocked At</th>
                {isAdmin && <th>Actions</th>}
              </tr>
            </thead>
            <tbody>
              {loading ? (
                <tr><td colSpan={isAdmin ? 7 : 6} style={{ textAlign: 'center', padding: '40px', color: 'var(--text-muted)' }}>Loading…</td></tr>
              ) : blocked.length === 0 ? (
                <tr><td colSpan={isAdmin ? 7 : 6} style={{ textAlign: 'center', padding: '40px', color: 'var(--text-muted)' }}>No blocked IPs {activeOnly ? 'currently' : 'on record'}.</td></tr>
              ) : blocked.map(b => (
                <tr key={b.id}>
                  <td><code>{b.ip}</code></td>
                  <td>
                    <span className={`sf-pill ${b.is_active ? 'sf-pill-high' : 'sf-pill-normal'}`}>
                      {b.is_active ? 'ACTIVE' : 'UNBLOCKED'}
                    </span>
                  </td>
                  <td style={{ fontSize: '0.82rem', color: 'var(--text-secondary)', maxWidth: 220, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>
                    {b.reason || '—'}
                  </td>
                  <td style={{ fontSize: '0.8rem', color: 'var(--text-muted)' }}>{b.blocked_by || 'system'}</td>
                  <td style={{ fontSize: '0.78rem', color: 'var(--text-muted)', whiteSpace: 'nowrap' }}>
                    {b.blocked_at ? new Date(b.blocked_at * 1000).toLocaleString() : '—'}
                  </td>
                  <td style={{ fontSize: '0.78rem', color: 'var(--text-muted)', whiteSpace: 'nowrap' }}>
                    {b.unblocked_at ? new Date(b.unblocked_at * 1000).toLocaleString() : '—'}
                  </td>
                  {isAdmin && (
                    <td>
                      {b.is_active ? (
                        <button className="sf-btn sf-btn-ghost sf-btn-sm"
                          style={{ color: 'var(--success)', borderColor: 'rgba(0,230,118,0.4)' }}
                          onClick={() => doAction(b.ip, 'unblock')}
                          disabled={opStatus[b.ip] === 'loading'}>
                          {statusIcon(b.ip) || '🔓 Unblock'}
                        </button>
                      ) : (
                        <button className="sf-btn sf-btn-danger sf-btn-sm"
                          onClick={() => doAction(b.ip, 'block')}
                          disabled={opStatus[b.ip] === 'loading'}>
                          {statusIcon(b.ip) || '🚫 Re-block'}
                        </button>
                      )}
                    </td>
                  )}
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </div>

      {/* Pagination */}
      {totalPages > 1 && (
        <div className="sf-pagination">
          <button className="sf-page-btn" onClick={() => { setPage(1); fetchBlocked(1, activeOnly); }} disabled={page === 1}>«</button>
          <button className="sf-page-btn" onClick={() => { const p = page - 1; setPage(p); fetchBlocked(p, activeOnly); }} disabled={page === 1}>‹</button>
          <span style={{ color: 'var(--text-muted)', fontSize: '0.82rem' }}>Page {page} / {totalPages}</span>
          <button className="sf-page-btn" onClick={() => { const p = page + 1; setPage(p); fetchBlocked(p, activeOnly); }} disabled={page === totalPages}>›</button>
          <button className="sf-page-btn" onClick={() => { setPage(totalPages); fetchBlocked(totalPages, activeOnly); }} disabled={page === totalPages}>»</button>
        </div>
      )}
    </div>
  );
}
