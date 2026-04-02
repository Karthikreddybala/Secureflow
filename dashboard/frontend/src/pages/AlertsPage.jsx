import React, { useState } from 'react';
import { useSelector, useDispatch } from 'react-redux';
import { useAuth } from '../context/AuthContext';
import { clearAlerts, setAlertLimit, setAlertSort, selectFilteredAlerts } from '../store/slices/alertsSlice';

const ML_API = 'http://127.0.0.1:8000/model_app';
const AUTH_API = 'http://127.0.0.1:5000';

function sev(alert) { return (alert.final?.severity || 'low').toLowerCase(); }
function isNormal(alert) { return (alert.final?.attack_type || '').toLowerCase() === 'normal'; }

export default function AlertsPage() {
  const dispatch   = useDispatch();
  const allAlerts  = useSelector(s => s.alerts.alerts);
  const alertLimit = useSelector(s => s.alerts.alertLimit);
  const alertSort  = useSelector(s => s.alerts.alertSort);
  const { user, isAdmin } = useAuth();
  const [activeTab,  setActiveTab]  = useState('high');
  const [dismissed,  setDismissed]  = useState(new Set());
  const [blockMsg,   setBlockMsg]   = useState({});

  const highs   = allAlerts.filter(a => !isNormal(a) && sev(a) === 'high');
  const mediums = allAlerts.filter(a => !isNormal(a) && sev(a) === 'medium' && !dismissed.has(a.id || a.src_ip));
  const lows    = allAlerts.filter(a => isNormal(a) || sev(a) === 'low');

  const blockIP = async (ip, reason = 'Manual block from Alerts page') => {
    try {
      await fetch(`${ML_API}/blocked_ips_db`, {
        method: 'POST', headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ ip, action: 'block', reason, blocked_by: user?.username || 'dashboard' }),
      });
      await fetch(`${AUTH_API}/alerts/action`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json', 'Authorization': `Bearer ${user?.token}` },
        body: JSON.stringify({ alert_src_ip: ip, action: 'block', reason }),
      });
      setBlockMsg(p => ({ ...p, [ip]: '✅ Blocked' }));
    } catch {
      setBlockMsg(p => ({ ...p, [ip]: '❌ Failed' }));
    }
    setTimeout(() => setBlockMsg(p => { const n = { ...p }; delete n[ip]; return n; }), 2500);
  };

  const dismissAlert = (alert) => {
    const key = alert.id || alert.src_ip || Math.random().toString();
    setDismissed(s => new Set([...s, key]));
  };

  const tabs = [
    { id: 'high',   cls: 'tab-high',   label: '🔴 High',   count: highs.length },
    { id: 'medium', cls: 'tab-medium', label: '🟡 Medium', count: mediums.length },
    { id: 'low',    cls: '',            label: '🟢 Low',    count: lows.length },
  ];

  const rawCurrent = activeTab === 'high' ? highs : activeTab === 'medium' ? mediums : lows;

  // Sort
  const sorted = [...rawCurrent].sort((a, b) => {
    if (alertSort === 'severity') {
      const smap = { high: 3, medium: 2, low: 1, normal: 0 };
      const diff = (smap[sev(b)] || 0) - (smap[sev(a)] || 0);
      return diff !== 0 ? diff : (b.timestamp || 0) - (a.timestamp || 0);
    }
    if (alertSort === 'score') {
      const diff = (b.final?.final_score || 0) - (a.final?.final_score || 0);
      return diff !== 0 ? diff : (b.timestamp || 0) - (a.timestamp || 0);
    }
    if (alertSort === 'oldest') return (a.timestamp || 0) - (b.timestamp || 0);
    return (b.timestamp || 0) - (a.timestamp || 0); // newest (default)
  });

  const current   = sorted.slice(0, alertLimit);
  const remaining = sorted.length - current.length;

  return (
    <div className="sf-page anim-fade-in">
      <div style={{ marginBottom: 24, display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start', flexWrap: 'wrap', gap: 12 }}>
        <div>
          <h2 style={{ fontSize: '1.4rem', fontWeight: 800, color: 'var(--text-primary)', margin: 0 }}>Alert Center</h2>
          <p style={{ color: 'var(--text-secondary)', fontSize: '0.85rem', marginTop: 4 }}>
            Real-time IDS alerts grouped by severity. {allAlerts.length} total in session.
          </p>
        </div>
        {isAdmin && allAlerts.length > 0 && (
          <button
            className="sf-btn sf-btn-ghost sf-btn-sm"
            onClick={() => dispatch(clearAlerts())}
            style={{ fontSize: '0.78rem' }}
          >
            🗑 Clear Session
          </button>
        )}
      </div>

      {/* KPI row */}
      <div className="sf-kpi-grid" style={{ marginBottom: 24 }}>
        <div className="sf-kpi-card">
          <span className="sf-kpi-label">High Severity</span>
          <span className="sf-kpi-value danger">{highs.length}</span>
        </div>
        <div className="sf-kpi-card">
          <span className="sf-kpi-label">Pending Actions</span>
          <span className="sf-kpi-value warning">{mediums.length}</span>
        </div>
        <div className="sf-kpi-card">
          <span className="sf-kpi-label">Dismissed</span>
          <span className="sf-kpi-value">{dismissed.size}</span>
        </div>
        <div className="sf-kpi-card">
          <span className="sf-kpi-label">Total Session</span>
          <span className="sf-kpi-value accent">{allAlerts.length}</span>
        </div>
      </div>

      {/* Tabs + Sort toolbar */}
      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', flexWrap: 'wrap', gap: 8, marginBottom: 4 }}>
        <div className="sf-tabs" style={{ marginBottom: 0 }}>
          {tabs.map(t => (
            <button key={t.id} className={`sf-tab ${t.cls} ${activeTab === t.id ? 'active' : ''}`} onClick={() => setActiveTab(t.id)}>
              {t.label} <span className="tab-count">{t.count}</span>
            </button>
          ))}
        </div>
        <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
          <span style={{ fontSize: '0.75rem', color: 'var(--text-muted)' }}>Sort:</span>
          {['newest', 'oldest', 'severity', 'score'].map(s => (
            <button
              key={s}
              onClick={() => dispatch(setAlertSort(s))}
              style={{
                fontSize: '0.72rem', padding: '3px 9px', borderRadius: 6, border: 'none',
                cursor: 'pointer', fontWeight: alertSort === s ? 700 : 400,
                background: alertSort === s ? 'var(--accent)' : 'var(--card)',
                color: alertSort === s ? '#fff' : 'var(--text-muted)',
                transition: 'all 0.15s',
              }}
            >
              {s.charAt(0).toUpperCase() + s.slice(1)}
            </button>
          ))}
        </div>
      </div>

      {/* Medium: Pending actions banner */}
      {activeTab === 'medium' && mediums.length > 0 && (
        <div style={{ background: 'rgba(255,184,0,0.08)', border: '1px solid rgba(255,184,0,0.25)', borderRadius: 10, padding: '12px 16px', marginBottom: 18, marginTop: 14, fontSize: '0.85rem', color: 'var(--warning)' }}>
          ⚡ <strong>Pending Action Queue</strong> — {mediums.length} medium-severity {mediums.length === 1 ? 'alert' : 'alerts'} awaiting your decision. Block or dismiss each alert.
        </div>
      )}

      {/* Alert list */}
      {sorted.length === 0 ? (
        <div className="sf-empty"><span className="sf-empty-icon">🛡</span><span>No {activeTab} alerts right now</span></div>
      ) : (
        <>
          <div style={{ display: 'flex', flexDirection: 'column', gap: 8, marginTop: 14 }}>
            {current.map((alert, idx) => {
              const severity = sev(alert);
              const ip = alert.src_ip || 'N/A';
              return (
                <div key={alert.id || idx} className={`alert-feed-item ${severity}`}>
                  <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start', gap: 12, flexWrap: 'wrap' }}>
                    <div style={{ flex: 1 }}>
                      <div style={{ display: 'flex', alignItems: 'center', gap: 10, flexWrap: 'wrap', marginBottom: 6 }}>
                        <strong style={{ fontSize: '0.92rem', color: 'var(--text-primary)' }}>
                          {alert.final?.attack_type || 'Unknown Attack'}
                        </strong>
                        <span className={`sf-pill sf-pill-${severity}`}>{severity.toUpperCase()}</span>
                        {alert.mitre?.id && <span className="sf-pill sf-pill-live" style={{ fontSize: '0.68rem' }}>{alert.mitre.id}</span>}
                        {alert.final?.final_score > 0 && (
                          <span style={{ fontSize: '0.75rem', color: 'var(--text-muted)' }}>Score: {alert.final.final_score}</span>
                        )}
                      </div>
                      <div style={{ fontSize: '0.8rem', color: 'var(--text-secondary)', fontFamily: 'var(--font-mono)' }}>
                        {alert.protocol || 'N/A'} · {ip}:{alert.sport || '?'} → {alert.dst_ip || 'N/A'}:{alert.dport || '?'}
                      </div>
                      {alert.mitre?.tactic && (
                        <div style={{ marginTop: 5, fontSize: '0.75rem', color: 'var(--accent2)' }}>
                          MITRE Tactic: {alert.mitre.tactic}
                        </div>
                      )}
                      {alert.shap?.length > 0 && (
                        <div style={{ display: 'flex', gap: 5, flexWrap: 'wrap', marginTop: 6 }}>
                          {alert.shap.map((s, i) => (
                            <span key={i} style={{ fontSize: '0.68rem', background: s.impact > 0 ? 'rgba(255,69,96,0.15)' : 'rgba(41,121,255,0.15)', color: s.impact > 0 ? 'var(--danger)' : 'var(--info)', padding: '2px 7px', borderRadius: 4 }}>
                              {s.feature}: {s.impact > 0 ? '+' : ''}{s.impact}
                            </span>
                          ))}
                        </div>
                      )}
                      <div style={{ marginTop: 5, fontSize: '0.72rem', color: 'var(--text-muted)' }}>
                        {alert.timestamp ? new Date(alert.timestamp * 1000).toLocaleString() : ''}
                        {alert.abuse_score > 0 && <span style={{ marginLeft: 12, color: alert.abuse_score > 50 ? 'var(--danger)' : 'var(--warning)' }}>⚠ Abuse: {alert.abuse_score}%</span>}
                      </div>
                    </div>

                    {/* Action buttons */}
                    <div style={{ display: 'flex', flexDirection: 'column', gap: 6, minWidth: 110 }}>
                      {ip !== 'N/A' && (
                        <button className="sf-btn sf-btn-danger sf-btn-sm" onClick={() => blockIP(ip)}>
                          {blockMsg[ip] || '🚫 Block IP'}
                        </button>
                      )}
                      {activeTab === 'medium' && (
                        <button className="sf-btn sf-btn-ghost sf-btn-sm" onClick={() => dismissAlert(alert)}>
                          ✓ Dismiss
                        </button>
                      )}
                      {activeTab === 'high' && (
                        <span style={{ fontSize: '0.7rem', color: 'var(--danger)', fontWeight: 700, textAlign: 'center' }}>AUTO-FLAGGED</span>
                      )}
                    </div>
                  </div>
                </div>
              );
            })}
          </div>

          {/* Show More / Less controls */}
          {remaining > 0 && (
            <div style={{ textAlign: 'center', marginTop: 18 }}>
              <button
                className="sf-btn sf-btn-ghost"
                onClick={() => dispatch(setAlertLimit(alertLimit + 500))}
                style={{ fontSize: '0.82rem' }}
              >
                ↓ Show {Math.min(remaining, 500)} more ({remaining} remaining)
              </button>
            </div>
          )}
          {alertLimit > 500 && (
            <div style={{ textAlign: 'center', marginTop: 8 }}>
              <button
                className="sf-btn sf-btn-ghost sf-btn-sm"
                onClick={() => dispatch(setAlertLimit(500))}
                style={{ fontSize: '0.78rem', color: 'var(--text-muted)' }}
              >
                ↑ Collapse
              </button>
            </div>
          )}
          <p style={{ textAlign: 'center', fontSize: '0.73rem', color: 'var(--text-muted)', marginTop: 10 }}>
            Showing {current.length} of {sorted.length} {activeTab} alerts this session
          </p>
        </>
      )}
    </div>
  );
}
