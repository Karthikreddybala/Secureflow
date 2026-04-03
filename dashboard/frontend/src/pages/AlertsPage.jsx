import React, { useState } from 'react';
import { useSelector } from 'react-redux';
import { useAuth } from '../context/AuthContext';

const ML_API = 'http://127.0.0.1:8000/model_app';
const AUTH_API = 'http://127.0.0.1:5000';

function sev(alert) { return (alert.final?.severity || 'low').toLowerCase(); }
function isNormal(alert) { return (alert.final?.attack_type || '').toLowerCase() === 'normal'; }

export default function AlertsPage() {
  const allAlerts = useSelector(s => s.alerts.alerts);
  const { user, isAdmin } = useAuth();
  const [activeTab, setActiveTab] = useState('high');
  const [dismissed, setDismissed] = useState(new Set());
  const [blockMsg, setBlockMsg] = useState({});

  const highs   = allAlerts.filter(a => !isNormal(a) && sev(a) === 'high');
  const mediums  = allAlerts.filter(a => !isNormal(a) && sev(a) === 'medium' && !dismissed.has(a.id || a.src_ip));
  const lows     = allAlerts.filter(a => isNormal(a) || sev(a) === 'low');

  const blockIP = async (ip, reason = 'Manual block from Alerts page') => {
    try {
      await fetch(`${ML_API}/blocked_ips_db`, {
        method: 'POST', headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ ip, action: 'block', reason, blocked_by: user?.username || 'dashboard' }),
      });
      // Log action to Node.js backend
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

  const current = activeTab === 'high' ? highs : activeTab === 'medium' ? mediums : lows;

  return (
    <div className="sf-page anim-fade-in">
      <div style={{ marginBottom: 24 }}>
        <h2 style={{ fontSize: '1.4rem', fontWeight: 800, color: 'var(--text-primary)', margin: 0 }}>Alert Center</h2>
        <p style={{ color: 'var(--text-secondary)', fontSize: '0.85rem', marginTop: 4 }}>
          Real-time IDS alerts grouped by severity. Medium alerts require action.
        </p>
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
          <span className="sf-kpi-label">Total Active</span>
          <span className="sf-kpi-value accent">{allAlerts.length}</span>
        </div>
      </div>

      {/* Tabs */}
      <div className="sf-tabs">
        {tabs.map(t => (
          <button key={t.id} className={`sf-tab ${t.cls} ${activeTab === t.id ? 'active' : ''}`} onClick={() => setActiveTab(t.id)}>
            {t.label} <span className="tab-count">{t.count}</span>
          </button>
        ))}
      </div>

      {/* Medium: Pending actions banner */}
      {activeTab === 'medium' && mediums.length > 0 && (
        <div style={{ background: 'rgba(255,184,0,0.08)', border: '1px solid rgba(255,184,0,0.25)', borderRadius: 10, padding: '12px 16px', marginBottom: 18, fontSize: '0.85rem', color: 'var(--warning)' }}>
          ⚡ <strong>Pending Action Queue</strong> — {mediums.length} medium-severity {mediums.length === 1 ? 'alert' : 'alerts'} awaiting your decision. Block or dismiss each alert.
        </div>
      )}

      {/* Alert list */}
      {current.length === 0 ? (
        <div className="sf-empty"><span className="sf-empty-icon">🛡</span><span>No {activeTab} alerts right now</span></div>
      ) : (
        <div style={{ display: 'flex', flexDirection: 'column', gap: 8 }}>
          {current.slice(0, 50).map((alert, idx) => {
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
      )}
    </div>
  );
}
