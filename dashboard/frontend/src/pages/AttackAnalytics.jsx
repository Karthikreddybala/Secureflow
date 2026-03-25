import React, { useMemo, useState, useEffect } from 'react';
import { useSelector } from 'react-redux';
import './css/attack.css';
import AlertControls from '../components/AlertControls.jsx';
import ProtocolPieChart from '../charts/ProtocolPieChart.jsx';
import AttackDistributionChart from '../charts/AttackDistributionChart.jsx';
import { selectFilteredAlerts, selectAlertStats } from '../store/slices/alertsSlice';

const API = 'http://127.0.0.1:8000/model_app'

function AttackAnalytics() {
  const filteredAlerts = useSelector((state) => selectFilteredAlerts(state));
  const alertStats = useSelector((state) => selectAlertStats(state));
  const [exporting, setExporting] = useState(false)
  const [incidents, setIncidents] = useState([])
  const [incFilter, setIncFilter] = useState('all')  // all | ongoing | resolved

  useEffect(() => {
    const fetchInc = async () => {
      try { const r = await fetch(`${API}/incidents`); const d = await r.json(); setIncidents(d.incidents || []) }
      catch {}
    }
    fetchInc()
    const id = setInterval(fetchInc, 5000)
    return () => clearInterval(id)
  }, [])

  const visibleInc = incidents.filter(i => incFilter === 'all' ? true : i.status === incFilter)
  const SEV_COLOR = { High:'#ff4444', Medium:'#ff9800', Low:'#4caf50' }
  const timeAgo = ts => { const d = Date.now()/1000-ts; if(d<60) return `${Math.round(d)}s ago`; if(d<3600) return `${Math.round(d/60)}m ago`; return `${Math.round(d/3600)}h ago` }

  const attackTypeBreakdown = useMemo(() => {
    const attackMap = new Map();

    filteredAlerts.forEach((alert) => {
      const attackType = alert.final?.attack_type || 'Unknown';
      attackMap.set(attackType, (attackMap.get(attackType) || 0) + 1);
    });

    return Array.from(attackMap.entries())
      .map(([type, count]) => ({ type, count }))
      .sort((left, right) => right.count - left.count)
      .slice(0, 8);
  }, [filteredAlerts]);

  const criticalAlerts = useMemo(() => {
    return filteredAlerts
      .filter((alert) => {
        const severity = (alert.final?.severity || '').toLowerCase();
        return severity === 'high' || severity === 'medium';
      })
      .slice(0, 10);
  }, [filteredAlerts]);

  const threatPressure = alertStats.total ? Math.round(((alertStats.high * 2 + alertStats.medium) / alertStats.total) * 100) : 0;

  const exportData = async (fmt) => {
    setExporting(true)
    try {
      const resp = await fetch(`${API}/export?format=${fmt}&limit=1000`)
      const blob = await resp.blob()
      const url  = URL.createObjectURL(blob)
      const a    = document.createElement('a')
      a.href     = url
      a.download = fmt === 'pdf' ? 'secureflow_report.pdf' : 'secureflow_alerts.csv'
      a.click()
      URL.revokeObjectURL(url)
    } catch { /* ignore */ }
    setExporting(false)
  }

  const blockIP = async (ip) => {
    await fetch(`${API}/block_ip`, {
      method: 'POST', headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ ip }),
    })
  }

  return (
    <div className="cyber-page attack-page">
      <div className="attack-layout">
        <section className="attack-controls cyber-panel">
          <div className="cyber-panel-header">
            <div>
              <h2 className="cyber-panel-title">Threat Analytics Control</h2>
              <p className="cyber-panel-subtitle">Filter and sort incoming alerts to inspect attack behavior trends.</p>
            </div>
            <div style={{ display: 'flex', gap: '8px', alignItems: 'center' }}>
              <span className="cyber-pill">Pressure {threatPressure}%</span>
              <button className="export-btn" onClick={() => exportData('csv')} disabled={exporting}>⬇ CSV</button>
              <button className="export-btn pdf" onClick={() => exportData('pdf')} disabled={exporting}>⬇ PDF</button>
            </div>
          </div>
          <AlertControls compact />
        </section>

        <section className="attack-charts">
          <div className="attack-chart-slot">
            <AttackDistributionChart />
          </div>
          <div className="attack-chart-slot">
            <ProtocolPieChart />
          </div>
        </section>

        <section className="attack-insights">
          <article className="attack-insight-card cyber-panel">
            <div className="cyber-panel-header">
              <h3 className="cyber-panel-title">Top Attack Classes</h3>
              <span className="cyber-pill">Top 8</span>
            </div>
            {attackTypeBreakdown.length === 0 ? (
              <div className="cyber-empty">No attack entries available for current filters.</div>
            ) : (
              <ul className="cyber-list attack-insight-list">
                {attackTypeBreakdown.map((entry) => (
                  <li key={entry.type} className="cyber-list-item attack-insight-item">
                    <span>{entry.type}</span>
                    <strong>{entry.count}</strong>
                  </li>
                ))}
              </ul>
            )}
          </article>

          <article className="attack-insight-card cyber-panel">
            <div className="cyber-panel-header">
              <h3 className="cyber-panel-title">Recent Critical Alerts</h3>
              <span className="cyber-pill">{criticalAlerts.length}</span>
            </div>
            {criticalAlerts.length === 0 ? (
              <div className="cyber-empty">No medium/high alerts found in current view.</div>
            ) : (
              <ul className="cyber-list attack-timeline-list">
                {criticalAlerts.map((alert, index) => (
                  <li key={alert.id || index} className="cyber-list-item attack-timeline-item">
                    <div>
                      <p className="attack-title">{alert.final?.attack_type || 'Unknown Attack'}</p>
                      <p className="attack-meta">
                        {alert.src_ip || 'N/A'}:{alert.sport || '-'} → {alert.dst_ip || 'N/A'}:{alert.dport || '-'}
                      </p>
                      {alert.mitre?.id && (
                        <span style={{ fontSize: '0.72rem', color: '#58a6ff', fontFamily: 'monospace' }}>
                          {alert.mitre.id} · {alert.mitre.tactic}
                        </span>
                      )}
                    </div>
                    <div className="attack-tag-wrap">
                      <span className={`attack-tag ${(alert.final?.severity || 'low').toLowerCase()}`}>{alert.final?.severity || 'Unknown'}</span>
                      {alert.src_ip && (
                        <button className="block-btn-sm" style={{ fontSize: '0.7rem', padding: '2px 8px', background: '#da363322', border: '1px solid #da3633', color: '#ff6b6b', borderRadius: '4px', cursor: 'pointer' }}
                          onClick={() => blockIP(alert.src_ip)}>🚫</button>
                      )}
                      <small>{alert.timestamp ? new Date(alert.timestamp * 1000).toLocaleTimeString() : 'N/A'}</small>
                    </div>
                  </li>
                ))}
              </ul>
            )}
          </article>
        </section>
        {/* ── Incident Timeline ────────────────────────────────── */}
        <section className="attack-incidents cyber-panel">
          <div className="cyber-panel-header">
            <div>
              <h3 className="cyber-panel-title">🔥 Incident Timeline</h3>
              <p className="cyber-panel-subtitle">Correlated attack patterns grouped by source IP + attack type · auto-refreshes every 5s</p>
            </div>
            <div style={{ display:'flex', gap:'6px', alignItems:'center' }}>
              {['all','ongoing','resolved'].map(f => (
                <button key={f} onClick={() => setIncFilter(f)}
                  style={{ background: incFilter===f ? '#58a6ff' : '#21262d',
                           color: incFilter===f ? '#0d1117' : '#8b949e',
                           border: `1px solid ${incFilter===f ? '#58a6ff' : '#30363d'}`,
                           padding:'4px 12px', borderRadius:'20px', cursor:'pointer',
                           fontSize:'0.78rem', fontWeight: incFilter===f ? '700' : '400' }}>
                  {f.charAt(0).toUpperCase()+f.slice(1)}
                </button>
              ))}
              <span className="cyber-pill">{incidents.filter(i=>i.status==='ongoing').length} live</span>
            </div>
          </div>

          {visibleInc.length === 0 ? (
            <div className="cyber-empty">
              No incidents yet. They appear when the same source IP generates repeated alerts.
            </div>
          ) : (
            <div className="inc-grid">
              {visibleInc.slice(0,12).map(inc => (
                <div key={inc.id} className="inc-embed-card"
                  style={{ borderLeft:`3px solid ${SEV_COLOR[inc.severity]||'#58a6ff'}` }}>
                  <div style={{ display:'flex', justifyContent:'space-between', alignItems:'flex-start', marginBottom:'6px' }}>
                    <div style={{ display:'flex', gap:'8px', alignItems:'center', flexWrap:'wrap' }}>
                      <span style={{ fontSize:'0.68rem', fontWeight:'700',
                        color: inc.status==='ongoing'?'#ff4444':'#4caf50' }}>
                        {inc.status==='ongoing'?'🔴':'✅'} {inc.status}
                      </span>
                      <strong style={{ fontSize:'0.9rem', color:'#e6edf3' }}>{inc.attack_type}</strong>
                      {inc.mitre?.id && (
                        <span style={{ fontFamily:'monospace', fontSize:'0.68rem', color:'#58a6ff',
                          background:'rgba(31,111,235,.15)', border:'1px solid rgba(31,111,235,.4)',
                          padding:'1px 5px', borderRadius:'3px' }}>{inc.mitre.id}</span>
                      )}
                    </div>
                    <span style={{ background: SEV_COLOR[inc.severity]||'#58a6ff', color:'#fff',
                      fontSize:'0.65rem', fontWeight:'700', padding:'2px 8px', borderRadius:'10px' }}>
                      {inc.severity}
                    </span>
                  </div>
                  <div style={{ display:'flex', gap:'16px', flexWrap:'wrap', fontSize:'0.78rem', color:'#8b949e', marginBottom:'6px' }}>
                    <span><b style={{color:'#e6edf3'}}>Src:</b> <code style={{color:'#58a6ff'}}>{inc.src_ip}</code></span>
                    <span><b style={{color:'#e6edf3'}}>Alerts:</b> {inc.alert_count}</span>
                    <span><b style={{color:'#e6edf3'}}>Rate:</b> {inc.peak_rate}/s</span>
                    <span><b style={{color:'#e6edf3'}}>Started:</b> {timeAgo(inc.start)}</span>
                  </div>
                  <div style={{ display:'flex', justifyContent:'space-between', alignItems:'center' }}>
                    <div style={{ display:'flex', gap:'4px', flexWrap:'wrap' }}>
                      {inc.dst_ports?.slice(0,5).map(p => (
                        <span key={p} style={{ background:'#21262d', border:'1px solid #30363d',
                          color:'#8b949e', padding:'1px 5px', borderRadius:'3px', fontSize:'0.7rem', fontFamily:'monospace' }}>:{p}</span>
                      ))}
                    </div>
                    <button onClick={() => blockIP(inc.src_ip)}
                      style={{ background:'rgba(218,54,51,.15)', border:'1px solid #da3633', color:'#ff6b6b',
                               fontSize:'0.72rem', padding:'3px 10px', borderRadius:'4px', cursor:'pointer' }}>
                      🚫 Block {inc.src_ip}
                    </button>
                  </div>
                </div>
              ))}
            </div>
          )}
        </section>
      </div>
    </div>
  );
}

export default AttackAnalytics;
