import React, { useEffect, useState } from 'react'
import './css/Incidents.css'

const API = 'http://127.0.0.1:8000/model_app'

const SEVERITY_COLOR = { High: '#ff4444', Medium: '#ff9800', Low: '#4caf50' }

function timeAgo(ts) {
  const diff = Date.now() / 1000 - ts
  if (diff < 60)  return `${Math.round(diff)}s ago`
  if (diff < 3600) return `${Math.round(diff / 60)}m ago`
  return `${Math.round(diff / 3600)}h ago`
}

export default function Incidents() {
  const [incidents, setIncidents] = useState([])
  const [loading, setLoading]     = useState(true)
  const [filter, setFilter]       = useState('all')  // all | ongoing | resolved

  const fetchIncidents = async () => {
    try {
      const r = await fetch(`${API}/incidents`)
      const d = await r.json()
      setIncidents(d.incidents || [])
    } catch { /* offline */ }
    setLoading(false)
  }

  useEffect(() => {
    fetchIncidents()
    const id = setInterval(fetchIncidents, 5000)
    return () => clearInterval(id)
  }, [])

  const visible = incidents.filter(i =>
    filter === 'all' ? true : i.status === filter
  )

  const blockIP = async (ip) => {
    await fetch(`${API}/block_ip`, {
      method: 'POST', headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ ip }),
    })
  }

  return (
    <div className="incidents-page">
      <div className="incidents-header">
        <div>
          <h1>🔥 Incident Timeline</h1>
          <p>Correlated attack patterns grouped by source IP + attack type</p>
        </div>
        <div className="inc-stats">
          <div className="inc-stat">
            <span>{incidents.filter(i => i.status === 'ongoing').length}</span>
            <label>Ongoing</label>
          </div>
          <div className="inc-stat">
            <span>{incidents.filter(i => i.status === 'resolved').length}</span>
            <label>Resolved</label>
          </div>
          <div className="inc-stat">
            <span>{incidents.reduce((s, i) => s + (i.alert_count || 0), 0)}</span>
            <label>Total Alerts</label>
          </div>
        </div>
        <div className="inc-filters">
          {['all', 'ongoing', 'resolved'].map(f =>
            <button key={f} className={`filter-btn ${filter === f ? 'active' : ''}`}
                    onClick={() => setFilter(f)}>
              {f.charAt(0).toUpperCase() + f.slice(1)}
            </button>
          )}
        </div>
      </div>

      {loading && <div className="loading-msg">Loading incidents…</div>}

      {!loading && visible.length === 0 && (
        <div className="empty-msg">
          <div className="empty-icon">🛡️</div>
          <h3>No incidents yet</h3>
          <p>Incidents appear when the same source IP generates repeated alerts. Start the backend and PCAP replay, or use the Simulate button on the Topology page.</p>
        </div>
      )}

      <div className="incidents-list">
        {visible.map(inc => (
          <div key={inc.id} className={`incident-card severity-${inc.severity?.toLowerCase()}`}>
            <div className="inc-top">
              <div className="inc-left">
                <span className={`status-badge ${inc.status}`}>{inc.status === 'ongoing' ? '🔴' : '✅'} {inc.status}</span>
                <h2 className="inc-type">{inc.attack_type}</h2>
                {inc.mitre?.id && (
                  <span className="mitre-badge">
                    <span className="mitre-id">{inc.mitre.id}</span>
                    <span className="mitre-tactic">{inc.mitre.tactic}</span>
                  </span>
                )}
              </div>
              <div className="inc-right">
                <span className="sev-badge" style={{ background: SEVERITY_COLOR[inc.severity] }}>
                  {inc.severity}
                </span>
              </div>
            </div>

            <div className="inc-body">
              <div className="inc-meta">
                <div><label>Source IP</label><span className="mono">{inc.src_ip}</span></div>
                <div><label>Alerts</label><span>{inc.alert_count}</span></div>
                <div><label>Rate</label><span>{inc.peak_rate} alerts/s</span></div>
                <div><label>Started</label><span>{timeAgo(inc.start)}</span></div>
                <div><label>Last Alert</label><span>{timeAgo(inc.last_alert_time)}</span></div>
              </div>

              {inc.dst_ports?.length > 0 && (
                <div className="port-chips">
                  <label>Target Ports:</label>
                  {inc.dst_ports.slice(0, 8).map(p =>
                    <span key={p} className="port-chip">:{p}</span>)}
                  {inc.dst_ports.length > 8 && <span className="port-chip">+{inc.dst_ports.length - 8}</span>}
                </div>
              )}
            </div>

            <div className="inc-actions">
              <button className="btn-block-sm" onClick={() => blockIP(inc.src_ip)}>
                🚫 Block {inc.src_ip}
              </button>
              <span className="inc-id">#{inc.id}</span>
            </div>
          </div>
        ))}
      </div>
    </div>
  )
}
