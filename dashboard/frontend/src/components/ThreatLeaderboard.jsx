import React, { useEffect, useState } from 'react'
import './ThreatLeaderboard.css'

const API = 'http://127.0.0.1:8000/model_app'

export default function ThreatLeaderboard() {
  const [hosts, setHosts] = useState([])

  useEffect(() => {
    const fetch_ = async () => {
      try {
        const r = await fetch(`${API}/hosts`)
        const d = await r.json()
        setHosts((d.hosts || []).slice(0, 7))
      } catch { /* offline */ }
    }
    fetch_()
    const id = setInterval(fetch_, 10000)
    return () => clearInterval(id)
  }, [])

  const scoreColor = (s) =>
    s >= 70 ? '#ff4444' : s >= 40 ? '#ff9800' : '#4caf50'

  if (hosts.length === 0) return null

  return (
    <div className="threat-leaderboard">
      <div className="tlb-header">
        <span>🎯 Most Suspicious Hosts</span>
        <span className="tlb-sub">Auto-decaying threat scores</span>
      </div>
      {hosts.map((h, i) => (
        <div key={h.ip} className="tlb-row">
          <span className="tlb-rank">#{i + 1}</span>
          <span className="tlb-ip">{h.ip}</span>
          <div className="tlb-bar-wrap">
            <div className="tlb-bar-fill" style={{
              width: `${h.score}%`,
              background: scoreColor(h.score),
            }} />
          </div>
          <span className="tlb-score" style={{ color: scoreColor(h.score) }}>
            {h.score}
          </span>
          <span className="tlb-attacks">{h.attacks?.slice(0,2).join(', ')}</span>
        </div>
      ))}
    </div>
  )
}
