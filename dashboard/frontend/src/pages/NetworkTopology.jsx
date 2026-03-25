import React, { useEffect, useRef, useState, useCallback } from 'react'
import { Network } from 'vis-network'
import './css/NetworkTopology.css'

const API = 'http://127.0.0.1:8000/model_app'

const ATTACK_COLORS = {
  DoS:        '#ff4444',
  DDoS:       '#ff0000',
  PortScan:   '#ff9800',
  BruteForce: '#e91e63',
  Botnet:     '#9c27b0',
  Infiltration:'#f44336',
  Heartbleed: '#b71c1c',
  Anomaly:    '#ff6b35',
  Normal:     '#4caf50',
}

export default function NetworkTopology() {
  const containerRef = useRef(null)
  const networkRef   = useRef(null)
  const [hosts, setHosts]       = useState([])
  const [selected, setSelected] = useState(null)
  const [loading, setLoading]   = useState(true)
  const [simRunning, setSimRunning] = useState(false)
  const [simType, setSimType]   = useState('DoS')
  const [blockMsg, setBlockMsg] = useState('')

  // ── Fetch host scores ────────────────────────────────────────────────────────
  const fetchHosts = useCallback(async () => {
    try {
      const r = await fetch(`${API}/hosts`)
      const d = await r.json()
      setHosts(d.hosts || [])
    } catch { /* offline */ }
    setLoading(false)
  }, [])

  useEffect(() => {
    fetchHosts()
    const id = setInterval(fetchHosts, 8000)
    return () => clearInterval(id)
  }, [fetchHosts])

  // ── Build / update vis-network ───────────────────────────────────────────────
  useEffect(() => {
    if (!containerRef.current) return

    const myNode = { id: 'you', label: '🛡 Your Network', color: '#1e88e5',
                     shape: 'ellipse', size: 40, font: { size: 14, color: '#fff' } }

    const nodes = [myNode, ...hosts.slice(0, 30).map((h, i) => {
      const attack = h.attacks?.[0] || 'Normal'
      const color  = ATTACK_COLORS[attack] || '#ff4444'
      const size   = Math.max(15, Math.min(40, 10 + h.score * 0.4))
      return {
        id:    h.ip,
        label: `${h.ip}\nScore: ${h.score}`,
        color: { background: color, border: '#fff', highlight: { background: color, border: '#fff' } },
        shape: 'dot',
        size,
        font:  { size: 11, color: '#fff', strokeWidth: 2, strokeColor: '#000' },
      }
    })]

    const edges = hosts.slice(0, 30).map(h => ({
      from: h.ip, to: 'you',
      color:  { color: ATTACK_COLORS[h.attacks?.[0]] || '#ff4444', opacity: 0.6 },
      width:  Math.max(1, Math.min(8, h.score / 15)),
      arrows: 'to',
      smooth: { type: 'curvedCW', roundness: 0.2 },
    }))

    const options = {
      nodes:   { borderWidth: 2, shadow: true },
      edges:   { smooth: { enabled: true } },
      physics: { enabled: true, barnesHut: { gravitationalConstant: -3000, springLength: 180 } },
      interaction: { hover: true, tooltipDelay: 100 },
      background: '#0d1117',
    }

    if (networkRef.current) {
      networkRef.current.destroy()
    }

    const net = new Network(containerRef.current, { nodes, edges }, options)
    net.on('click', (params) => {
      if (params.nodes.length) {
        const ip = params.nodes[0]
        const h  = hosts.find(x => x.ip === ip)
        if (h) setSelected(h)
      } else {
        setSelected(null)
      }
    })
    networkRef.current = net
  }, [hosts])

  // ── Block IP ─────────────────────────────────────────────────────────────────
  const blockIP = async (ip) => {
    try {
      const r = await fetch(`${API}/block_ip`, {
        method: 'POST', headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ ip }),
      })
      const d = await r.json()
      setBlockMsg(d.status === 'blocked' ? `✅ Blocked ${ip}` : `❌ ${d.error || 'Failed'}`)
    } catch { setBlockMsg('❌ Connection error') }
    setTimeout(() => setBlockMsg(''), 3000)
  }

  // ── Simulate attack ──────────────────────────────────────────────────────────
  const simulate = async () => {
    setSimRunning(true)
    try {
      await fetch(`${API}/simulate`, {
        method: 'POST', headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ attack_type: simType }),
      })
      setTimeout(fetchHosts, 2000)
    } catch { /* ignore */ }
    setSimRunning(false)
  }

  return (
    <div className="topology-page">
      <div className="topo-header">
        <h1>🌐 Network Topology</h1>
        <p className="topo-sub">Live attack graph — node size = threat score, color = attack type</p>
        <div className="topo-controls">
          <select value={simType} onChange={e => setSimType(e.target.value)}>
            {['DoS','DDoS','PortScan','BruteForce','Botnet','Normal'].map(t =>
              <option key={t}>{t}</option>)}
          </select>
          <button className="btn-sim" onClick={simulate} disabled={simRunning}>
            {simRunning ? '⏳ Simulating…' : '⚡ Simulate Attack'}
          </button>
          {blockMsg && <span className="block-msg">{blockMsg}</span>}
        </div>
      </div>

      <div className="topo-body">
        <div className="graph-wrap" ref={containerRef}>
          {loading && <div className="graph-loading">Loading topology…</div>}
          {!loading && hosts.length === 0 &&
            <div className="graph-empty">No threats detected yet. Start backend + PCAP replay or use Simulate.</div>}
        </div>

        {selected && (
          <div className="node-card">
            <h3>🔎 {selected.ip}</h3>
            <div className="nc-score">
              <span>Threat Score</span>
              <div className="score-bar">
                <div className="score-fill" style={{
                  width: `${selected.score}%`,
                  background: selected.score > 70 ? '#ff4444' : selected.score > 40 ? '#ff9800' : '#4caf50'
                }} />
              </div>
              <strong>{selected.score}</strong>
            </div>
            <p><b>Attacks:</b> {selected.attacks?.join(', ') || 'None'}</p>
            <p><b>Last seen:</b> {selected.last_seen
              ? new Date(selected.last_seen * 1000).toLocaleTimeString() : '—'}</p>
            <button className="btn-block" onClick={() => blockIP(selected.ip)}>
              🚫 Block IP
            </button>
          </div>
        )}
      </div>

      <div className="legend">
        {Object.entries(ATTACK_COLORS).map(([k, v]) =>
          <span key={k} className="legend-item">
            <span className="legend-dot" style={{ background: v }} />
            {k}
          </span>)}
      </div>
    </div>
  )
}
