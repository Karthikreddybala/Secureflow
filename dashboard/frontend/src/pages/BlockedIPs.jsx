import React, { useMemo, useEffect, useRef, useState, useCallback } from 'react';
import { useSelector } from 'react-redux';
import { Network } from 'vis-network';
import './css/blockedip.css';
import ThreatLeaderboard from '../components/ThreatLeaderboard.jsx';
import { selectFilteredAlerts, selectAlertStats } from '../store/slices/alertsSlice';

const API = 'http://127.0.0.1:8000/model_app'

const ATTACK_COLORS = {
  DoS:'#ff4444', DDoS:'#ff0000', PortScan:'#ff9800', BruteForce:'#e91e63',
  Botnet:'#9c27b0', Infiltration:'#f44336', Heartbleed:'#b71c1c', Normal:'#4caf50',
}
const SIM_TYPES = ['DoS','DDoS','PortScan','BruteForce','Botnet','Normal']

function calculateSeverityWeight(severity) {
  const key = (severity || '').toLowerCase();
  if (key === 'high') return 3;
  if (key === 'medium') return 2;
  if (key === 'low') return 1;
  return 1;
}

function BlockedIPs() {
  const filteredAlerts = useSelector((state) => selectFilteredAlerts(state));
  const alertStats = useSelector((state) => selectAlertStats(state));

  // ── Topology state ────────────────────────────────────────────────────────
  const containerRef = useRef(null)
  const networkRef   = useRef(null)
  const [topoHosts, setTopoHosts]   = useState([])
  const [selected,  setSelected]    = useState(null)
  const [simType,   setSimType]     = useState('DoS')
  const [simState,  setSimState]    = useState('idle')
  const [blockMsg,  setBlockMsg]    = useState('')

  const fetchHosts = useCallback(async () => {
    try { const r = await fetch(`${API}/hosts`); const d = await r.json(); setTopoHosts(d.hosts || []) }
    catch {}
  }, [])

  useEffect(() => { fetchHosts(); const id = setInterval(fetchHosts, 8000); return () => clearInterval(id) }, [fetchHosts])

  // ── Build vis-network graph ───────────────────────────────────────────────
  useEffect(() => {
    if (!containerRef.current) return
    const myNode = { id:'you', label:'🛡 Your Network', color:'#1e88e5', shape:'ellipse', size:40, font:{size:13,color:'#fff'} }
    const nodes = [myNode, ...topoHosts.slice(0,25).map(h => {
      const color = ATTACK_COLORS[h.attacks?.[0]] || '#ff4444'
      const size  = Math.max(12, Math.min(35, 10 + h.score * 0.4))
      return { id:h.ip, label:`${h.ip}\nScore: ${h.score}`, color:{background:color,border:'#fff'},
               shape:'dot', size, font:{size:10,color:'#fff',strokeWidth:2,strokeColor:'#000'} }
    })]
    const edges = topoHosts.slice(0,25).map(h => ({
      from:h.ip, to:'you',
      color:{color: ATTACK_COLORS[h.attacks?.[0]] || '#ff4444', opacity:0.5},
      width: Math.max(1, Math.min(6, h.score/15)), arrows:'to',
      smooth:{type:'curvedCW',roundness:0.2}
    }))
    if (networkRef.current) networkRef.current.destroy()
    const net = new Network(containerRef.current, {nodes,edges}, {
      nodes:{borderWidth:2,shadow:true},
      physics:{enabled:true,barnesHut:{gravitationalConstant:-3000,springLength:160}},
      interaction:{hover:true},
    })
    net.on('click', params => {
      const ip = params.nodes[0]
      if (ip && ip !== 'you') setSelected(topoHosts.find(x => x.ip === ip) || null)
      else setSelected(null)
    })
    networkRef.current = net
  }, [topoHosts])

  const blockIPDirect = async (ip) => {
    try {
      const r = await fetch(`${API}/block_ip`, { method:'POST', headers:{'Content-Type':'application/json'}, body:JSON.stringify({ip}) })
      const d = await r.json()
      setBlockMsg(d.status === 'blocked' ? `✅ Blocked ${ip}` : `❌ ${d.error||'Failed'}`)
    } catch { setBlockMsg('❌ Connection error') }
    setTimeout(() => setBlockMsg(''), 3000)
  }

  const simulate = async () => {
    setSimState('running')
    try { await fetch(`${API}/simulate`, { method:'POST', headers:{'Content-Type':'application/json'}, body:JSON.stringify({attack_type:simType}) })
          setTimeout(fetchHosts, 2000) }
    catch {}
    setSimState('done')
    setTimeout(() => setSimState('idle'), 4000)
  }

  const sourceProfiles = useMemo(() => {
    const profileMap = new Map();

    filteredAlerts.forEach((alert) => {
      const sourceIp = alert.src_ip || alert.src || 'Unknown';
      const destinationIp = alert.dst_ip || alert.dst || 'Unknown';
      const severity = alert.final?.severity || 'Unknown';
      const attackType = alert.final?.attack_type || 'Unknown';
      const score = Number(alert.final?.final_score || 0);

      if (!profileMap.has(sourceIp)) {
        profileMap.set(sourceIp, {
          ip: sourceIp,
          hits: 0,
          highestSeverity: 'Low',
          severityWeight: 0,
          destinations: new Set(),
          attackTypes: new Set(),
          scoreTotal: 0,
          lastSeen: null
        });
      }

      const profile = profileMap.get(sourceIp);
      profile.hits += 1;
      profile.destinations.add(destinationIp);
      profile.attackTypes.add(attackType);
      profile.scoreTotal += score;

      const severityWeight = calculateSeverityWeight(severity);
      if (severityWeight >= profile.severityWeight) {
        profile.severityWeight = severityWeight;
        profile.highestSeverity = severity;
      }

      const timestamp = alert.timestamp ? new Date(alert.timestamp).getTime() : 0;
      if (!profile.lastSeen || timestamp > profile.lastSeen) {
        profile.lastSeen = timestamp;
      }
    });

    return Array.from(profileMap.values())
      .map((profile) => ({
        ...profile,
        destinationCount: profile.destinations.size,
        attackTypeCount: profile.attackTypes.size,
        riskScore: Math.round(profile.hits * 10 + profile.severityWeight * 14 + profile.scoreTotal),
        avgScore: profile.hits ? (profile.scoreTotal / profile.hits).toFixed(2) : '0.00'
      }))
      .sort((left, right) => right.riskScore - left.riskScore);
  }, [filteredAlerts]);

  const destinationFocus = useMemo(() => {
    const destinationMap = new Map();

    filteredAlerts.forEach((alert) => {
      const destinationIp = alert.dst_ip || alert.dst || 'Unknown';
      destinationMap.set(destinationIp, (destinationMap.get(destinationIp) || 0) + 1);
    });

    return Array.from(destinationMap.entries())
      .map(([ip, hits]) => ({ ip, hits }))
      .sort((left, right) => right.hits - left.hits)
      .slice(0, 8);
  }, [filteredAlerts]);

  const recentEvents = filteredAlerts.slice(0, 10);

  return (
    <div className="cyber-page blockedip-page">
      <div className="blocked-layout">
        <section className="blocked-overview cyber-panel">
          <div className="cyber-panel-header">
            <div>
              <h2 className="cyber-panel-title">Blocked IP Intelligence</h2>
              <p className="cyber-panel-subtitle">Hostile source profiling based on observed alert traffic.</p>
            </div>
            <span className="cyber-pill">{sourceProfiles.length} Sources</span>
          </div>

          <div className="cyber-kpi-grid blocked-kpis">
            <div className="cyber-kpi-card">
              <span className="cyber-kpi-label">Alert Volume</span>
              <span className="cyber-kpi-value">{alertStats.total}</span>
            </div>
            <div className="cyber-kpi-card">
              <span className="cyber-kpi-label">Attack Alerts</span>
              <span className="cyber-kpi-value">{alertStats.attacks}</span>
            </div>
            <div className="cyber-kpi-card">
              <span className="cyber-kpi-label">High Severity</span>
              <span className="cyber-kpi-value">{alertStats.high}</span>
            </div>
            <div className="cyber-kpi-card">
              <span className="cyber-kpi-label">Tracked Sources</span>
              <span className="cyber-kpi-value">{sourceProfiles.length}</span>
            </div>
          </div>
        </section>

        <section className="blocked-main cyber-panel">
          <div className="cyber-panel-header">
            <h3 className="cyber-panel-title">Hostile Source Ranking</h3>
            <span className="cyber-pill">Risk Ordered</span>
          </div>

          {sourceProfiles.length === 0 ? (
            <div className="cyber-empty">No suspicious source profiles available yet.</div>
          ) : (
            <div className="blocked-table-scroll">
              <table className="blocked-table">
                <thead>
                  <tr>
                    <th>Source IP</th>
                    <th>Risk Score</th>
                    <th>Hits</th>
                    <th>Severity</th>
                    <th>Targets</th>
                    <th>Attack Types</th>
                    <th>Avg Score</th>
                    <th>Last Seen</th>
                  </tr>
                </thead>
                <tbody>
                  {sourceProfiles.slice(0, 24).map((profile) => (
                    <tr key={profile.ip}>
                      <td>
                        <code>{profile.ip}</code>
                      </td>
                      <td>{profile.riskScore}</td>
                      <td>{profile.hits}</td>
                      <td>
                        <span className={`blocked-severity ${(profile.highestSeverity || 'low').toLowerCase()}`}>{profile.highestSeverity}</span>
                      </td>
                      <td>{profile.destinationCount}</td>
                      <td>{profile.attackTypeCount}</td>
                      <td>{profile.avgScore}</td>
                      <td>{profile.lastSeen ? new Date(profile.lastSeen).toLocaleTimeString() : 'N/A'}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}
        </section>

        <aside className="blocked-side">
          <article className="blocked-side-card cyber-panel">
            <div className="cyber-panel-header">
              <h3 className="cyber-panel-title">Most Targeted Destinations</h3>
              <span className="cyber-pill">Top 8</span>
            </div>
            {destinationFocus.length === 0 ? (
              <div className="cyber-empty">No destination hotspots detected.</div>
            ) : (
              <ul className="cyber-list">
                {destinationFocus.map((destination) => (
                  <li key={destination.ip} className="cyber-list-item blocked-list-item">
                    <code>{destination.ip}</code>
                    <strong>{destination.hits} hits</strong>
                  </li>
                ))}
              </ul>
            )}
          </article>

          <article className="blocked-side-card cyber-panel">
            <div className="cyber-panel-header">
              <h3 className="cyber-panel-title">Recent Suspicious Events</h3>
              <span className="cyber-pill">Latest 10</span>
            </div>
            {recentEvents.length === 0 ? (
              <div className="cyber-empty">No recent suspicious events.</div>
            ) : (
              <ul className="cyber-list blocked-event-list">
                {recentEvents.map((alert, index) => (
                  <li key={alert.id || index} className="cyber-list-item blocked-event-item">
                    <div>
                      <p>{alert.final?.attack_type || 'Unknown Attack'}</p>
                      <small>
                        {alert.src_ip || 'N/A'} -&gt; {alert.dst_ip || 'N/A'}
                      </small>
                    </div>
                    <span className={`blocked-severity ${(alert.final?.severity || 'low').toLowerCase()}`}>{alert.final?.severity || 'Unknown'}</span>
                  </li>
                ))}
              </ul>
            )}
          </article>
        </aside>
        {/* ── Network Topology ─────────────────────────────── */}
        <section className="cyber-panel" style={{ marginTop: '16px' }}>
          <div className="cyber-panel-header">
            <div>
              <h3 className="cyber-panel-title">🌐 Network Topology — Live Attack Graph</h3>
              <p className="cyber-panel-subtitle">Node size = threat score · Color = attack type · Click node to inspect</p>
            </div>
            <div style={{ display:'flex', gap:'8px', alignItems:'center', flexWrap:'wrap' }}>
              <select value={simType} onChange={e => setSimType(e.target.value)}
                style={{ background:'#0d1117', border:'1px solid #30363d', color:'#fff', padding:'5px 10px', borderRadius:'6px', fontSize:'0.82rem' }}>
                {SIM_TYPES.map(t => <option key={t}>{t}</option>)}
              </select>
              <button onClick={simulate} disabled={simState==='running'}
                style={{ background:'linear-gradient(135deg,#e91e63,#ff4444)', border:'none', color:'#fff',
                         padding:'6px 14px', borderRadius:'6px', fontWeight:'700', cursor:'pointer',
                         opacity: simState==='running' ? 0.6 : 1 }}>
                {simState==='running' ? '⏳ Simulating…' : simState==='done' ? '✅ Done' : '⚡ Simulate'}
              </button>
              {blockMsg && <span style={{ color:'#4caf50', fontSize:'0.85rem', fontWeight:'700' }}>{blockMsg}</span>}
            </div>
          </div>

          <div style={{ display:'flex', gap:'16px', height:'420px' }}>
            {/* Graph canvas */}
            <div ref={containerRef} style={{ flex:1, background:'#0d1117', borderRadius:'10px',
                  border:'1px solid #30363d', position:'relative', overflow:'hidden' }}>
              {topoHosts.length === 0 && (
                <div style={{ position:'absolute', inset:0, display:'flex', alignItems:'center',
                              justifyContent:'center', color:'#8b949e', textAlign:'center', padding:'20px' }}>
                  No threats yet. Start backend + PCAP replay, then simulate an attack above.
                </div>
              )}
            </div>

            {/* Node detail card */}
            {selected && (
              <div style={{ width:'220px', background:'#161b22', border:'1px solid #30363d',
                            borderRadius:'10px', padding:'16px', display:'flex', flexDirection:'column', gap:'10px' }}>
                <h4 style={{ margin:0, color:'#e6edf3', wordBreak:'break-all', fontSize:'0.9rem' }}>{selected.ip}</h4>
                <div>
                  <div style={{ fontSize:'0.72rem', color:'#8b949e', marginBottom:'4px' }}>Threat Score</div>
                  <div style={{ height:'8px', background:'#21262d', borderRadius:'4px', overflow:'hidden' }}>
                    <div style={{ height:'100%', borderRadius:'4px', transition:'width 0.5s',
                      width:`${selected.score}%`,
                      background: selected.score>70?'#ff4444':selected.score>40?'#ff9800':'#4caf50' }} />
                  </div>
                  <strong style={{ fontSize:'1.2rem', color:'#fff' }}>{selected.score}</strong>
                </div>
                <p style={{ margin:0, fontSize:'0.82rem', color:'#8b949e' }}>
                  <b style={{color:'#e6edf3'}}>Attacks:</b> {selected.attacks?.join(', ') || 'None'}
                </p>
                <button onClick={() => blockIPDirect(selected.ip)}
                  style={{ background:'#da3633', border:'none', color:'#fff', padding:'7px',
                           borderRadius:'6px', fontWeight:'700', cursor:'pointer', marginTop:'auto' }}>
                  🚫 Block IP
                </button>
              </div>
            )}
          </div>

          {/* Colour legend */}
          <div style={{ display:'flex', gap:'12px', flexWrap:'wrap', marginTop:'10px' }}>
            {Object.entries(ATTACK_COLORS).map(([k,v]) => (
              <span key={k} style={{ display:'flex', alignItems:'center', gap:'5px', fontSize:'0.75rem', color:'#8b949e' }}>
                <span style={{ width:'10px', height:'10px', borderRadius:'50%', background:v, display:'inline-block' }} />{k}
              </span>
            ))}
          </div>
        </section>

        {/* ── Threat Leaderboard ──────────────────────────── */}
        <ThreatLeaderboard />
      </div>
    </div>
  );
}

export default BlockedIPs;
