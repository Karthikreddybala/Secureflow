import React, { useMemo, useState } from 'react';
import { useSelector, useDispatch } from 'react-redux';
import './css/traffic.css';
import LiveTrafficTable from '../charts/livetrafic';
import ConnectionStatus from '../components/ConnectionStatus.jsx';
import { pauseNetworkData, resumeNetworkData, clearNetworkData } from '../store/slices/networkDataSlice';

const API = 'http://127.0.0.1:8000/model_app'
const SIM_TYPES = ['DoS', 'DDoS', 'PortScan', 'BruteForce', 'Botnet', 'Normal']

function RealTimeTraffic() {
  const dispatch = useDispatch();
  const networkData = useSelector((state) => state.networkData.networkData);
  const isPaused = useSelector((state) => state.networkData.isPaused);
  const packetCount = useSelector((state) => state.networkData.packetCount);
  const lastNetworkTime = useSelector((state) => state.networkData.lastNetworkTime);
  const [simType, setSimType]     = useState('DoS')
  const [simState, setSimState]   = useState('idle')  // idle | running | done
  const [simResult, setSimResult] = useState(null)

  const simulate = async () => {
    setSimState('running')
    try {
      const r = await fetch(`${API}/simulate`, {
        method: 'POST', headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ attack_type: simType }),
      })
      const d = await r.json()
      setSimResult(d)
    } catch { setSimResult({ error: 'Connection failed' }) }
    setSimState('done')
    setTimeout(() => setSimState('idle'), 4000)
  }

  const protocolSummary = useMemo(() => {
    return networkData.reduce(
      (accumulator, packet) => {
        const protocolValue = String(packet.proto || packet.protocol || 'Other');

        if (protocolValue === '6' || protocolValue.toUpperCase() === 'TCP') {
          accumulator.TCP += 1;
        } else if (protocolValue === '17' || protocolValue.toUpperCase() === 'UDP') {
          accumulator.UDP += 1;
        } else if (protocolValue === '1' || protocolValue.toUpperCase() === 'ICMP') {
          accumulator.ICMP += 1;
        } else {
          accumulator.Other += 1;
        }

        return accumulator;
      },
      { TCP: 0, UDP: 0, ICMP: 0, Other: 0 }
    );
  }, [networkData]);

  const topSources = useMemo(() => {
    const sourceMap = new Map();

    networkData.forEach((packet) => {
      const sourceIp = packet.src || packet.src_ip || 'Unknown';
      sourceMap.set(sourceIp, (sourceMap.get(sourceIp) || 0) + 1);
    });

    return Array.from(sourceMap.entries())
      .map(([ip, count]) => ({ ip, count }))
      .sort((left, right) => right.count - left.count)
      .slice(0, 6);
  }, [networkData]);

  const trafficIntensity = packetCount === 0 ? 0 : Math.min(100, Math.round((networkData.length / packetCount) * 1000));

  return (
    <div className="cyber-page traffic-page">
      <div className="traffic-layout">
        <section className="traffic-main cyber-panel">
          <div className="traffic-main-header">
            <div>
              <h2>Live Network Traffic</h2>
              <p>Real-time packet stream with search and protocol-level filtering.</p>
            </div>
            <div className="traffic-main-actions">
              <button className="traffic-btn warning" onClick={() => dispatch(isPaused ? resumeNetworkData() : pauseNetworkData())}>
                {isPaused ? 'Resume Feed' : 'Pause Feed'}
              </button>
              <button className="traffic-btn danger" onClick={() => dispatch(clearNetworkData())} disabled={networkData.length === 0}>
                Clear Data
              </button>
            </div>
          </div>

          <div className="cyber-kpi-grid traffic-kpis">
            <div className="cyber-kpi-card">
              <span className="cyber-kpi-label">Total Packets</span>
              <span className="cyber-kpi-value">{packetCount}</span>
            </div>
            <div className="cyber-kpi-card">
              <span className="cyber-kpi-label">Visible Rows</span>
              <span className="cyber-kpi-value">{networkData.length}</span>
            </div>
            <div className="cyber-kpi-card">
              <span className="cyber-kpi-label">Feed State</span>
              <span className="cyber-kpi-value">{isPaused ? 'Paused' : 'Live'}</span>
            </div>
            <div className="cyber-kpi-card">
              <span className="cyber-kpi-label">Last Packet</span>
              <span className="cyber-kpi-value small">{lastNetworkTime ? new Date(lastNetworkTime).toLocaleTimeString() : 'N/A'}</span>
            </div>
          </div>

          <LiveTrafficTable data={networkData} isPaused={isPaused} />
        </section>

        <aside className="traffic-side">
          <section className="traffic-side-panel cyber-panel">
            <div className="cyber-panel-header">
              <h3 className="cyber-panel-title">Protocol Breakdown</h3>
              <span className="cyber-pill">Live</span>
            </div>
            <ul className="cyber-list">
              {Object.entries(protocolSummary).map(([protocol, count]) => (
                <li key={protocol} className="cyber-list-item traffic-stat-item">
                  <span>{protocol}</span>
                  <strong>{count}</strong>
                </li>
              ))}
            </ul>
          </section>

          <section className="traffic-side-panel cyber-panel">
            <div className="cyber-panel-header">
              <h3 className="cyber-panel-title">Top Source Hosts</h3>
              <span className="cyber-pill">Top 6</span>
            </div>
            {topSources.length === 0 ? (
              <div className="cyber-empty">No packet sources available yet.</div>
            ) : (
              <ul className="cyber-list">
                {topSources.map((source) => (
                  <li key={source.ip} className="cyber-list-item traffic-source-item">
                    <code>{source.ip}</code>
                    <span>{source.count} packets</span>
                  </li>
                ))}
              </ul>
            )}
          </section>

          <section className="traffic-side-panel cyber-panel">
            <div className="cyber-panel-header">
              <h3 className="cyber-panel-title">Traffic Intensity</h3>
              <span className="cyber-pill">{trafficIntensity}%</span>
            </div>
            <div className="traffic-intensity-track">
              <div className="traffic-intensity-fill" style={{ width: `${trafficIntensity}%` }} />
            </div>
            <p className="traffic-intensity-note">Relative density of current visible packets vs cumulative ingestion.</p>
          </section>

          <section className="traffic-side-panel cyber-panel">
            <div className="cyber-panel-header">
              <h3 className="cyber-panel-title">⚡ Attack Simulation</h3>
              <span className="cyber-pill">Demo</span>
            </div>
            <p style={{ color: '#8b949e', fontSize: '0.8rem', marginBottom: '10px' }}>
              Inject synthetic attacks into the live detection pipeline.
            </p>
            <select
              value={simType}
              onChange={e => setSimType(e.target.value)}
              style={{ width: '100%', background: '#0d1117', border: '1px solid #30363d', color: '#fff',
                       padding: '6px 10px', borderRadius: '6px', marginBottom: '8px' }}>
              {SIM_TYPES.map(t => <option key={t}>{t}</option>)}
            </select>
            <button
              onClick={simulate}
              disabled={simState === 'running'}
              style={{ width: '100%', background: 'linear-gradient(135deg,#e91e63,#ff4444)',
                       border: 'none', color: '#fff', padding: '8px', borderRadius: '6px',
                       fontWeight: '700', cursor: 'pointer', opacity: simState === 'running' ? 0.6 : 1 }}>
              {simState === 'running' ? '⏳ Simulating…' : simState === 'done' ? '✅ Done' : '⚡ Simulate'}
            </button>
            {simResult && simState === 'done' && (
              <p style={{ color: '#4caf50', fontSize: '0.8rem', marginTop: '6px' }}>
                {simResult.error
                  ? `❌ ${simResult.error}`
                  : `✅ ${simResult.packets_sent} pkts → ${simResult.alerts_emitted} alerts`}
              </p>
            )}
          </section>

          <ConnectionStatus compact />
        </aside>
      </div>
    </div>
  );
}

export default RealTimeTraffic;
