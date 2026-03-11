import React from 'react';
import { useNavigate } from 'react-router-dom';
import { useSelector } from 'react-redux';
import './css/home.css';
import { selectAlertStats } from '../store/slices/alertsSlice';

const featureModules = [
  {
    title: 'Real-Time Traffic',
    subtitle: 'Telemetry Stream',
    description: 'Inspect packet flow, protocol mix, and session behavior with live controls.',
    route: '/traffic',
    accent: 'cyan'
  },
  {
    title: 'Blocked IP Intelligence',
    subtitle: 'Threat Inventory',
    description: 'Track hostile sources, recurrence patterns, and suspicious destination targeting.',
    route: '/blocked-ips',
    accent: 'red'
  },
  {
    title: 'Attack Analytics',
    subtitle: 'Adversary Trends',
    description: 'Analyze severity distribution, attack classes, and response posture indicators.',
    route: '/analytics',
    accent: 'amber'
  }
];

function Home() {
  const navigate = useNavigate();
  const alertStats = useSelector((state) => selectAlertStats(state));
  const packetCount = useSelector((state) => state.networkData.packetCount);
  const isAlertConnected = useSelector((state) => state.connectionStatus.isAlertConnected);
  const isNetworkConnected = useSelector((state) => state.connectionStatus.isNetworkConnected);

  const streamHealth = isAlertConnected && isNetworkConnected ? 'Stable' : isAlertConnected || isNetworkConnected ? 'Partial' : 'Offline';

  return (
    <div className="cyber-page home-page">
      <section className="home-hero cyber-panel">
        <div className="home-hero-grid">
          <div>
            <p className="home-label">Unified Security Operations Console</p>
            <h1>Monitor threats, traffic, and attack behavior from one command surface.</h1>
            <p className="home-intro">
              Secureflow AI gives your team continuous network visibility, fast incident triage, and a clear picture of attack pressure.
            </p>
            <div className="home-hero-actions">
              <button className="home-primary-btn" onClick={() => navigate('/dashboard')}>
                Open Dashboard
              </button>
              <button className="home-secondary-btn" onClick={() => navigate('/traffic')}>
                Inspect Live Traffic
              </button>
            </div>
          </div>

          <div className="home-glass-card">
            <h3>Current System Pulse</h3>
            <div className="cyber-kpi-grid">
              <div className="cyber-kpi-card">
                <span className="cyber-kpi-label">Packets Ingested</span>
                <span className="cyber-kpi-value">{packetCount}</span>
              </div>
              <div className="cyber-kpi-card">
                <span className="cyber-kpi-label">Alert Volume</span>
                <span className="cyber-kpi-value">{alertStats.total}</span>
              </div>
              <div className="cyber-kpi-card">
                <span className="cyber-kpi-label">High Severity</span>
                <span className="cyber-kpi-value">{alertStats.high}</span>
              </div>
              <div className="cyber-kpi-card">
                <span className="cyber-kpi-label">Stream Health</span>
                <span className="cyber-kpi-value">{streamHealth}</span>
              </div>
            </div>
          </div>
        </div>
      </section>

      <section className="home-modules home-grid">
        {featureModules.map((module) => (
          <article key={module.title} className={`home-module-card cyber-panel ${module.accent}`}>
            <div className="cyber-panel-header">
              <div>
                <h3 className="cyber-panel-title">{module.title}</h3>
                <p className="cyber-panel-subtitle">{module.subtitle}</p>
              </div>
              <span className="cyber-pill">Live</span>
            </div>
            <p className="home-module-text">{module.description}</p>
            <button className="home-module-btn" onClick={() => navigate(module.route)}>
              Open {module.title}
            </button>
          </article>
        ))}
      </section>

      <section className="home-quickstart cyber-panel">
        <div className="cyber-panel-header">
          <div>
            <h3 className="cyber-panel-title">Quick Start Workflow</h3>
            <p className="cyber-panel-subtitle">Suggested analyst flow for live monitoring sessions.</p>
          </div>
        </div>
        <ol className="home-flow-list">
          <li>Open <strong>Real-Time Traffic</strong> and validate stream stability and packet velocity.</li>
          <li>Move to <strong>Attack Analytics</strong> and evaluate severity distribution trends.</li>
          <li>Review <strong>Blocked IP Intelligence</strong> for repeat hostile sources and target concentration.</li>
          <li>Use the <strong>Dashboard</strong> for consolidated monitoring once triage is complete.</li>
        </ol>
      </section>
    </div>
  );
}

export default Home;
