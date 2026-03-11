import React from 'react';
import { useSelector } from 'react-redux';
import './components.css';

function GlobalStateTest({ compact = false }) {
  const alerts = useSelector((state) => state.alerts.alerts);
  const networkData = useSelector((state) => state.networkData.networkData);
  const chartData = useSelector((state) => state.chartData.networkTrafficData);
  const isConnected = useSelector((state) => state.connectionStatus.isAlertConnected);

  return (
    <section className={`global-state-shell cyber-panel ${compact ? 'compact' : ''}`}>
      <div className="global-state-header">
        <h3>Global State Integrity</h3>
        <span className="cyber-pill">Diagnostics</span>
      </div>

      <div className="global-state-grid">
        <div className="global-state-cell">
          <span>Alerts</span>
          <strong>{alerts.length}</strong>
        </div>
        <div className="global-state-cell">
          <span>Network Rows</span>
          <strong>{networkData.length}</strong>
        </div>
        <div className="global-state-cell">
          <span>Chart Labels</span>
          <strong>{chartData.labels.length}</strong>
        </div>
        <div className="global-state-cell">
          <span>Alert Socket</span>
          <strong>{isConnected ? 'Connected' : 'Disconnected'}</strong>
        </div>
      </div>

      {!compact && <p className="global-state-note">Navigate across routes to confirm state is retained and counters remain stable.</p>}
    </section>
  );
}

export default GlobalStateTest;
