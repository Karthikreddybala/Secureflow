import React from 'react';
import { useSelector, useDispatch } from 'react-redux';
import { resetConnectionStatus } from '../store/slices/connectionStatusSlice';
import './components.css';

function formatTime(timestamp) {
  if (!timestamp) {
    return 'Never';
  }

  return new Date(timestamp).toLocaleTimeString();
}

function ConnectionStatus({ compact = false }) {
  const dispatch = useDispatch();
  const isAlertConnected = useSelector((state) => state.connectionStatus.isAlertConnected);
  const isNetworkConnected = useSelector((state) => state.connectionStatus.isNetworkConnected);
  const lastAlertTime = useSelector((state) => state.alerts.lastAlertTime);
  const lastNetworkTime = useSelector((state) => state.networkData.lastNetworkTime);
  const connectionStatus = useSelector((state) => state.connectionStatus.connectionStatus);
  const connectionError = useSelector((state) => state.connectionStatus.connectionError);
  const lastConnectionAttempt = useSelector((state) => state.connectionStatus.lastConnectionAttempt);

  const overallClass = connectionStatus === 'connected' ? 'connected' : connectionStatus === 'error' ? 'error' : 'pending';

  return (
    <section className={`connection-status-shell cyber-panel ${compact ? 'compact' : ''}`}>
      <div className="connection-status-header">
        <h3>WebSocket Links</h3>
        <span className={`connection-overall ${overallClass}`}>{connectionStatus}</span>
      </div>

      <ul className="connection-list">
        <li className="connection-item">
          <div>
            <p>Alerts Stream</p>
            <small>ws://localhost:8000/ws/alerts/</small>
          </div>
          <span className={`connection-chip ${isAlertConnected ? 'connected' : 'disconnected'}`}>
            {isAlertConnected ? 'Connected' : 'Disconnected'}
          </span>
        </li>
        <li className="connection-item">
          <div>
            <p>Traffic Stream</p>
            <small>ws://localhost:8000/ws/network/</small>
          </div>
          <span className={`connection-chip ${isNetworkConnected ? 'connected' : 'disconnected'}`}>
            {isNetworkConnected ? 'Connected' : 'Disconnected'}
          </span>
        </li>
      </ul>

      <div className="connection-meta">
        <span>Last alert packet: {formatTime(lastAlertTime)}</span>
        <span>Last network packet: {formatTime(lastNetworkTime)}</span>
        <span>Last reconnect attempt: {formatTime(lastConnectionAttempt)}</span>
      </div>

      {connectionError && <p className="connection-error">{connectionError}</p>}

      {!compact && (
        <ul className="connection-notes">
          <li>Automatic retry sequence runs with progressive delay.</li>
          <li>Successful reconnect resets retry counters immediately.</li>
        </ul>
      )}

      <button className="connection-reset-btn" onClick={() => dispatch(resetConnectionStatus())} disabled={!connectionError}>
        Reset Connection State
      </button>
    </section>
  );
}

export default ConnectionStatus;
