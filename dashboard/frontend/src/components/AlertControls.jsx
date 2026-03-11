import React from 'react';
import { useSelector, useDispatch } from 'react-redux';
import {
  setAlertFilter,
  setAlertSort,
  clearAlerts,
  selectAlertStats,
  selectAlertFilter,
  selectAlertSort
} from '../store/slices/alertsSlice';
import './components.css';

const FILTER_OPTIONS = ['all', 'high', 'medium', 'low', 'normal'];

const SORT_OPTIONS = [
  { value: 'newest', label: 'Newest First' },
  { value: 'oldest', label: 'Oldest First' },
  { value: 'severity', label: 'By Severity' },
  { value: 'score', label: 'By Score' }
];

function AlertControls({ compact = false }) {
  const dispatch = useDispatch();
  const stats = useSelector((state) => selectAlertStats(state));
  const currentFilter = useSelector((state) => selectAlertFilter(state));
  const currentSort = useSelector((state) => selectAlertSort(state));

  return (
    <div className={`alert-controls-shell ${compact ? 'compact' : ''}`}>
      <div className="alert-controls-top">
        <div className="alert-controls-stats">
          <span className="alert-chip total">Total {stats.total}</span>
          <span className="alert-chip high">High {stats.high}</span>
          <span className="alert-chip medium">Medium {stats.medium}</span>
          <span className="alert-chip low">Low {stats.low}</span>
          <span className="alert-chip normal">Normal {stats.normal}</span>
          <span className="alert-chip attack">Attacks {stats.attacks}</span>
        </div>

        <button className="alert-clear-btn" onClick={() => dispatch(clearAlerts())} disabled={stats.total === 0}>
          Clear Alerts
        </button>
      </div>

      <div className="alert-controls-actions">
        <div className="alert-filter-group">
          {FILTER_OPTIONS.map((filter) => (
            <button
              key={filter}
              className={`alert-filter-btn ${currentFilter === filter ? 'active' : ''}`}
              onClick={() => dispatch(setAlertFilter(filter))}
            >
              {filter}
            </button>
          ))}
        </div>

        <div className="alert-sort-group">
          <label htmlFor="alert-sort">Sort</label>
          <select id="alert-sort" value={currentSort} onChange={(event) => dispatch(setAlertSort(event.target.value))}>
            {SORT_OPTIONS.map((option) => (
              <option key={option.value} value={option.value}>
                {option.label}
              </option>
            ))}
          </select>
        </div>
      </div>

      {currentFilter !== 'all' && <p className="alert-filter-note">Filtering by <strong>{currentFilter}</strong> severity.</p>}
    </div>
  );
}

export default AlertControls;
