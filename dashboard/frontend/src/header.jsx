import React, { useState, useEffect, useRef } from 'react';
import { useNavigate, useLocation, Link } from 'react-router-dom';
import { useAuth } from './context/AuthContext';
import { useSelector } from 'react-redux';
import './header.css';

const ML_API = 'http://127.0.0.1:8000/model_app';

const NAV_ITEMS = [
  { path: '/dashboard',   icon: '⬡',  label: 'Dashboard' },
  { path: '/traffic',     icon: '⟳',  label: 'Live Traffic' },
  { path: '/alerts',      icon: '🔔', label: 'Alerts' },
  { path: '/flows',       icon: '📊', label: 'Network Flows' },
  { path: '/hotspot',     icon: '📡', label: 'Devices' },
  { path: '/blocked-ips', icon: '🛡', label: 'Blocked IPs' },
  { path: '/analytics',   icon: '📈', label: 'Analytics' },
];

const ADMIN_NAV = [
  { path: '/admin/users',   icon: '👥', label: 'Users' },
  { path: '/device-emails', icon: '📧', label: 'Alert Emails' },
];

function Header() {
  const navigate            = useNavigate();
  const location            = useLocation();
  const { user, logout, isAdmin } = useAuth();
  const [collapsed, setCollapsed]   = useState(false);
  const [capturing, setCapturing]   = useState(false);
  const [captLoading, setCaptLoading] = useState(false);
  const alertStats = useSelector(s => s.alerts);

  // Poll capture status
  useEffect(() => {
    const check = async () => {
      try {
        const r = await fetch(`${ML_API}/capture`);
        const d = await r.json();
        setCapturing(d.running);
      } catch {}
    };
    check();
    const id = setInterval(check, 8000);
    return () => clearInterval(id);
  }, []);

  const toggleCapture = async () => {
    setCaptLoading(true);
    try {
      const action = capturing ? 'stop' : 'start';
      await fetch(`${ML_API}/capture`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ action }),
      });
      setCapturing(!capturing);
    } catch {}
    setCaptLoading(false);
  };

  const handleLogout = () => { logout(); navigate('/login'); };

  const allNav = [...NAV_ITEMS, ...(isAdmin ? ADMIN_NAV : [])];

  return (
    <aside className={`sf-sidebar ${collapsed ? 'collapsed' : ''}`}>
      {/* Logo */}
      <div className="sidebar-logo" onClick={() => setCollapsed(c => !c)}>
        <div className="logo-icon">⬡</div>
        {!collapsed && <span className="logo-text">Secure<b>Flow</b></span>}
        <button className="collapse-btn">{collapsed ? '›' : '‹'}</button>
      </div>

      {/* Capture Toggle */}
      <div className="sidebar-section">
        <button
          className={`capture-toggle ${capturing ? 'running' : ''} ${collapsed ? 'capture-compact' : ''}`}
          onClick={toggleCapture}
          disabled={captLoading}
          title={capturing ? 'Stop Capture' : 'Start Capture'}
        >
          <span className={`capture-dot ${capturing ? 'active' : ''}`} />
          {!collapsed && (
            <span className="capture-text">
              {captLoading ? '…' : capturing ? 'Capture ON' : 'Capture OFF'}
            </span>
          )}
        </button>
      </div>

      {/* Navigation */}
      <nav className="sidebar-nav">
        {allNav.map(item => {
          const isActive = location.pathname === item.path;
          return (
            <Link
              key={item.path}
              to={item.path}
              className={`nav-item ${isActive ? 'active' : ''}`}
              title={collapsed ? item.label : ''}
            >
              <span className="nav-icon">{item.icon}</span>
              {!collapsed && <span className="nav-label">{item.label}</span>}
              {!collapsed && item.path === '/alerts' && alertStats?.alerts?.length > 0 && (
                <span className="nav-badge">{Math.min(alertStats.alerts.length, 99)}</span>
              )}
            </Link>
          );
        })}
      </nav>

      {/* User footer */}
      <div className="sidebar-footer">
        <div className={`user-info ${collapsed ? 'user-compact' : ''}`}>
          <div className="user-avatar">{user?.username?.[0]?.toUpperCase() || 'U'}</div>
          {!collapsed && (
            <div className="user-details">
              <span className="user-name">{user?.username?.split('@')[0] || 'User'}</span>
              <span className={`sf-pill ${isAdmin ? 'sf-pill-admin' : 'sf-pill-normal'}`}>
                {isAdmin ? 'ADMIN' : 'USER'}
              </span>
            </div>
          )}
        </div>
        <button className="logout-btn" onClick={handleLogout} title="Logout">⏻</button>
      </div>
    </aside>
  );
}

export default Header;
