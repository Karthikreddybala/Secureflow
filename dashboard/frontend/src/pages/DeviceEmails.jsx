import React, { useState, useEffect, useCallback } from 'react';
import { useAuth } from '../context/AuthContext';
import './css/DeviceEmails.css';

const ML_API = 'http://127.0.0.1:8000/model_app';

const SEV_OPTIONS = ['Low', 'Medium', 'High'];
const SEV_COLOR   = { Low: 'var(--success)', Medium: 'var(--warning)', High: 'var(--danger)' };
// device mail
function fmt(ts) {
  if (!ts) return '—';
  return new Date(ts * 1000).toLocaleString();
}

export default function DeviceEmails() {
  const { user, isAdmin } = useAuth();
  const [rules,    setRules]    = useState([]);
  const [devices,  setDevices]  = useState([]);
  const [loading,  setLoading]  = useState(true);
  const [msg,      setMsg]      = useState(null);   // { type: 'ok'|'err', text }
  const [testMsg,  setTestMsg]  = useState({});      // ruleId → message
  const [showForm, setShowForm] = useState(false);
  const [form,     setForm]     = useState({
    ip: '', email: '', label: '', mac: '', min_severity: 'Medium', enabled: true,
  });
  const [editId, setEditId] = useState(null);

  // ── Fetch rules + connected devices ───────────────────────
  const refresh = useCallback(async () => {
    setLoading(true);
    try {
      const res  = await fetch(`${ML_API}/device_emails`);
      const data = await res.json();
      setRules(data.rules  || []);
      setDevices((data.connected_devices || []).filter(d => d.status === 'online'));
    } catch (e) {
      setMsg({ type: 'err', text: 'Failed to load rules: ' + String(e) });
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => { refresh(); }, [refresh]);

  // Auto-fill label when device selected from dropdown
  const handleDeviceSelect = (e) => {
    const ip = e.target.value;
    const dev = devices.find(d => d.ip === ip);
    setForm(f => ({
      ...f,
      ip,
      mac:   dev?.mac   || f.mac,
      label: dev?.hostname || dev?.ip || f.label,
    }));
  };

  // ── Save (create or update) ─────────────────────────────-
  const handleSave = async (e) => {
    e.preventDefault();
    if (!form.email) { setMsg({ type: 'err', text: 'Email is required.' }); return; }
    try {
      const url    = editId ? `${ML_API}/device_emails/${editId}` : `${ML_API}/device_emails`;
      const method = editId ? 'PUT' : 'POST';
      const res    = await fetch(url, {
        method,
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(form),
      });
      const data = await res.json();
      if (!res.ok) throw new Error(data.error || 'Save failed');
      setMsg({ type: 'ok', text: editId ? 'Rule updated.' : 'Rule created.' });
      setShowForm(false);
      setEditId(null);
      setForm({ ip: '', email: '', label: '', mac: '', min_severity: 'Medium', enabled: true });
      refresh();
    } catch (err) {
      setMsg({ type: 'err', text: String(err.message) });
    }
    setTimeout(() => setMsg(null), 4000);
  };

  // ── Delete ────────────────────────────────────────────────
  const handleDelete = async (id) => {
    if (!window.confirm('Delete this alert email rule?')) return;
    try {
      await fetch(`${ML_API}/device_emails/${id}`, { method: 'DELETE' });
      setMsg({ type: 'ok', text: 'Rule deleted.' });
      refresh();
    } catch (err) {
      setMsg({ type: 'err', text: String(err) });
    }
    setTimeout(() => setMsg(null), 3000);
  };

  // ── Toggle enabled ────────────────────────────────────────
  const handleToggle = async (rule) => {
    try {
      await fetch(`${ML_API}/device_emails/${rule.id}`, {
        method: 'PUT',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ enabled: !rule.enabled }),
      });
      refresh();
    } catch {}
  };

  // ── Test email ────────────────────────────────────────────
  const handleTest = async (rule) => {
    setTestMsg(p => ({ ...p, [rule.id]: '⏳ Sending…' }));
    try {
      const res  = await fetch(`${ML_API}/device_emails/test`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ rule_id: rule.id }),
      });
      const data = await res.json();
      if (!res.ok) throw new Error(data.error || 'Failed');
      setTestMsg(p => ({ ...p, [rule.id]: '✅ Sent!' }));
    } catch (err) {
      setTestMsg(p => ({ ...p, [rule.id]: '❌ ' + err.message }));
    }
    setTimeout(() => setTestMsg(p => { const n = { ...p }; delete n[rule.id]; return n; }), 5000);
  };

  // ── Edit ─────────────────────────────────────────────────
  const handleEdit = (rule) => {
    setForm({
      ip:           rule.ip,
      email:        rule.email,
      label:        rule.label,
      mac:          rule.mac,
      min_severity: rule.min_severity,
      enabled:      rule.enabled,
    });
    setEditId(rule.id);
    setShowForm(true);
    window.scrollTo({ top: 0, behavior: 'smooth' });
  };

  if (!isAdmin) {
    return (
      <div className="sf-page anim-fade-in">
        <div className="sf-empty">
          <span className="sf-empty-icon">🔒</span>
          <span>Admin access required</span>
        </div>
      </div>
    );
  }

  return (
    <div className="sf-page anim-fade-in">
      {/* Header */}
      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start', marginBottom: 24, flexWrap: 'wrap', gap: 12 }}>
        <div>
          <h2 style={{ fontSize: '1.4rem', fontWeight: 800, color: 'var(--text-primary)', margin: 0 }}>
            📧 Device Alert Emails
          </h2>
          <p style={{ color: 'var(--text-secondary)', fontSize: '0.85rem', marginTop: 4 }}>
            Automatically email a recipient when a specific hotspot client triggers a Medium or High severity alert.
          </p>
        </div>
        <button
          className="sf-btn sf-btn-accent"
          onClick={() => { setShowForm(s => !s); setEditId(null); setForm({ ip: '', email: '', label: '', mac: '', min_severity: 'Medium', enabled: true }); }}
        >
          {showForm ? '✕ Cancel' : '＋ Add Rule'}
        </button>
      </div>

      {/* Flash message */}
      {msg && (
        <div style={{
          padding: '10px 16px', borderRadius: 8, marginBottom: 16, fontSize: '0.87rem',
          background: msg.type === 'ok' ? 'rgba(63,185,80,0.12)' : 'rgba(248,81,73,0.12)',
          border: `1px solid ${msg.type === 'ok' ? 'var(--success)' : 'var(--danger)'}`,
          color: msg.type === 'ok' ? 'var(--success)' : 'var(--danger)',
        }}>
          {msg.text}
        </div>
      )}

      {/* Add / Edit form */}
      {showForm && (
        <form onSubmit={handleSave} style={{
          background: 'var(--bg-card)', border: '1px solid var(--border)', borderRadius: 12,
          padding: 24, marginBottom: 24,
        }}>
          <h3 style={{ margin: '0 0 18px', fontSize: '1rem', fontWeight: 700, color: 'var(--text-primary)' }}>
            {editId ? '✏️ Edit Rule' : '＋ New Alert Email Rule'}
          </h3>

          {/* Quick-select from connected devices */}
          {devices.length > 0 && (
            <div style={{ marginBottom: 16 }}>
              <label style={labelStyle}>Quick-select connected device</label>
              <select
                style={inputStyle}
                value={form.ip}
                onChange={handleDeviceSelect}
              >
                <option value="">— select a device —</option>
                {devices.map(d => (
                  <option key={d.ip} value={d.ip}>
                    {d.hostname || d.ip} ({d.ip}) {d.vendor ? `· ${d.vendor}` : ''}
                  </option>
                ))}
              </select>
            </div>
          )}

          <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 14 }}>
            <div>
              <label style={labelStyle}>Device IP (192.168.137.x)</label>
              <input
                style={inputStyle} placeholder="192.168.137.5"
                value={form.ip} onChange={e => setForm(f => ({ ...f, ip: e.target.value }))}
              />
            </div>
            <div>
              <label style={labelStyle}>Friendly Label</label>
              <input
                style={inputStyle} placeholder="My Phone"
                value={form.label} onChange={e => setForm(f => ({ ...f, label: e.target.value }))}
              />
            </div>
            <div>
              <label style={labelStyle}>Alert Email *</label>
              <input
                required type="email" style={inputStyle} placeholder="you@gmail.com"
                value={form.email} onChange={e => setForm(f => ({ ...f, email: e.target.value }))}
              />
            </div>
            <div>
              <label style={labelStyle}>Min Severity</label>
              <select
                style={inputStyle}
                value={form.min_severity}
                onChange={e => setForm(f => ({ ...f, min_severity: e.target.value }))}
              >
                {SEV_OPTIONS.map(s => <option key={s} value={s}>{s}</option>)}
              </select>
            </div>
          </div>

          <div style={{ marginTop: 16, display: 'flex', alignItems: 'center', gap: 10 }}>
            <label style={{ ...labelStyle, margin: 0 }}>Enabled</label>
            <input
              type="checkbox" checked={form.enabled}
              onChange={e => setForm(f => ({ ...f, enabled: e.target.checked }))}
              style={{ width: 16, height: 16, accentColor: 'var(--accent)' }}
            />
          </div>

          <div style={{ marginTop: 20, display: 'flex', gap: 10 }}>
            <button type="submit" className="sf-btn sf-btn-accent">
              {editId ? '💾 Save Changes' : '➕ Create Rule'}
            </button>
            <button type="button" className="sf-btn sf-btn-ghost" onClick={() => { setShowForm(false); setEditId(null); }}>
              Cancel
            </button>
          </div>
        </form>
      )}

      {/* KPI row */}
      <div className="sf-kpi-grid" style={{ marginBottom: 24 }}>
        <div className="sf-kpi-card">
          <span className="sf-kpi-label">Total Rules</span>
          <span className="sf-kpi-value accent">{rules.length}</span>
        </div>
        <div className="sf-kpi-card">
          <span className="sf-kpi-label">Active Rules</span>
          <span className="sf-kpi-value">{rules.filter(r => r.enabled).length}</span>
        </div>
        <div className="sf-kpi-card">
          <span className="sf-kpi-label">Online Devices</span>
          <span className="sf-kpi-value" style={{ color: 'var(--success)' }}>{devices.length}</span>
        </div>
        <div className="sf-kpi-card">
          <span className="sf-kpi-label">SMTP Status</span>
          <span className="sf-kpi-value" style={{ fontSize: '0.9rem' }}>
            {rules.length > 0 ? '📧 Configured' : '⚙️ Set .env'}
          </span>
        </div>
      </div>

      {/* Rules table */}
      {loading ? (
        <div className="sf-empty"><span className="sf-empty-icon">⏳</span><span>Loading…</span></div>
      ) : rules.length === 0 ? (
        <div className="sf-empty">
          <span className="sf-empty-icon">📭</span>
          <span>No email rules yet. Click <strong>+ Add Rule</strong> to create one.</span>
        </div>
      ) : (
        <div style={{ overflowX: 'auto' }}>
          <table style={{ width: '100%', borderCollapse: 'collapse', fontSize: '0.85rem' }}>
            <thead>
              <tr style={{ borderBottom: '1px solid var(--border)', color: 'var(--text-muted)', fontSize: '0.75rem', textTransform: 'uppercase', letterSpacing: '0.05em' }}>
                {['Device IP', 'Label', 'Email Recipient', 'Min Severity', 'Created', 'Status', 'Actions'].map(h => (
                  <th key={h} style={{ padding: '10px 12px', textAlign: 'left', whiteSpace: 'nowrap' }}>{h}</th>
                ))}
              </tr>
            </thead>
            <tbody>
              {rules.map((rule, i) => (
                <tr key={rule.id} style={{
                  borderBottom: '1px solid var(--border)',
                  background: i % 2 === 0 ? 'transparent' : 'rgba(255,255,255,0.015)',
                  transition: 'background 0.15s',
                }}>
                  <td style={{ padding: '12px', fontFamily: 'var(--font-mono)', color: 'var(--accent)' }}>
                    {rule.ip || <span style={{ color: 'var(--text-muted)' }}>Any</span>}
                  </td>
                  <td style={{ padding: '12px', color: 'var(--text-primary)' }}>{rule.label || '—'}</td>
                  <td style={{ padding: '12px', color: 'var(--text-secondary)' }}>{rule.email}</td>
                  <td style={{ padding: '12px' }}>
                    <span className={`sf-pill sf-pill-${rule.min_severity.toLowerCase()}`}
                      style={{ color: SEV_COLOR[rule.min_severity] }}>
                      {rule.min_severity}+
                    </span>
                  </td>
                  <td style={{ padding: '12px', color: 'var(--text-muted)', fontSize: '0.78rem', whiteSpace: 'nowrap' }}>
                    {fmt(rule.created_at)}
                  </td>
                  <td style={{ padding: '12px' }}>
                    <button
                      onClick={() => handleToggle(rule)}
                      style={{
                        background: rule.enabled ? 'rgba(63,185,80,0.15)' : 'rgba(139,148,158,0.15)',
                        color: rule.enabled ? 'var(--success)' : 'var(--text-muted)',
                        border: 'none', borderRadius: 6, padding: '4px 10px',
                        cursor: 'pointer', fontSize: '0.78rem', fontWeight: 700,
                      }}
                      title={rule.enabled ? 'Click to disable' : 'Click to enable'}
                    >
                      {rule.enabled ? '● ON' : '○ OFF'}
                    </button>
                  </td>
                  <td style={{ padding: '12px' }}>
                    <div style={{ display: 'flex', gap: 6, flexWrap: 'wrap' }}>
                      <button
                        className="sf-btn sf-btn-ghost sf-btn-sm"
                        onClick={() => handleTest(rule)}
                        title="Send a test email"
                      >
                        {testMsg[rule.id] || '📨 Test'}
                      </button>
                      <button
                        className="sf-btn sf-btn-ghost sf-btn-sm"
                        onClick={() => handleEdit(rule)}
                      >
                        ✏️
                      </button>
                      <button
                        className="sf-btn sf-btn-danger sf-btn-sm"
                        onClick={() => handleDelete(rule.id)}
                      >
                        🗑
                      </button>
                    </div>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}

      {/* Setup hint */}
      <div style={{
        marginTop: 28, padding: '14px 18px',
        background: 'rgba(41,121,255,0.07)', border: '1px solid rgba(41,121,255,0.2)',
        borderRadius: 10, fontSize: '0.82rem', color: 'var(--text-secondary)',
      }}>
        <strong style={{ color: 'var(--info)' }}>📋 Setup Checklist</strong>
        <ol style={{ margin: '8px 0 0 18px', lineHeight: 1.8 }}>
          <li>In <code>ml_model/.env</code>, set <code>SMTP_USER</code>, <code>SMTP_PASSWORD</code> (Gmail App Password), and <code>SMTP_FROM</code>.</li>
          <li>For push notifications, run <code style={{ color: 'var(--accent2)' }}>python generate_vapid.py</code> in <code>ml_model/</code> and paste keys into <code>.env</code>.</li>
          <li>Add rules above — one row per (device IP → recipient email) mapping.</li>
          <li>Use <strong>📨 Test</strong> to verify email delivery before going live.</li>
        </ol>
      </div>
    </div>
  );
}

/* ── Shared styles ─────────────────────────────────────────────── */
const labelStyle = {
  display: 'block', fontSize: '0.78rem', color: 'var(--text-muted)',
  marginBottom: 5, textTransform: 'uppercase', letterSpacing: '0.06em',
};
const inputStyle = {
  width: '100%', boxSizing: 'border-box',
  background: 'var(--bg-surface)', border: '1px solid var(--border)',
  borderRadius: 8, padding: '9px 12px',
  color: 'var(--text-primary)', fontSize: '0.88rem',
  outline: 'none',
};
