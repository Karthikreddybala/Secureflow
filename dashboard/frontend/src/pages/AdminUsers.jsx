import React, { useState, useEffect, useCallback } from 'react';
import { useAuth } from '../context/AuthContext';

const ML_API = 'http://127.0.0.1:8000/model_app';

export default function AdminUsers() {
  const { user } = useAuth();
  const [users, setUsers]     = useState([]);
  const [loading, setLoading] = useState(false);
  const [msg, setMsg]         = useState('');

  const token = user?.token;

  const fetchUsers = useCallback(async () => {
    setLoading(true);
    try {
      const r = await fetch('http://127.0.0.1:5000/admin/users', {
        headers: { Authorization: `Bearer ${token}` },
      });
      const d = await r.json();
      setUsers(d.users || []);
    } catch { setMsg('Failed to load users'); }
    setLoading(false);
  }, [token]);

  useEffect(() => { fetchUsers(); }, [fetchUsers]);

  const updateRole = async (id, role) => {
    try {
      const r = await fetch(`http://127.0.0.1:5000/admin/users/${id}/role`, {
        method: 'PUT',
        headers: { 'Content-Type': 'application/json', Authorization: `Bearer ${token}` },
        body: JSON.stringify({ role }),
      });
      const d = await r.json();
      if (d.status === 'success') {
        setMsg(`✅ Role updated to ${role}`);
        fetchUsers();
      } else {
        setMsg(`❌ ${d.error}`);
      }
    } catch { setMsg('❌ Request failed'); }
    setTimeout(() => setMsg(''), 3000);
  };

  return (
    <div className="sf-page anim-fade-in">
      <div style={{ marginBottom: 24, display: 'flex', justifyContent: 'space-between', alignItems: 'center', flexWrap: 'wrap', gap: 12 }}>
        <div>
          <h2 style={{ fontSize: '1.4rem', fontWeight: 800, color: 'var(--text-primary)', margin: 0 }}>User Management</h2>
          <p style={{ color: 'var(--text-secondary)', fontSize: '0.85rem', marginTop: 4 }}>Admin-only: manage roles and access</p>
        </div>
        <div style={{ display: 'flex', gap: 10, alignItems: 'center' }}>
          {msg && <span style={{ fontSize: '0.85rem', color: msg.startsWith('✅') ? 'var(--success)' : 'var(--danger)' }}>{msg}</span>}
          <button className="sf-btn sf-btn-ghost" onClick={fetchUsers} disabled={loading}>⟳ Refresh</button>
        </div>
      </div>

      <div className="sf-kpi-grid" style={{ marginBottom: 22 }}>
        <div className="sf-kpi-card"><span className="sf-kpi-label">Total Users</span><span className="sf-kpi-value accent">{users.length}</span></div>
        <div className="sf-kpi-card"><span className="sf-kpi-label">Admins</span><span className="sf-kpi-value warning">{users.filter(u => u.role === 'admin').length}</span></div>
        <div className="sf-kpi-card"><span className="sf-kpi-label">Regular Users</span><span className="sf-kpi-value">{users.filter(u => u.role !== 'admin').length}</span></div>
      </div>

      <div className="sf-card" style={{ padding: 0, overflow: 'hidden' }}>
        <div className="sf-table-wrap">
          <table className="sf-table">
            <thead>
              <tr><th>ID</th><th>Email</th><th>Role</th><th>Actions</th></tr>
            </thead>
            <tbody>
              {loading ? (
                <tr><td colSpan={4} style={{ textAlign: 'center', padding: '40px', color: 'var(--text-muted)' }}>Loading…</td></tr>
              ) : users.length === 0 ? (
                <tr><td colSpan={4} style={{ textAlign: 'center', padding: '40px', color: 'var(--text-muted)' }}>No users found.</td></tr>
              ) : users.map(u => (
                <tr key={u.id}>
                  <td style={{ color: 'var(--text-muted)', fontSize: '0.8rem' }}>{u.id}</td>
                  <td><code>{u.email}</code></td>
                  <td>
                    <span className={`sf-pill ${u.role === 'admin' ? 'sf-pill-admin' : 'sf-pill-normal'}`}>
                      {u.role?.toUpperCase() || 'USER'}
                    </span>
                  </td>
                  <td>
                    {u.role === 'admin' ? (
                      <button className="sf-btn sf-btn-ghost sf-btn-sm" onClick={() => updateRole(u.id, 'user')}>↓ Demote to User</button>
                    ) : (
                      <button className="sf-btn sf-btn-ghost sf-btn-sm" style={{ color: 'var(--warning)', borderColor: 'rgba(255,184,0,0.4)' }} onClick={() => updateRole(u.id, 'admin')}>↑ Promote to Admin</button>
                    )}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </div>
    </div>
  );
}
