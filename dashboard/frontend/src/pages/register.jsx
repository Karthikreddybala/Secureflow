import React, { useState } from 'react';
import { useNavigate } from 'react-router-dom';
import { useAuth } from '../context/AuthContext';

export default function Register() {
  const { register } = useAuth();
  const navigate = useNavigate();
  const [form, setForm]   = useState({ username: '', password: '', confirm: '' });
  const [error, setError] = useState('');
  const [ok, setOk]       = useState('');
  const [loading, setLoading] = useState(false);

  const handleSubmit = async (e) => {
    e.preventDefault(); setError(''); setOk('');
    if (form.password !== form.confirm) { setError('Passwords do not match'); return; }
    if (form.password.length < 6) { setError('Password must be at least 6 characters'); return; }
    setLoading(true);
    const result = await register(form.username, form.password);
    setLoading(false);
    if (result.success) {
      setOk('Account created! Redirecting to login…');
      setTimeout(() => navigate('/login'), 1500);
    } else { setError(result.error || 'Registration failed'); }
  };

  return (
    <div style={{ position: 'fixed', inset: 0, display: 'flex', alignItems: 'center', justifyContent: 'center', background: 'var(--bg-base)' }}>
      <div style={{ width: '100%', maxWidth: 400, background: 'rgba(8,14,31,0.90)', border: '1px solid rgba(0,245,212,0.2)', borderRadius: 24, padding: '40px 36px', boxShadow: '0 8px 64px rgba(0,0,0,0.7)', backdropFilter: 'blur(20px)', animation: 'fadeInUp 0.4s ease' }}>
        <div style={{ textAlign: 'center', marginBottom: 32 }}>
          <div style={{ fontSize: '2.4rem', marginBottom: 6 }}>⬡</div>
          <h1 style={{ fontSize: '1.45rem', fontWeight: 800, color: 'var(--text-primary)', margin: 0 }}>
            Create Account
          </h1>
          <p style={{ color: 'var(--text-muted)', fontSize: '0.8rem', marginTop: 5 }}>SecureFlow IDS access request</p>
        </div>

        {error && <div style={{ background: 'rgba(255,69,96,0.12)', border: '1px solid rgba(255,69,96,0.3)', borderRadius: 8, padding: '10px 14px', color: 'var(--danger)', fontSize: '0.85rem', marginBottom: 18 }}>⚠ {error}</div>}
        {ok && <div style={{ background: 'rgba(0,230,118,0.1)', border: '1px solid rgba(0,230,118,0.3)', borderRadius: 8, padding: '10px 14px', color: 'var(--success)', fontSize: '0.85rem', marginBottom: 18 }}>✅ {ok}</div>}

        <form onSubmit={handleSubmit} style={{ display: 'flex', flexDirection: 'column', gap: 16 }}>
          <div>
            <label className="sf-label">Email</label>
            <input className="sf-input" type="email" placeholder="you@example.com" value={form.username} onChange={e => setForm(f => ({ ...f, username: e.target.value }))} required />
          </div>
          <div>
            <label className="sf-label">Password</label>
            <input className="sf-input" type="password" placeholder="Min 6 characters" value={form.password} onChange={e => setForm(f => ({ ...f, password: e.target.value }))} required />
          </div>
          <div>
            <label className="sf-label">Confirm Password</label>
            <input className="sf-input" type="password" placeholder="Repeat password" value={form.confirm} onChange={e => setForm(f => ({ ...f, confirm: e.target.value }))} required />
          </div>
          <button type="submit" className="sf-btn sf-btn-primary" style={{ width: '100%', justifyContent: 'center', padding: '11px', marginTop: 4 }} disabled={loading}>
            {loading ? 'Creating…' : '→ Create Account'}
          </button>
        </form>

        <p style={{ textAlign: 'center', marginTop: 20, color: 'var(--text-muted)', fontSize: '0.8rem' }}>
          Already have an account? <a href="/login" style={{ color: 'var(--accent)', textDecoration: 'none', fontWeight: 600 }}>Sign In</a>
        </p>
      </div>
    </div>
  );
}
