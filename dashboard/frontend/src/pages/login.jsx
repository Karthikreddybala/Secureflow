import React, { useState, useEffect, useRef } from 'react';
import { useNavigate, useLocation } from 'react-router-dom';
import { useAuth } from '../context/AuthContext';

export default function Login() {
  const { login, user } = useAuth();
  const navigate        = useNavigate();
  const location        = useLocation();
  const canvasRef       = useRef(null);
  const [form, setForm] = useState({ username: '', password: '' });
  const [error, setError] = useState('');
  const [loading, setLoading] = useState(false);

  // Redirect if already logged in
  useEffect(() => {
    if (user) navigate(location.state?.from?.pathname || '/dashboard', { replace: true });
  }, [user, navigate, location]);

  // Particle canvas animation
  useEffect(() => {
    const canvas = canvasRef.current;
    if (!canvas) return;
    const ctx = canvas.getContext('2d');
    let animId;
    const resize = () => { canvas.width = canvas.offsetWidth; canvas.height = canvas.offsetHeight; };
    resize();
    window.addEventListener('resize', resize);

    const DOTS = Array.from({ length: 60 }, () => ({
      x: Math.random() * canvas.width, y: Math.random() * canvas.height,
      vx: (Math.random() - 0.5) * 0.4, vy: (Math.random() - 0.5) * 0.4,
      r: Math.random() * 1.5 + 0.5,
    }));

    const draw = () => {
      ctx.clearRect(0, 0, canvas.width, canvas.height);
      DOTS.forEach(d => {
        d.x += d.vx; d.y += d.vy;
        if (d.x < 0) d.x = canvas.width;
        if (d.x > canvas.width) d.x = 0;
        if (d.y < 0) d.y = canvas.height;
        if (d.y > canvas.height) d.y = 0;
        ctx.beginPath();
        ctx.arc(d.x, d.y, d.r, 0, Math.PI * 2);
        ctx.fillStyle = 'rgba(0,245,212,0.5)';
        ctx.fill();
      });
      DOTS.forEach((a, i) => DOTS.slice(i + 1).forEach(b => {
        const dist = Math.hypot(a.x - b.x, a.y - b.y);
        if (dist < 120) {
          ctx.beginPath();
          ctx.moveTo(a.x, a.y); ctx.lineTo(b.x, b.y);
          ctx.strokeStyle = `rgba(0,245,212,${0.15 * (1 - dist / 120)})`;
          ctx.lineWidth = 0.6; ctx.stroke();
        }
      }));
      animId = requestAnimationFrame(draw);
    };
    draw();
    return () => { window.removeEventListener('resize', resize); cancelAnimationFrame(animId); };
  }, []);

  const handleSubmit = async (e) => {
    e.preventDefault();
    setError(''); setLoading(true);
    const result = await login(form.username, form.password);
    setLoading(false);
    if (result.success) {
      navigate('/dashboard');
    } else {
      setError(result.error || 'Login failed');
    }
  };

  return (
    <div style={{ position: 'fixed', inset: 0, display: 'flex', alignItems: 'center', justifyContent: 'center', background: 'var(--bg-base)', overflow: 'hidden' }}>
      {/* Particle Canvas */}
      <canvas ref={canvasRef} style={{ position: 'absolute', inset: 0, width: '100%', height: '100%', zIndex: 0 }} />

      {/* Glow orbs */}
      <div style={{ position: 'absolute', top: '15%', left: '20%', width: 400, height: 400, borderRadius: '50%', background: 'radial-gradient(circle, rgba(0,245,212,0.07) 0%, transparent 70%)', zIndex: 0 }} />
      <div style={{ position: 'absolute', bottom: '10%', right: '15%', width: 350, height: 350, borderRadius: '50%', background: 'radial-gradient(circle, rgba(123,47,255,0.07) 0%, transparent 70%)', zIndex: 0 }} />

      {/* Login Card */}
      <div style={{
        position: 'relative', zIndex: 10, width: '100%', maxWidth: 420,
        background: 'rgba(8,14,31,0.88)', border: '1px solid rgba(0,245,212,0.2)',
        borderRadius: 24, padding: '44px 40px', boxShadow: '0 8px 64px rgba(0,0,0,0.7), 0 0 0 1px rgba(0,245,212,0.06)',
        backdropFilter: 'blur(24px)',
        animation: 'fadeInUp 0.5s ease both',
      }}>
        {/* Logo */}
        <div style={{ textAlign: 'center', marginBottom: 36 }}>
          <div style={{ fontSize: '2.8rem', marginBottom: 8, lineHeight: 1 }}>⬡</div>
          <h1 style={{ fontSize: '1.6rem', fontWeight: 800, color: 'var(--text-primary)', margin: 0 }}>
            Secure<span style={{ color: 'var(--accent)' }}>Flow</span>
          </h1>
          <p style={{ color: 'var(--text-muted)', fontSize: '0.82rem', marginTop: 6 }}>Intrusion Detection System</p>
        </div>

        {error && (
          <div style={{ background: 'rgba(255,69,96,0.12)', border: '1px solid rgba(255,69,96,0.3)', borderRadius: 8, padding: '10px 14px', color: 'var(--danger)', fontSize: '0.85rem', marginBottom: 20 }}>
            ⚠ {error}
          </div>
        )}

        <form onSubmit={handleSubmit} style={{ display: 'flex', flexDirection: 'column', gap: 18 }}>
          <div>
            <label className="sf-label">Email / Username</label>
            <input
              className="sf-input" type="email" placeholder="admin@secureflow.io"
              value={form.username} onChange={e => setForm(f => ({ ...f, username: e.target.value }))}
              required autoFocus
            />
          </div>
          <div>
            <label className="sf-label">Password</label>
            <input
              className="sf-input" type="password" placeholder="••••••••"
              value={form.password} onChange={e => setForm(f => ({ ...f, password: e.target.value }))}
              required
            />
          </div>
          <button
            type="submit" className="sf-btn sf-btn-primary"
            style={{ width: '100%', justifyContent: 'center', padding: '12px', fontSize: '0.95rem', marginTop: 4 }}
            disabled={loading}
          >
            {loading ? 'Authenticating…' : '→ Sign In'}
          </button>
        </form>

        <p style={{ textAlign: 'center', marginTop: 22, color: 'var(--text-muted)', fontSize: '0.8rem' }}>
          Don't have an account? <a href="/register" style={{ color: 'var(--accent)', textDecoration: 'none', fontWeight: 600 }}>Register</a>
        </p>

        <div style={{ marginTop: 28, paddingTop: 20, borderTop: '1px solid var(--border)', display: 'flex', gap: 8, justifyContent: 'center', flexWrap: 'wrap' }}>
          {['ML Detection', 'Real-time IDS', 'MITRE ATT&CK'].map(l => (
            <span key={l} className="sf-pill sf-pill-live" style={{ fontSize: '0.68rem' }}>{l}</span>
          ))}
        </div>
      </div>
    </div>
  );
}
