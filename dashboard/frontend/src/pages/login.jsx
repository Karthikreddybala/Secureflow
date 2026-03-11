import React, { useState } from 'react';
import { useNavigate } from 'react-router-dom';
import { Loginapi } from '../server/api.js';
import './css/login.css';

function Login() {
  const navigate = useNavigate();
  const [email, setEmail] = useState('');
  const [password, setPassword] = useState('');
  const [keepSignedIn, setKeepSignedIn] = useState(false);
  const [isSubmitting, setIsSubmitting] = useState(false);
  const [errorMessage, setErrorMessage] = useState('');

  const handleSubmit = async (event) => {
    event.preventDefault();
    setErrorMessage('');

    if (!email.trim() || !password.trim()) {
      setErrorMessage('Enter both email and password to continue.');
      return;
    }

    try {
      setIsSubmitting(true);
      const response = await Loginapi(email, password);

      if (response && response.status === 'success') {
        navigate('/dashboard');
        return;
      }

      setErrorMessage('Login failed. Check your credentials and try again.');
    } catch {
      setErrorMessage('Unable to reach authentication service. Try again shortly.');
    } finally {
      setIsSubmitting(false);
    }
  };

  return (
    <div className="cyber-page auth-page">
      <div className="auth-shell">
        <section className="auth-left cyber-panel">
          <span className="auth-chip">Secure Access Layer</span>
          <h1>Authenticate into your network defense control room.</h1>
          <p>
            Access live telemetry, attack insights, and incident response workflows from a hardened operations interface.
          </p>

          <ul className="auth-value-list">
            <li>Real-time threat visibility with centralized dashboards</li>
            <li>Live WebSocket ingestion for alerts and packet events</li>
            <li>Actionable severity intelligence for analyst triage</li>
          </ul>
        </section>

        <section className="auth-right cyber-panel">
          <div className="auth-form-header">
            <h2>Login Account</h2>
            <p>Use your analyst credentials to continue.</p>
          </div>

          <form className="auth-form" onSubmit={handleSubmit}>
            <label htmlFor="login-email">Email</label>
            <input
              id="login-email"
              type="email"
              value={email}
              onChange={(event) => setEmail(event.target.value)}
              placeholder="analyst@secureflow.ai"
              autoComplete="email"
            />

            <label htmlFor="login-password">Password</label>
            <input
              id="login-password"
              type="password"
              value={password}
              onChange={(event) => setPassword(event.target.value)}
              placeholder="Enter password"
              autoComplete="current-password"
            />

            <div className="auth-form-row">
              <label className="auth-checkbox" htmlFor="keep-signed-in">
                <input
                  id="keep-signed-in"
                  type="checkbox"
                  checked={keepSignedIn}
                  onChange={(event) => setKeepSignedIn(event.target.checked)}
                />
                Keep me signed in
              </label>

              <button type="button" className="auth-link-btn" onClick={() => navigate('/register')}>
                Create account
              </button>
            </div>

            {errorMessage && <p className="auth-error">{errorMessage}</p>}

            <button type="submit" className="auth-submit-btn" disabled={isSubmitting}>
              {isSubmitting ? 'Authenticating...' : 'Login'}
            </button>
          </form>
        </section>
      </div>
    </div>
  );
}

export default Login;
