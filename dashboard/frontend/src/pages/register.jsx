import React, { useState } from 'react';
import { useNavigate } from 'react-router-dom';
import { Registerapi } from '../server/api.js';
import './css/login.css';

function Register() {
  const navigate = useNavigate();
  const [email, setEmail] = useState('');
  const [password, setPassword] = useState('');
  const [confirmPassword, setConfirmPassword] = useState('');
  const [isSubmitting, setIsSubmitting] = useState(false);
  const [errorMessage, setErrorMessage] = useState('');

  const handleSubmit = async (event) => {
    event.preventDefault();
    setErrorMessage('');

    if (!email.trim() || !password.trim()) {
      setErrorMessage('Email and password are required.');
      return;
    }

    if (password.length < 6) {
      setErrorMessage('Password must be at least 6 characters.');
      return;
    }

    if (password !== confirmPassword) {
      setErrorMessage('Password confirmation does not match.');
      return;
    }

    try {
      setIsSubmitting(true);
      const response = await Registerapi(email, password);

      if (response && (response.status === 'success' || response.success === true)) {
        navigate('/login');
        return;
      }

      setErrorMessage('Registration failed. Please try with a different email.');
    } catch {
      setErrorMessage('Unable to complete registration right now.');
    } finally {
      setIsSubmitting(false);
    }
  };

  return (
    <div className="cyber-page auth-page">
      <div className="auth-shell">
        <section className="auth-left cyber-panel register-surface">
          <span className="auth-chip">Identity Enrollment</span>
          <h1>Create your operator profile for Secureflow AI.</h1>
          <p>
            Register a new analyst account to access network telemetry intelligence, threat analytics, and incident monitoring dashboards.
          </p>

          <ul className="auth-value-list">
            <li>Role-focused interface for SOC and IR workflows</li>
            <li>Centralized event visibility and alert processing</li>
            <li>Fast access to traffic intelligence and threat trend pages</li>
          </ul>
        </section>

        <section className="auth-right cyber-panel">
          <div className="auth-form-header">
            <h2>Register Account</h2>
            <p>Provision credentials for analyst access.</p>
          </div>

          <form className="auth-form" onSubmit={handleSubmit}>
            <label htmlFor="register-email">Email</label>
            <input
              id="register-email"
              type="email"
              value={email}
              onChange={(event) => setEmail(event.target.value)}
              placeholder="new-analyst@secureflow.ai"
              autoComplete="email"
            />

            <label htmlFor="register-password">Password</label>
            <input
              id="register-password"
              type="password"
              value={password}
              onChange={(event) => setPassword(event.target.value)}
              placeholder="Create password"
              autoComplete="new-password"
            />

            <label htmlFor="register-confirm-password">Confirm Password</label>
            <input
              id="register-confirm-password"
              type="password"
              value={confirmPassword}
              onChange={(event) => setConfirmPassword(event.target.value)}
              placeholder="Repeat password"
              autoComplete="new-password"
            />

            <div className="auth-form-row">
              <span className="auth-hint">Already have access?</span>
              <button type="button" className="auth-link-btn" onClick={() => navigate('/login')}>
                Go to login
              </button>
            </div>

            {errorMessage && <p className="auth-error">{errorMessage}</p>}

            <button type="submit" className="auth-submit-btn" disabled={isSubmitting}>
              {isSubmitting ? 'Creating Account...' : 'Create Account'}
            </button>
          </form>
        </section>
      </div>
    </div>
  );
}

export default Register;
