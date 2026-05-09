import { useState, useEffect } from 'react';
import './index.css';

const API = '/api';

// ─── Icons ─────────────────────────────────────────
const MicrosoftIcon = () => (
  <svg width="20" height="20" viewBox="0 0 21 21">
    <rect x="1" y="1" width="9" height="9" fill="#F25022"/>
    <rect x="11" y="1" width="9" height="9" fill="#7FBA00"/>
    <rect x="1" y="11" width="9" height="9" fill="#00A4EF"/>
    <rect x="11" y="11" width="9" height="9" fill="#FFB900"/>
  </svg>
);

const LogoutIcon = () => (
  <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
    <path d="M15.75 9V5.25A2.25 2.25 0 0013.5 3h-6a2.25 2.25 0 00-2.25 2.25v13.5A2.25 2.25 0 007.5 21h6a2.25 2.25 0 002.25-2.25V15m3 0l3-3m0 0l-3-3m3 3H9"/>
  </svg>
);

// ─── Login Page ─────────────────────────────────────
function LoginPage() {
  return (
    <div className="page center">
      <div className="card login-card">
        <img src="/logo.png" className="logo" />

        <h1 className="title">Sign in</h1>
        <p className="subtitle">Use your organization account</p>

        <a href="/auth/login" className="btn">
          <MicrosoftIcon />
          Continue with Microsoft
        </a>

        <p className="footer">
          Secured by <strong>Microsoft Entra ID</strong>
        </p>
      </div>
    </div>
  );
}

// ─── Dashboard ──────────────────────────────────────
function Dashboard({ user }) {
  const [data, setData] = useState(null);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    fetch('/api/dashboard', { credentials: 'include' })
      .then(r => r.json())
      .then(d => {
        setData(d);
        setLoading(false);
      })
      .catch(() => setLoading(false));
  }, []);

  const initials = user.displayName
    ? user.displayName.split(' ').map(n => n[0]).join('').slice(0, 2).toUpperCase()
    : '??';

  return (
    <div className="page">
      {/* Navbar */}
      <div className="navbar">
        <img src="/logo.png" className="logo-small" />

        <div className="nav-user">
          <div className="avatar">{initials}</div>
          <span>{user.displayName}</span>
          <a href="/auth/logout" className="btn-outline">
            <LogoutIcon />  
            Logout
          </a>
        </div>
      </div>

      {/* Hero */}
      <div className="hero">
        <h1>
          Welcome, <span>{user.firstName || user.displayName}</span>
        </h1>
        <p>Your session is secure and active.</p>
      </div>

      {/* Cards */}
      <div className="grid">
        <div className="card">
          <p className="label">User</p>
          <h2>{user.displayName}</h2>
          <p className="muted">{user.email}</p>
        </div>

        {loading ? (
          <div className="card skeleton" />
        ) : data ? (
          <>
            <div className="card">
              <p className="label">Logins</p>
              <h2>{data.stats.logins}</h2>
            </div>

            <div className="card">
              <p className="label">Role</p>
              <h2>{data.stats.role}</h2>
            </div>
          </>
        ) : (
          <div className="card error">Failed to load data</div>
        )}
      </div>
    </div>
  );
}

// ─── Root ───────────────────────────────────────────
export default function App() {
  const [user, setUser] = useState(null);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    fetch('/api/me', { credentials: 'include' })
      .then(r => r.json())
      .then(d => {
        setUser(d.user);
        setLoading(false);
      })
      .catch(() => setLoading(false));
  }, []);

  if (loading) {
    return (
      <div className="center">
        <div className="spinner"></div>
      </div>
    );
  }

  return user ? <Dashboard user={user} /> : <LoginPage />;
}