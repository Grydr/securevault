import React from 'react';
import { Shield, LogOut, User } from 'lucide-react';

export default function Navbar({ user, onLogout }) {
  return (
    <header className="navbar">
      <div className="navbar-inner">
        <div className="navbar-brand">
          <div className="brand-icon-box">
            <Shield size={16} strokeWidth={2.5} />
          </div>
          <div style={{ display: 'flex', alignItems: 'baseline', gap: '0.65rem' }}>
            <span>CryptaVault</span>
            <span style={{ 
              fontSize: '0.725rem',
              fontWeight: 500,
              color: 'var(--text-muted)',
              fontFamily: 'var(--font-mono)',
              letterSpacing: '0.04em'
            }}>
              LABORATORY EDITION
            </span>
          </div>
        </div>

        <div className="navbar-user">
          <div className="user-badge">
            <User size={13} color="var(--text-muted)" />
            <span>{user?.username}</span>
          </div>

          <button 
            className="btn btn-secondary btn-sm" 
            onClick={onLogout}
            title="Sign out of vault"
          >
            <LogOut size={13} />
            <span>Sign Out</span>
          </button>
        </div>
      </div>
    </header>
  );
}
