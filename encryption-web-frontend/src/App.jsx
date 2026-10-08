import React, { useState, useEffect } from 'react';
import Navbar from './components/Navbar';
import AuthView from './components/AuthView';
import PersonalDataTab from './components/PersonalDataTab';
import FilesTab from './components/FilesTab';
import BenchmarkTab from './components/BenchmarkTab';
import { api, getToken, setToken } from './api';
import { Shield, Files, Gauge } from 'lucide-react';

export default function App() {
  const [user, setUser] = useState(null);
  const [loading, setLoading] = useState(true);
  const [activeTab, setActiveTab] = useState('files'); // 'files', 'personal', 'benchmark'

  useEffect(() => {
    const handleUnauthorized = () => {
      setUser(null);
    };
    window.addEventListener('auth:unauthorized', handleUnauthorized);

    const checkAuth = async () => {
      const token = getToken();
      if (!token) {
        setLoading(false);
        return;
      }
      try {
        const u = await api.getMe();
        setUser(u);
      } catch (err) {
        console.warn('Session verification failed, logging out', err);
        setToken(null);
        setUser(null);
      } finally {
        setLoading(false);
      }
    };

    checkAuth();
    return () => window.removeEventListener('auth:unauthorized', handleUnauthorized);
  }, []);

  const handleLogout = () => {
    setToken(null);
    setUser(null);
  };

  if (loading) {
    return (
      <div style={{ 
        minHeight: '100vh', 
        display: 'flex', 
        alignItems: 'center', 
        justifyContent: 'center', 
        color: 'var(--text-muted)',
        fontFamily: 'var(--font-mono)',
        fontSize: '0.85rem',
        backgroundColor: 'var(--bg-main)'
      }}>
        Loading CryptaVault Laboratory...
      </div>
    );
  }

  // Not logged in -> Show login/sign up immediately
  if (!user) {
    return <AuthView onAuthSuccess={(u) => setUser(u)} />;
  }

  return (
    <div className="app-container">
      <Navbar user={user} onLogout={handleLogout} />

      <main className="main-content">
        {/* Navigation Tabs (Minimalist Scandinavian Segmented Controller) */}
        <div className="tabs-header">
          <button
            className={`tab-btn ${activeTab === 'files' ? 'active' : ''}`}
            onClick={() => setActiveTab('files')}
          >
            <Files size={14} />
            <span>Encrypted Files (ID Cards, Docs, Videos)</span>
          </button>

          <button
            className={`tab-btn ${activeTab === 'personal' ? 'active' : ''}`}
            onClick={() => setActiveTab('personal')}
          >
            <Shield size={14} />
            <span>GDPR & UU PDP Personal Data</span>
          </button>

          <button
            className={`tab-btn ${activeTab === 'benchmark' ? 'active' : ''}`}
            onClick={() => setActiveTab('benchmark')}
          >
            <Gauge size={14} />
            <span>Empirical Benchmarks & Analysis</span>
          </button>
        </div>

        {/* Tab Content */}
        {activeTab === 'files' && <FilesTab />}
        {activeTab === 'personal' && <PersonalDataTab />}
        {activeTab === 'benchmark' && <BenchmarkTab />}
      </main>
    </div>
  );
}
