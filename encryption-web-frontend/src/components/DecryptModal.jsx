import React, { useState, useEffect } from 'react';
import { ShieldCheck, X, Clock, Hash, CheckCircle2, AlertTriangle, Key, Download, Copy, Check } from 'lucide-react';
import { api } from '../api';

function formatNs(ns) {
  if (!ns && ns !== 0) return '0 µs';
  if (ns < 1000) return `${ns} ns`;
  if (ns < 1000000) return `${(ns / 1000).toFixed(2)} µs`;
  return `${(ns / 1000000).toFixed(3)} ms`;
}

export default function DecryptModal({ record, onClose }) {
  const [selectedCipher, setSelectedCipher] = useState('aes');
  const [loading, setLoading] = useState(true);
  const [decryptedData, setDecryptedData] = useState(null);
  const [error, setError] = useState('');
  const [copiedHex, setCopiedHex] = useState(false);

  useEffect(() => {
    let ignore = false;
    api.decryptPersonalData(record.id, selectedCipher)
      .then((res) => {
        if (!ignore) {
          setDecryptedData(res);
          setError('');
          setLoading(false);
        }
      })
      .catch((err) => {
        if (!ignore) {
          setError(err.message || 'Decryption failed');
          setLoading(false);
        }
      });
    return () => {
      ignore = true;
    };
  }, [record.id, selectedCipher]);

  const handleDownloadDecryptedJSON = () => {
    if (!decryptedData) return;
    const now = new Date().toISOString();
    const exportPayload = {
      record_id: record.id,
      label: record.label,
      decrypted_at: now,
      decrypted_with_algorithm: selectedCipher.toUpperCase(),
      decryption_time_ns: decryptedData.decryption_time_ns,
      sha256_checksum: record.sha256_checksum,
      integrity_valid: decryptedData.integrity_valid,
      gdpr_uu_pdp_personal_data: decryptedData.data,
    };
    const blob = new Blob([JSON.stringify(exportPayload, null, 2)], { type: 'application/json' });
    const url = window.URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `decrypted_${record.label.toLowerCase().replace(/[^a-z0-9_-]/g, '_')}_${selectedCipher}.json`;
    document.body.appendChild(a);
    a.click();
    window.URL.revokeObjectURL(url);
    document.body.removeChild(a);
  };

  const handleCopyHex = (text) => {
    if (!text) return;
    navigator.clipboard.writeText(text);
    setCopiedHex(true);
    setTimeout(() => setCopiedHex(false), 2000);
  };

  const activeHex = selectedCipher === 'aes' 
    ? record.aes_cipher_hex 
    : selectedCipher === 'rc4' 
      ? record.rc4_cipher_hex 
      : record.des_cipher_hex;

  return (
    <div className="modal-overlay" onClick={onClose}>
      <div className="modal-content" onClick={(e) => e.stopPropagation()}>
        <div className="modal-header">
          <div>
            <h3 className="modal-title" style={{ display: 'flex', alignItems: 'center', gap: '0.45rem' }}>
              <ShieldCheck color="var(--aes-color)" size={18} />
              <span>Decrypted Personal Record</span>
            </h3>
            <p style={{ fontSize: '0.775rem', color: 'var(--text-muted)', marginTop: '0.2rem' }}>
              Record: <strong style={{ color: 'var(--text-main)' }}>{record.label}</strong> • ID: <code style={{ fontSize: '0.725rem' }}>{record.id.slice(0, 8)}</code>
            </p>
          </div>
          <button className="close-btn" onClick={onClose} title="Close"><X size={16} /></button>
        </div>

        {/* Algorithm selector pills */}
        <div style={{ marginBottom: '1.25rem' }}>
          <label className="form-label" style={{ marginBottom: '0.45rem', display: 'flex', alignItems: 'center', gap: '0.35rem' }}>
            <Key size={12} />
            <span>Select Decryption Cipher Algorithm:</span>
          </label>
          <div style={{ display: 'flex', gap: '0.45rem' }}>
            <button
              className={`btn btn-sm ${selectedCipher === 'aes' ? 'btn-primary' : 'btn-secondary'}`}
              onClick={() => { if (selectedCipher !== 'aes') { setSelectedCipher('aes'); setLoading(true); } }}
            >
              <span className="badge badge-aes">AES-256-CBC</span>
            </button>
            <button
              className={`btn btn-sm ${selectedCipher === 'rc4' ? 'btn-primary' : 'btn-secondary'}`}
              onClick={() => { if (selectedCipher !== 'rc4') { setSelectedCipher('rc4'); setLoading(true); } }}
            >
              <span className="badge badge-rc4">RC4-128</span>
            </button>
            <button
              className={`btn btn-sm ${selectedCipher === 'des' ? 'btn-primary' : 'btn-secondary'}`}
              onClick={() => { if (selectedCipher !== 'des') { setSelectedCipher('des'); setLoading(true); } }}
            >
              <span className="badge badge-des">DES-CBC</span>
            </button>
          </div>
        </div>

        {loading && (
          <div style={{ padding: '2.5rem', textAlign: 'center', color: 'var(--text-muted)', fontFamily: 'var(--font-mono)', fontSize: '0.825rem' }}>
            Decrypting {record.label} using {selectedCipher.toUpperCase()}...
          </div>
        )}

        {error && (
          <div className="alert-banner alert-banner-error">
            <AlertTriangle size={15} />
            <span>{error}</span>
          </div>
        )}

        {decryptedData && !loading && (
          <div>
            {/* Decryption Benchmark Summary */}
            <div className="grid-3" style={{ marginBottom: '1.25rem' }}>
              <div className="stat-box">
                <div className="stat-label">Algorithm</div>
                <div className="stat-value" style={{ fontSize: '1.05rem', textTransform: 'uppercase', color: 'var(--text-main)' }}>
                  {decryptedData.cipher_algorithm}
                </div>
              </div>
              <div className="stat-box">
                <div className="stat-label" style={{ display: 'flex', alignItems: 'center', gap: '0.3rem' }}>
                  <Clock size={11} /> Decryption Latency
                </div>
                <div className="stat-value tabular-nums" style={{ fontSize: '1.05rem', color: 'var(--aes-color)' }}>
                  {formatNs(decryptedData.decryption_time_ns)}
                </div>
              </div>
              <div className="stat-box">
                <div className="stat-label" style={{ display: 'flex', alignItems: 'center', gap: '0.3rem' }}>
                  <Hash size={11} /> SHA-256 Checksum
                </div>
                <div className="stat-value" style={{ fontSize: '0.85rem', color: decryptedData.integrity_valid ? 'var(--aes-color)' : 'var(--danger-color)', display: 'flex', alignItems: 'center', gap: '0.3rem' }}>
                  {decryptedData.integrity_valid ? (
                    <>
                      <CheckCircle2 size={14} />
                      <span>Verified Match</span>
                    </>
                  ) : 'Mismatch'}
                </div>
              </div>
            </div>

            {/* GDPR & UU PDP Fields Display */}
            <div style={{ marginBottom: '1.25rem' }}>
              <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: '0.45rem' }}>
                <span className="stat-label">Decrypted GDPR / UU PDP Personal Attributes:</span>
                <span className="badge badge-neutral">Confidential Record</span>
              </div>

              <div style={{
                backgroundColor: 'var(--bg-well)',
                border: '1px solid var(--border-subtle)',
                borderRadius: '6px',
                padding: '1rem',
                display: 'grid',
                gridTemplateColumns: 'repeat(auto-fit, minmax(220px, 1fr))',
                gap: '0.85rem'
              }}>
                <div>
                  <span style={{ fontSize: '0.7rem', color: 'var(--text-muted)', display: 'block', textTransform: 'uppercase', fontWeight: 600 }}>Full Name (Data Umum)</span>
                  <strong style={{ color: 'var(--text-main)', fontSize: '0.875rem' }}>{decryptedData.data.full_name || '—'}</strong>
                </div>
                <div>
                  <span style={{ fontSize: '0.7rem', color: 'var(--text-muted)', display: 'block', textTransform: 'uppercase', fontWeight: 600 }}>NIK / ID (UU PDP Art. 4)</span>
                  <strong style={{ color: 'var(--rc4-color)', fontSize: '0.875rem', fontFamily: 'var(--font-mono)' }}>{decryptedData.data.nik || '—'}</strong>
                </div>
                <div>
                  <span style={{ fontSize: '0.7rem', color: 'var(--text-muted)', display: 'block', textTransform: 'uppercase', fontWeight: 600 }}>Date of Birth</span>
                  <span style={{ color: 'var(--text-secondary)', fontSize: '0.85rem' }}>{decryptedData.data.date_of_birth || '—'}</span>
                </div>
                <div>
                  <span style={{ fontSize: '0.7rem', color: 'var(--text-muted)', display: 'block', textTransform: 'uppercase', fontWeight: 600 }}>Contact Info</span>
                  <span style={{ color: 'var(--text-secondary)', fontSize: '0.85rem' }}>
                    {decryptedData.data.email || '—'} • {decryptedData.data.phone_number || '—'}
                  </span>
                </div>
                <div style={{ gridColumn: '1 / -1' }}>
                  <span style={{ fontSize: '0.7rem', color: 'var(--text-muted)', display: 'block', textTransform: 'uppercase', fontWeight: 600 }}>Residential Address</span>
                  <span style={{ color: 'var(--text-secondary)', fontSize: '0.85rem' }}>{decryptedData.data.address || '—'}</span>
                </div>
                <div>
                  <span style={{ fontSize: '0.7rem', color: 'var(--des-color)', display: 'block', textTransform: 'uppercase', fontWeight: 600 }}>Health Data (Data Spesifik)</span>
                  <span style={{ color: '#78350f', fontSize: '0.825rem' }}>{decryptedData.data.health_data || 'None recorded'}</span>
                </div>
                <div>
                  <span style={{ fontSize: '0.7rem', color: 'var(--des-color)', display: 'block', textTransform: 'uppercase', fontWeight: 600 }}>Financial Data (Data Spesifik)</span>
                  <span style={{ color: '#78350f', fontSize: '0.825rem' }}>{decryptedData.data.financial_data || 'None recorded'}</span>
                </div>
              </div>
            </div>

            {/* Ciphertext details with Copy */}
            <div style={{ marginBottom: '0.5rem' }}>
              <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: '0.35rem' }}>
                <span className="stat-label">Stored Ciphertext Hex Snippet ({selectedCipher.toUpperCase()}):</span>
                <button
                  type="button"
                  className="btn btn-ghost btn-sm"
                  onClick={() => handleCopyHex(activeHex)}
                  style={{ padding: '0.15rem 0.45rem', fontSize: '0.7rem' }}
                >
                  {copiedHex ? <Check size={11} color="var(--aes-color)" /> : <Copy size={11} />}
                  <span>{copiedHex ? 'Copied' : 'Copy Hex'}</span>
                </button>
              </div>
              <div className="code-box">
                {activeHex}
              </div>
            </div>
          </div>
        )}

        <div style={{ marginTop: '1.25rem', display: 'flex', justifyContent: 'flex-end', gap: '0.55rem' }}>
          {decryptedData && !loading && (
            <button
              className="btn btn-primary"
              onClick={handleDownloadDecryptedJSON}
            >
              <Download size={13} />
              <span>Download Decrypted JSON ({selectedCipher.toUpperCase()})</span>
            </button>
          )}
          <button className="btn btn-secondary" onClick={onClose}>Close</button>
        </div>
      </div>
    </div>
  );
}
