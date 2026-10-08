import React, { useState, useEffect, useCallback } from 'react';
import { Shield, Plus, Trash2, Eye, FileText, CheckCircle2, Download, X } from 'lucide-react';
import { api } from '../api';
import DecryptModal from './DecryptModal';

export default function PersonalDataTab() {
  const [records, setRecords] = useState([]);
  const [loading, setLoading] = useState(false);
  const [showAddForm, setShowAddForm] = useState(false);
  const [selectedRecord, setSelectedRecord] = useState(null);
  const [error, setError] = useState('');
  const [success, setSuccess] = useState('');

  // Form states
  const [label, setLabel] = useState('');
  const [fullName, setFullName] = useState('');
  const [nik, setNik] = useState('');
  const [dateOfBirth, setDateOfBirth] = useState('');
  const [email, setEmail] = useState('');
  const [phone, setPhone] = useState('');
  const [address, setAddress] = useState('');
  const [healthData, setHealthData] = useState('');
  const [financialData, setFinancialData] = useState('');
  const [biometricNote, setBiometricNote] = useState('');

  const loadRecords = useCallback(async () => {
    setLoading(true);
    try {
      const data = await api.getPersonalData();
      setRecords(data);
    } catch (err) {
      setError(err.message || 'Failed to load personal data');
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    loadRecords();
  }, [loadRecords]);

  const handleCreate = async (e) => {
    e.preventDefault();
    setError('');
    setSuccess('');
    try {
      await api.storePersonalData(label || 'Personal Profile', {
        full_name: fullName,
        nik: nik,
        date_of_birth: dateOfBirth,
        email: email,
        phone_number: phone,
        address: address,
        health_data: healthData,
        financial_data: financialData,
        biometric_note: biometricNote,
      });
      setSuccess('Private data encrypted with AES-256, RC4, and DES successfully.');
      setShowAddForm(false);
      // Reset form
      setLabel('');
      setFullName('');
      setNik('');
      setDateOfBirth('');
      setEmail('');
      setPhone('');
      setAddress('');
      setHealthData('');
      setFinancialData('');
      setBiometricNote('');
      loadRecords();
      setTimeout(() => setSuccess(''), 4000);
    } catch (err) {
      setError(err.message || 'Failed to save encrypted personal data');
    }
  };

  const handleDelete = async (id) => {
    if (!window.confirm('Delete this encrypted record and all its ciphertexts?')) return;
    try {
      await api.deletePersonalData(id);
      loadRecords();
    } catch (err) {
      setError(err.message || 'Failed to delete record');
    }
  };

  const handleQuickDownload = async (record, cipher = 'aes') => {
    try {
      const res = await api.decryptPersonalData(record.id, cipher);
      const now = new Date().toISOString();
      const exportPayload = {
        record_id: record.id,
        label: record.label,
        decrypted_at: now,
        decrypted_with_algorithm: cipher.toUpperCase(),
        decryption_time_ns: res.decryption_time_ns,
        sha256_checksum: record.sha256_checksum,
        integrity_valid: res.integrity_valid,
        gdpr_uu_pdp_personal_data: res.data,
      };
      const blob = new Blob([JSON.stringify(exportPayload, null, 2)], { type: 'application/json' });
      const url = window.URL.createObjectURL(blob);
      const a = document.createElement('a');
      a.href = url;
      a.download = `decrypted_${record.label.toLowerCase().replace(/[^a-z0-9_-]/g, '_')}_${cipher}.json`;
      document.body.appendChild(a);
      a.click();
      window.URL.revokeObjectURL(url);
      document.body.removeChild(a);
      setSuccess(`Downloaded decrypted record for "${record.label}" using ${cipher.toUpperCase()} (${formatNs(res.decryption_time_ns)}).`);
      setTimeout(() => setSuccess(''), 4000);
    } catch (err) {
      setError(`Failed to decrypt and download: ${err.message}`);
    }
  };

  const formatNs = (ns) => {
    if (!ns && ns !== 0) return '0 µs';
    if (ns < 1000) return `${ns} ns`;
    if (ns < 1000000) return `${(ns / 1000).toFixed(2)} µs`;
    return `${(ns / 1000000).toFixed(3)} ms`;
  };

  return (
    <div>
      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start', marginBottom: '1.5rem', flexWrap: 'wrap', gap: '1rem' }}>
        <div>
          <h2 style={{ fontSize: '1.15rem', fontWeight: 600, color: 'var(--text-main)', display: 'flex', alignItems: 'center', gap: '0.45rem', letterSpacing: '-0.01em' }}>
            <Shield color="var(--primary)" size={18} />
            <span>GDPR & UU PDP Protected Data Vault</span>
          </h2>
          <p style={{ fontSize: '0.8rem', color: 'var(--text-muted)', marginTop: '0.15rem' }}>
            Every entry is simultaneously encrypted with AES-256-CBC, RC4-128, and DES-CBC using unique initialization vectors.
          </p>
        </div>
        <button
          className={showAddForm ? 'btn btn-secondary' : 'btn btn-primary'}
          onClick={() => setShowAddForm(!showAddForm)}
        >
          {showAddForm ? <X size={14} /> : <Plus size={14} />}
          <span>{showAddForm ? 'Cancel' : 'New Encrypted Record'}</span>
        </button>
      </div>

      {error && (
        <div className="alert-banner alert-banner-error">
          <span>{error}</span>
        </div>
      )}

      {success && (
        <div className="alert-banner alert-banner-success">
          <CheckCircle2 size={15} />
          <span>{success}</span>
        </div>
      )}

      {showAddForm && (
        <div className="card" style={{ marginBottom: '1.75rem' }}>
          <div className="card-header">
            <h3 className="card-title">New Private Data Record (EU GDPR & UU PDP No. 27/2022)</h3>
          </div>
          <form onSubmit={handleCreate}>
            <div className="form-group">
              <label className="form-label">Record Label / Alias</label>
              <input
                type="text"
                className="form-input"
                placeholder="e.g. Primary Identity, Banking Profile"
                value={label}
                onChange={(e) => setLabel(e.target.value)}
                required
              />
            </div>

            <div style={{ marginBottom: '1.25rem', padding: '0.85rem', backgroundColor: 'var(--bg-well)', borderRadius: '6px', border: '1px solid var(--border-subtle)' }}>
              <span style={{ fontSize: '0.725rem', fontWeight: 600, textTransform: 'uppercase', letterSpacing: '0.04em', color: 'var(--text-secondary)', display: 'block', marginBottom: '0.75rem' }}>
                Classification: Data Pribadi Umum (General Personal Data)
              </span>

              <div className="grid-2">
                <div className="form-group">
                  <label className="form-label">Full Name</label>
                  <input
                    type="text"
                    className="form-input"
                    placeholder="e.g. Budi Santoso"
                    value={fullName}
                    onChange={(e) => setFullName(e.target.value)}
                    required
                  />
                </div>

                <div className="form-group">
                  <label className="form-label">NIK / National ID Number (UU PDP)</label>
                  <input
                    type="text"
                    className="form-input tabular-nums"
                    placeholder="e.g. 3171012345670001 (16 digits)"
                    value={nik}
                    onChange={(e) => setNik(e.target.value)}
                    required
                  />
                </div>
              </div>

              <div className="grid-3">
                <div className="form-group">
                  <label className="form-label">Date of Birth</label>
                  <input
                    type="date"
                    className="form-input"
                    value={dateOfBirth}
                    onChange={(e) => setDateOfBirth(e.target.value)}
                  />
                </div>

                <div className="form-group">
                  <label className="form-label">Email Address</label>
                  <input
                    type="email"
                    className="form-input"
                    placeholder="user@example.com"
                    value={email}
                    onChange={(e) => setEmail(e.target.value)}
                  />
                </div>

                <div className="form-group">
                  <label className="form-label">Phone Number</label>
                  <input
                    type="text"
                    className="form-input"
                    placeholder="+62 812-3456-7890"
                    value={phone}
                    onChange={(e) => setPhone(e.target.value)}
                  />
                </div>
              </div>

              <div className="form-group" style={{ marginBottom: 0 }}>
                <label className="form-label">Residential Address</label>
                <input
                  type="text"
                  className="form-input"
                  placeholder="e.g. Jl. Sudirman No. 10, Jakarta Pusat"
                  value={address}
                  onChange={(e) => setAddress(e.target.value)}
                />
              </div>
            </div>

            <div style={{ marginBottom: '1.25rem', padding: '0.85rem', backgroundColor: 'var(--bg-well)', borderRadius: '6px', border: '1px solid var(--border-subtle)' }}>
              <span style={{ fontSize: '0.725rem', fontWeight: 600, textTransform: 'uppercase', letterSpacing: '0.04em', color: 'var(--des-color)', display: 'block', marginBottom: '0.75rem' }}>
                Classification: Data Pribadi Spesifik (Sensitive Personal Data)
              </span>

              <div className="grid-2">
                <div className="form-group">
                  <label className="form-label">Health Data (UU PDP Article 4)</label>
                  <textarea
                    className="form-textarea"
                    placeholder="e.g. Blood Type O+, Penicillin Allergy, Medical History"
                    value={healthData}
                    onChange={(e) => setHealthData(e.target.value)}
                  />
                </div>

                <div className="form-group">
                  <label className="form-label">Financial Data (UU PDP Article 4)</label>
                  <textarea
                    className="form-textarea"
                    placeholder="e.g. Bank BCA: 0123456789, NPWP: 98.765.432.1-012.000"
                    value={financialData}
                    onChange={(e) => setFinancialData(e.target.value)}
                  />
                </div>
              </div>

              <div className="form-group" style={{ marginBottom: 0 }}>
                <label className="form-label">Biometric Notes / Identifiers</label>
                <input
                  type="text"
                  className="form-input"
                  placeholder="e.g. Terminal registration token, biometric hash"
                  value={biometricNote}
                  onChange={(e) => setBiometricNote(e.target.value)}
                />
              </div>
            </div>

            <div style={{ display: 'flex', gap: '0.55rem', justifyContent: 'flex-end' }}>
              <button type="button" className="btn btn-secondary" onClick={() => setShowAddForm(false)}>Cancel</button>
              <button type="submit" className="btn btn-primary">Encrypt & Save Record</button>
            </div>
          </form>
        </div>
      )}

      {/* Records Table */}
      <div className="card">
        <div className="card-header">
          <h3 className="card-title">Encrypted Records in Database ({records.length})</h3>
        </div>

        {loading ? (
          <p style={{ color: 'var(--text-muted)', textAlign: 'center', padding: '2.5rem', fontFamily: 'var(--font-mono)', fontSize: '0.825rem' }}>
            Loading encrypted records...
          </p>
        ) : records.length === 0 ? (
          <div style={{ textAlign: 'center', padding: '3.5rem 1rem', color: 'var(--text-muted)' }}>
            <FileText size={36} color="var(--text-dim)" style={{ margin: '0 auto 0.75rem', display: 'block' }} />
            <p style={{ fontWeight: 600, color: 'var(--text-secondary)', fontSize: '0.875rem' }}>No encrypted private data stored yet.</p>
            <p style={{ fontSize: '0.8rem', color: 'var(--text-dim)', marginTop: '0.2rem' }}>
              Click "New Encrypted Record" above to add GDPR and UU PDP compliant records.
            </p>
          </div>
        ) : (
          <div className="table-wrapper">
            <table className="data-table">
              <thead>
                <tr>
                  <th>Label</th>
                  <th>Plain Size</th>
                  <th>AES-256 (Size / Enc Time)</th>
                  <th>RC4 (Size / Enc Time)</th>
                  <th>DES (Size / Enc Time)</th>
                  <th style={{ textAlign: 'right' }}>Actions</th>
                </tr>
              </thead>
              <tbody>
                {records.map((r) => (
                  <tr key={r.id}>
                    <td>
                      <strong style={{ color: 'var(--text-main)' }}>{r.label}</strong>
                      <span className="tabular-nums" style={{ display: 'block', fontSize: '0.72rem', color: 'var(--text-dim)' }}>
                        {r.id.slice(0, 8)}
                      </span>
                    </td>
                    <td className="tabular-nums">{r.plaintext_size} B</td>
                    <td>
                      <span className="badge badge-aes tabular-nums">{r.aes_cipher_size} B</span>
                      <span className="tabular-nums" style={{ fontSize: '0.725rem', color: 'var(--text-muted)', display: 'block', marginTop: '0.15rem' }}>
                        {formatNs(r.aes_duration_ns)}
                      </span>
                    </td>
                    <td>
                      <span className="badge badge-rc4 tabular-nums">{r.rc4_cipher_size} B</span>
                      <span className="tabular-nums" style={{ fontSize: '0.725rem', color: 'var(--text-muted)', display: 'block', marginTop: '0.15rem' }}>
                        {formatNs(r.rc4_duration_ns)}
                      </span>
                    </td>
                    <td>
                      <span className="badge badge-des tabular-nums">{r.des_cipher_size} B</span>
                      <span className="tabular-nums" style={{ fontSize: '0.725rem', color: 'var(--text-muted)', display: 'block', marginTop: '0.15rem' }}>
                        {formatNs(r.des_duration_ns)}
                      </span>
                    </td>
                    <td>
                      <div style={{ display: 'flex', gap: '0.35rem', justifyContent: 'flex-end' }}>
                        <button
                          className="btn btn-secondary btn-sm"
                          onClick={() => setSelectedRecord(r)}
                          title="Decrypt & View Details"
                        >
                          <Eye size={12} color="var(--rc4-color)" />
                          <span>Decrypt</span>
                        </button>
                        <button
                          className="btn btn-secondary btn-sm"
                          onClick={() => handleQuickDownload(r, 'aes')}
                          title="Decrypt & Download JSON (AES)"
                        >
                          <Download size={12} color="var(--aes-color)" />
                          <span>Download</span>
                        </button>
                        <button
                          className="btn btn-danger btn-sm"
                          onClick={() => handleDelete(r.id)}
                          title="Delete Record"
                        >
                          <Trash2 size={12} />
                        </button>
                      </div>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </div>

      {selectedRecord && (
        <DecryptModal
          record={selectedRecord}
          onClose={() => setSelectedRecord(null)}
        />
      )}
    </div>
  );
}
