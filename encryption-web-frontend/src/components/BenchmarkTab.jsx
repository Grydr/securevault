import React, { useState, useEffect } from 'react';
import { Gauge, Play, TrendingUp, Zap, AlertTriangle, ShieldCheck, FileCode } from 'lucide-react';
import { api } from '../api';

export default function BenchmarkTab() {
  const [files, setFiles] = useState([]);
  const [selectedFileId, setSelectedFileId] = useState('');
  const [iterations, setIterations] = useState(10);
  const [loading, setLoading] = useState(false);
  const [result, setResult] = useState(null);
  const [error, setError] = useState('');

  useEffect(() => {
    api.getFiles().then((data) => {
      setFiles(data);
      if (data.length > 0) {
        setSelectedFileId(data[0].id);
      }
    }).catch(() => {});
  }, []);

  const runBenchmark = async () => {
    if (!selectedFileId) {
      setError('Please select a file to benchmark');
      return;
    }
    setError('');
    setLoading(true);
    try {
      const res = await api.runBenchmark(selectedFileId, iterations);
      setResult(res);
    } catch (err) {
      setError(err.message || 'Benchmark run failed');
    } finally {
      setLoading(false);
    }
  };

  const formatNs = (ns) => {
    if (!ns && ns !== 0) return '0 µs';
    if (ns < 1000) return `${ns} ns`;
    if (ns < 1000000) return `${(ns / 1000).toFixed(2)} µs`;
    return `${(ns / 1000000).toFixed(3)} ms`;
  };

  const formatBytes = (bytes) => {
    if (!bytes) return '0 B';
    const k = 1024;
    const sizes = ['B', 'KB', 'MB', 'GB'];
    const i = Math.floor(Math.log(bytes) / Math.log(k));
    return parseFloat((bytes / Math.pow(k, i)).toFixed(2)) + ' ' + sizes[i];
  };

  return (
    <div>
      <div style={{ marginBottom: '1.5rem' }}>
        <h2 style={{ fontSize: '1.15rem', fontWeight: 600, color: 'var(--text-main)', display: 'flex', alignItems: 'center', gap: '0.45rem', letterSpacing: '-0.01em' }}>
          <Gauge color="var(--primary)" size={18} />
          <span>Cipher Empirical Benchmark & Comparative Matrix</span>
        </h2>
        <p style={{ fontSize: '0.8rem', color: 'var(--text-muted)', marginTop: '0.15rem' }}>
          Empirical multi-download evaluation of AES-256-CBC, RC4-128, and DES-CBC across repeated decryption iterations.
        </p>
      </div>

      {/* Benchmark Control Card */}
      <div className="card" style={{ marginBottom: '1.5rem' }}>
        <div className="card-header">
          <h3 className="card-title">Run Multi-Download Benchmarks</h3>
        </div>

        {files.length === 0 ? (
          <div style={{ color: 'var(--text-muted)', padding: '1.5rem', textAlign: 'center', fontSize: '0.825rem' }}>
            No files available to benchmark. Please upload an ID card image, PDF, or video in the "Encrypted Files" tab first.
          </div>
        ) : (
          <div style={{ display: 'flex', gap: '1rem', flexWrap: 'wrap', alignItems: 'flex-end' }}>
            <div style={{ flex: '1', minWidth: '240px' }}>
              <label className="form-label">Target File</label>
              <select
                className="form-select"
                value={selectedFileId}
                onChange={(e) => setSelectedFileId(e.target.value)}
              >
                {files.map((f) => (
                  <option key={f.id} value={f.id}>
                    {f.file_name} ({formatBytes(f.original_size)} - {f.category})
                  </option>
                ))}
              </select>
            </div>

            <div style={{ width: '160px' }}>
              <label className="form-label">Cycles (Runs)</label>
              <select
                className="form-select"
                value={iterations}
                onChange={(e) => setIterations(Number(e.target.value))}
              >
                <option value={5}>5 Iterations</option>
                <option value={10}>10 Iterations</option>
                <option value={20}>20 Iterations</option>
                <option value={30}>30 Iterations</option>
              </select>
            </div>

            <div>
              <button
                className="btn btn-primary"
                onClick={runBenchmark}
                disabled={loading}
                style={{ padding: '0.5rem 1rem' }}
              >
                <Play size={14} />
                <span>{loading ? `Benchmarking ${iterations}x...` : `Execute Benchmark`}</span>
              </button>
            </div>
          </div>
        )}

        {error && (
          <div className="alert-banner alert-banner-error" style={{ marginTop: '1rem', marginBottom: 0 }}>
            <span>{error}</span>
          </div>
        )}
      </div>

      {/* Benchmark Results */}
      {result && (
        <div className="card" style={{ marginBottom: '1.5rem' }}>
          <div className="card-header">
            <h3 className="card-title" style={{ display: 'flex', alignItems: 'center', gap: '0.45rem' }}>
              <TrendingUp color="var(--aes-color)" size={16} />
              <span>Results for {result.file_name} ({formatBytes(result.original_size)} • {result.iterations} Repeated Cycles)</span>
            </h3>
          </div>

          <div className="table-wrapper" style={{ marginBottom: '1.25rem' }}>
            <table className="data-table">
              <thead>
                <tr>
                  <th>Algorithm</th>
                  <th>Ciphertext Size</th>
                  <th>Expansion</th>
                  <th>Avg Decrypt Time</th>
                  <th>Median Time</th>
                  <th>Min / Max</th>
                  <th style={{ textAlign: 'right' }}>Throughput</th>
                </tr>
              </thead>
              <tbody>
                {Object.entries(result.summaries).map(([cipherName, s]) => {
                  const badgeClass = cipherName.includes('AES')
                    ? 'badge-aes'
                    : cipherName.includes('RC4')
                    ? 'badge-rc4'
                    : 'badge-des';

                  return (
                    <tr key={cipherName}>
                      <td><span className={`badge ${badgeClass}`}>{cipherName}</span></td>
                      <td className="tabular-nums">{formatBytes(s.cipher_size)}</td>
                      <td className="tabular-nums">
                        <span style={{ color: s.expansion_ratio > 1 ? 'var(--des-color)' : 'var(--aes-color)', fontWeight: 600 }}>
                          {(s.expansion_ratio * 100).toFixed(2)}%
                        </span>
                      </td>
                      <td className="tabular-nums"><strong style={{ color: 'var(--text-main)' }}>{formatNs(s.avg_ns)}</strong></td>
                      <td className="tabular-nums">{formatNs(s.median_ns)}</td>
                      <td className="tabular-nums" style={{ fontSize: '0.75rem', color: 'var(--text-muted)' }}>
                        {formatNs(s.min_ns)} / {formatNs(s.max_ns)}
                      </td>
                      <td className="tabular-nums" style={{ textAlign: 'right' }}>
                        <strong style={{ color: 'var(--rc4-color)' }}>{s.avg_throughput_mb_s} MB/s</strong>
                      </td>
                    </tr>
                  );
                })}
              </tbody>
            </table>
          </div>

          {/* Visual Bar Comparison */}
          <div style={{ backgroundColor: 'var(--bg-well)', padding: '1.15rem', borderRadius: '6px', border: '1px solid var(--border-subtle)' }}>
            <span style={{ fontSize: '0.725rem', fontWeight: 600, color: 'var(--text-muted)', textTransform: 'uppercase', letterSpacing: '0.04em', display: 'block', marginBottom: '0.85rem' }}>
              Relative Decryption Latency (Shorter bar is faster):
            </span>
            {Object.entries(result.summaries).map(([cipherName, s]) => {
              const allAvgs = Object.values(result.summaries).map((x) => x.avg_ns);
              const maxAvg = Math.max(...allAvgs, 1);
              const percent = Math.max(12, Math.round((s.avg_ns / maxAvg) * 100));

              const color = cipherName.includes('AES')
                ? 'var(--aes-color)'
                : cipherName.includes('RC4')
                ? 'var(--rc4-color)'
                : 'var(--des-color)';

              return (
                <div key={cipherName} style={{ marginBottom: '0.75rem' }}>
                  <div style={{ display: 'flex', justifyContent: 'space-between', fontSize: '0.8rem', marginBottom: '0.25rem' }}>
                    <span style={{ fontWeight: 600, color: 'var(--text-main)' }}>{cipherName}</span>
                    <span className="tabular-nums" style={{ color: 'var(--text-muted)' }}>{formatNs(s.avg_ns)} • {s.avg_throughput_mb_s} MB/s</span>
                  </div>
                  <div style={{ height: '7px', backgroundColor: '#e5e7eb', borderRadius: '4px', overflow: 'hidden' }}>
                    <div
                      style={{
                        height: '100%',
                        width: `${percent}%`,
                        backgroundColor: color,
                        borderRadius: '4px',
                        transition: 'width 0.4s ease-out'
                      }}
                    />
                  </div>
                </div>
              );
            })}
          </div>
        </div>
      )}

      {/* Cryptographic Comparison Matrix */}
      <div className="card">
        <div className="card-header">
          <h3 className="card-title">Cryptographic Comparison Matrix & Legal Evaluation</h3>
        </div>

        <div className="table-wrapper">
          <table className="data-table">
            <thead>
              <tr>
                <th>Criteria</th>
                <th>AES (Rijndael)</th>
                <th>RC4 (ARC4)</th>
                <th>DES (Data Encryption Standard)</th>
              </tr>
            </thead>
            <tbody>
              <tr>
                <td><strong>Classification</strong></td>
                <td>Symmetric Block Cipher</td>
                <td>Symmetric Stream Cipher</td>
                <td>Symmetric Block Cipher</td>
              </tr>
              <tr>
                <td><strong>Block Operation Mode</strong></td>
                <td>CBC (Cipher Block Chaining) + PKCS#7</td>
                <td>Stream XOR Keystream (HKDF Nonce)</td>
                <td>CBC (Cipher Block Chaining) + PKCS#7</td>
              </tr>
              <tr>
                <td><strong>Key Length</strong></td>
                <td className="tabular-nums">256 bits (32 bytes)</td>
                <td className="tabular-nums">128 bits (16 bytes)</td>
                <td className="tabular-nums">64 bits total (56 bits effective)</td>
              </tr>
              <tr>
                <td><strong>Block Size</strong></td>
                <td className="tabular-nums">128 bits (16 bytes)</td>
                <td>Stream (N/A)</td>
                <td className="tabular-nums">64 bits (8 bytes)</td>
              </tr>
              <tr>
                <td><strong>Hardware Acceleration</strong></td>
                <td><span className="badge badge-aes"><Zap size={10} /> Intel AES-NI / ARMv8</span></td>
                <td><span className="badge badge-neutral">None (Software State Array)</span></td>
                <td><span className="badge badge-neutral">None (Software Bit Permutations)</span></td>
              </tr>
              <tr>
                <td><strong>Security Classification</strong></td>
                <td><span className="badge badge-aes"><ShieldCheck size={10} /> NIST Approved / Modern</span></td>
                <td><span className="badge badge-rc4"><AlertTriangle size={10} /> Deprecated (RFC 7465)</span></td>
                <td><span className="badge badge-des"><AlertTriangle size={10} /> Broken (56-bit Key Space)</span></td>
              </tr>
              <tr>
                <td><strong>GDPR / UU PDP Suitability</strong></td>
                <td>Compliant (Art. 32 GDPR / Art. 35 UU PDP)</td>
                <td>Non-compliant for production storage</td>
                <td>Prohibited due to insufficient key length</td>
              </tr>
            </tbody>
          </table>
        </div>

        <div style={{ marginTop: '1.25rem', padding: '0.85rem 1rem', backgroundColor: 'var(--bg-well)', borderRadius: '6px', border: '1px solid var(--border-subtle)', display: 'flex', alignItems: 'center', gap: '0.65rem' }}>
          <FileCode size={16} color="var(--text-main)" />
          <span style={{ fontSize: '0.8rem', color: 'var(--text-muted)' }}>
            Full comparative benchmark findings, mathematical proofs, and legal justifications are documented in <strong style={{ color: 'var(--text-secondary)' }}>ANALYSIS_REPORT.md</strong>.
          </span>
        </div>
      </div>
    </div>
  );
}
