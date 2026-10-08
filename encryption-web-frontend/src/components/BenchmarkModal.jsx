import React, { useState } from 'react';
import { Gauge, X, Play, TrendingUp } from 'lucide-react';
import { api } from '../api';

export default function BenchmarkModal({ file, onClose }) {
  const [iterations, setIterations] = useState(5);
  const [loading, setLoading] = useState(false);
  const [result, setResult] = useState(null);
  const [error, setError] = useState('');

  const runBenchmark = async () => {
    setLoading(true);
    setError('');
    try {
      const data = await api.runBenchmark(file.id, iterations);
      setResult(data);
    } catch (err) {
      setError(err.message || 'Benchmark execution failed');
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
    <div className="modal-overlay" onClick={onClose}>
      <div className="modal-content" onClick={(e) => e.stopPropagation()} style={{ maxWidth: '820px' }}>
        <div className="modal-header">
          <div>
            <h3 className="modal-title" style={{ display: 'flex', alignItems: 'center', gap: '0.45rem' }}>
              <Gauge color="var(--primary)" size={18} />
              <span>Multi-Download Benchmark & Analysis</span>
            </h3>
            <p style={{ fontSize: '0.775rem', color: 'var(--text-muted)', marginTop: '0.2rem' }}>
              Target: <strong style={{ color: 'var(--text-main)' }}>{file.file_name}</strong> ({formatBytes(file.original_size)})
            </p>
          </div>
          <button className="close-btn" onClick={onClose}><X size={16} /></button>
        </div>

        {/* Controls */}
        <div style={{
          display: 'flex',
          alignItems: 'flex-end',
          gap: '1rem',
          backgroundColor: 'var(--bg-well)',
          padding: '0.85rem 1rem',
          borderRadius: '6px',
          marginBottom: '1.25rem',
          border: '1px solid var(--border-subtle)'
        }}>
          <div>
            <label className="form-label" style={{ marginBottom: '0.35rem' }}>Iterations (Cycles):</label>
            <select
              className="form-select"
              value={iterations}
              onChange={(e) => setIterations(Number(e.target.value))}
              style={{ width: '150px' }}
              disabled={loading}
            >
              <option value={3}>3 Runs</option>
              <option value={5}>5 Runs (Standard)</option>
              <option value={10}>10 Runs (Deep)</option>
              <option value={20}>20 Runs (Stress)</option>
            </select>
          </div>

          <div>
            <button
              className="btn btn-primary"
              onClick={runBenchmark}
              disabled={loading}
              style={{ display: 'flex', alignItems: 'center', gap: '0.45rem' }}
            >
              <Play size={13} />
              <span>{loading ? `Executing ${iterations} cycles...` : `Start Multi-Download Benchmark`}</span>
            </button>
          </div>
        </div>

        {error && (
          <div className="alert-banner alert-banner-error">
            <span>{error}</span>
          </div>
        )}

        {result && (
          <div>
            <h4 style={{ fontSize: '0.875rem', fontWeight: 600, color: 'var(--text-main)', marginBottom: '0.75rem', display: 'flex', alignItems: 'center', gap: '0.4rem' }}>
              <TrendingUp size={14} color="var(--aes-color)" />
              <span>Comparative Performance Summary ({result.iterations} Iterations)</span>
            </h4>

            <div className="table-wrapper" style={{ marginBottom: '1.25rem' }}>
              <table className="data-table">
                <thead>
                  <tr>
                    <th>Algorithm</th>
                    <th>Ciphertext Size</th>
                    <th>Expansion</th>
                    <th>Avg Duration</th>
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
                        <td>
                          <span className={`badge ${badgeClass}`}>{cipherName}</span>
                        </td>
                        <td className="tabular-nums">{formatBytes(s.cipher_size)}</td>
                        <td className="tabular-nums">
                          <span style={{ color: s.expansion_ratio > 1 ? 'var(--des-color)' : 'var(--aes-color)', fontWeight: 600 }}>
                            {(s.expansion_ratio * 100).toFixed(1)}%
                          </span>
                        </td>
                        <td className="tabular-nums">
                          <strong style={{ color: 'var(--text-main)' }}>{formatNs(s.avg_ns)}</strong>
                        </td>
                        <td className="tabular-nums" style={{ fontSize: '0.75rem', color: 'var(--text-muted)' }}>
                          {formatNs(s.min_ns)} / {formatNs(s.max_ns)}
                        </td>
                        <td className="tabular-nums" style={{ textAlign: 'right' }}>
                          <span style={{ color: 'var(--rc4-color)', fontWeight: 600 }}>
                            {s.avg_throughput_mb_s} MB/s
                          </span>
                        </td>
                      </tr>
                    );
                  })}
                </tbody>
              </table>
            </div>

            {/* Visual Bar Comparison */}
            <div style={{
              backgroundColor: 'var(--bg-well)',
              padding: '1.15rem',
              borderRadius: '6px',
              border: '1px solid var(--border-subtle)',
              marginBottom: '1.25rem'
            }}>
              <span style={{ fontSize: '0.725rem', color: 'var(--text-muted)', marginBottom: '0.75rem', textTransform: 'uppercase', letterSpacing: '0.04em', display: 'block', fontWeight: 600 }}>
                Relative Decryption Latency:
              </span>
              {Object.entries(result.summaries).map(([cipherName, s]) => {
                const allAvgs = Object.values(result.summaries).map((x) => x.avg_ns);
                const maxAvg = Math.max(...allAvgs, 1);
                const percent = Math.max(10, Math.round((s.avg_ns / maxAvg) * 100));

                const color = cipherName.includes('AES')
                  ? 'var(--aes-color)'
                  : cipherName.includes('RC4')
                  ? 'var(--rc4-color)'
                  : 'var(--des-color)';

                return (
                  <div key={cipherName} style={{ marginBottom: '0.75rem' }}>
                    <div style={{ display: 'flex', justifyContent: 'space-between', fontSize: '0.8rem', marginBottom: '0.25rem' }}>
                      <span style={{ fontWeight: 600, color: 'var(--text-main)' }}>{cipherName}</span>
                      <span className="tabular-nums" style={{ color: 'var(--text-muted)' }}>{formatNs(s.avg_ns)} ({s.avg_throughput_mb_s} MB/s)</span>
                    </div>
                    <div style={{ height: '7px', backgroundColor: '#e5e7eb', borderRadius: '4px', overflow: 'hidden' }}>
                      <div
                        style={{
                          height: '100%',
                          width: `${percent}%`,
                          backgroundColor: color,
                          borderRadius: '4px',
                          transition: 'width 0.4s ease'
                        }}
                      />
                    </div>
                  </div>
                );
              })}
            </div>
          </div>
        )}

        <div style={{ display: 'flex', justifyContent: 'flex-end', marginTop: '1rem' }}>
          <button className="btn btn-secondary" onClick={onClose}>Close</button>
        </div>
      </div>
    </div>
  );
}
