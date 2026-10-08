import React, { useState, useEffect, useCallback } from 'react';
import { Layers, Upload, Download, Trash2, FileText, Image, Video, Activity, FileCheck, CheckCircle2, Clock, X } from 'lucide-react';
import { api } from '../api';
import BenchmarkModal from './BenchmarkModal';

export default function FilesTab() {
  const [files, setFiles] = useState([]);
  const [loading, setLoading] = useState(false);
  const [categoryFilter, setCategoryFilter] = useState('');
  const [showUpload, setShowUpload] = useState(false);
  const [uploadCategory, setUploadCategory] = useState('id_card');
  const [selectedFile, setSelectedFile] = useState(null);
  const [uploading, setUploading] = useState(false);
  const [error, setError] = useState('');
  const [selectedFileForBench, setSelectedFileForBench] = useState(null);
  const [downloadNotice, setDownloadNotice] = useState(null);

  const loadFiles = useCallback(async () => {
    setLoading(true);
    try {
      const data = await api.getFiles(categoryFilter);
      setFiles(data);
    } catch (err) {
      setError(err.message || 'Failed to load files');
    } finally {
      setLoading(false);
    }
  }, [categoryFilter]);

  useEffect(() => {
    loadFiles();
  }, [loadFiles]);

  const handleUpload = async (e) => {
    e.preventDefault();
    if (!selectedFile) {
      setError('Please select a file to upload');
      return;
    }
    setError('');
    setUploading(true);

    try {
      await api.uploadFile(selectedFile, uploadCategory);
      setSelectedFile(null);
      setShowUpload(false);
      loadFiles();
    } catch (err) {
      setError(err.message || 'File upload failed');
    } finally {
      setUploading(false);
    }
  };

  const handleDownload = async (file, cipher) => {
    try {
      setDownloadNotice({ status: 'downloading', message: `Decrypting & downloading with ${cipher.toUpperCase()}...` });
      const { decTimeNs } = await api.downloadFile(file.id, cipher, file.file_name);

      const timeFormatted = formatNs(Number(decTimeNs));
      setDownloadNotice({
        status: 'success',
        message: `Successfully decrypted "${file.file_name}" using ${cipher.toUpperCase()} in ${timeFormatted}! Integrity verified.`
      });

      setTimeout(() => setDownloadNotice(null), 5000);
    } catch (err) {
      setDownloadNotice({
        status: 'error',
        message: `Download failed: ${err.message}`
      });
      setTimeout(() => setDownloadNotice(null), 5000);
    }
  };

  const handleDelete = async (id) => {
    if (!window.confirm('Delete this file and all its encrypted variants?')) return;
    try {
      await api.deleteFile(id);
      loadFiles();
    } catch (err) {
      setError(err.message || 'Failed to delete file');
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

  const getCategoryIcon = (cat) => {
    switch (cat) {
      case 'id_card':
        return <Image size={14} color="var(--rc4-color)" />;
      case 'video':
        return <Video size={14} color="#be123c" />;
      default:
        return <FileText size={14} color="var(--des-color)" />;
    }
  };

  const getCategoryLabel = (cat) => {
    switch (cat) {
      case 'id_card':
        return 'ID Card Image';
      case 'video':
        return 'Video File';
      default:
        return 'Document (PDF/DOC/XLS)';
    }
  };

  return (
    <div>
      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start', marginBottom: '1.5rem', flexWrap: 'wrap', gap: '1rem' }}>
        <div>
          <h2 style={{ fontSize: '1.15rem', fontWeight: 600, color: 'var(--text-main)', display: 'flex', alignItems: 'center', gap: '0.45rem', letterSpacing: '-0.01em' }}>
            <Layers color="var(--primary)" size={18} />
            <span>Encrypted Files & Multimedia Repository</span>
          </h2>
          <p style={{ fontSize: '0.8rem', color: 'var(--text-muted)', marginTop: '0.15rem' }}>
            ID cards, office documents, and videos protected under simultaneous AES-256-CBC, RC4-128, and DES-CBC encryption.
          </p>
        </div>

        <button
          className={showUpload ? 'btn btn-secondary' : 'btn btn-primary'}
          onClick={() => setShowUpload(!showUpload)}
        >
          {showUpload ? <X size={14} /> : <Upload size={14} />}
          <span>{showUpload ? 'Cancel' : 'Upload New File'}</span>
        </button>
      </div>

      {downloadNotice && (
        <div className={`alert-banner ${downloadNotice.status === 'error' ? 'alert-banner-error' : downloadNotice.status === 'downloading' ? 'alert-banner-info' : 'alert-banner-success'}`}>
          {downloadNotice.status === 'downloading' ? (
            <Clock size={15} />
          ) : (
            <CheckCircle2 size={15} />
          )}
          <span>{downloadNotice.message}</span>
        </div>
      )}

      {error && (
        <div className="alert-banner alert-banner-error">
          <span>{error}</span>
        </div>
      )}

      {/* Upload Form */}
      {showUpload && (
        <div className="card" style={{ marginBottom: '1.75rem' }}>
          <div className="card-header">
            <h3 className="card-title">Upload & Encrypt File (AES-256-CBC, RC4-128, DES-CBC)</h3>
          </div>
          <form onSubmit={handleUpload}>
            <div className="grid-2">
              <div className="form-group">
                <label className="form-label">Classification Category</label>
                <select
                  className="form-select"
                  value={uploadCategory}
                  onChange={(e) => setUploadCategory(e.target.value)}
                >
                  <option value="id_card">User ID Card Image (KTP / Driver License)</option>
                  <option value="document">Office Document (PDF / DOC / DOCX / XLS / XLSX)</option>
                  <option value="video">Multimedia Video File (MP4 / MKV / WebM)</option>
                </select>
              </div>

              <div className="form-group">
                <label className="form-label">Select File</label>
                <input
                  type="file"
                  className="form-input"
                  onChange={(e) => setSelectedFile(e.target.files[0])}
                  required
                />
              </div>
            </div>

            <div style={{ display: 'flex', justifyContent: 'flex-end', gap: '0.55rem', marginTop: '1rem' }}>
              <button type="button" className="btn btn-secondary" onClick={() => setShowUpload(false)}>Cancel</button>
              <button type="submit" className="btn btn-primary" disabled={uploading}>
                {uploading ? 'Encrypting & Storing...' : 'Encrypt & Upload'}
              </button>
            </div>
          </form>
        </div>
      )}

      {/* Filter Switcher */}
      <div style={{ display: 'inline-flex', gap: '0.25rem', marginBottom: '1.25rem', overflowX: 'auto', backgroundColor: 'var(--bg-well)', padding: '3px', borderRadius: '6px', border: '1px solid var(--border-subtle)' }}>
        <button
          className={`tab-btn ${categoryFilter === '' ? 'active' : ''}`}
          onClick={() => setCategoryFilter('')}
        >
          All Files ({files.length})
        </button>
        <button
          className={`tab-btn ${categoryFilter === 'id_card' ? 'active' : ''}`}
          onClick={() => setCategoryFilter('id_card')}
        >
          <Image size={13} /> ID Cards
        </button>
        <button
          className={`tab-btn ${categoryFilter === 'document' ? 'active' : ''}`}
          onClick={() => setCategoryFilter('document')}
        >
          <FileText size={13} /> Documents
        </button>
        <button
          className={`tab-btn ${categoryFilter === 'video' ? 'active' : ''}`}
          onClick={() => setCategoryFilter('video')}
        >
          <Video size={13} /> Videos
        </button>
      </div>

      {/* Files List Table */}
      <div className="card">
        <div className="card-header">
          <h3 className="card-title">Encrypted Storage Repository ({files.length})</h3>
        </div>

        {loading ? (
          <p style={{ color: 'var(--text-muted)', textAlign: 'center', padding: '2.5rem', fontFamily: 'var(--font-mono)', fontSize: '0.825rem' }}>
            Loading encrypted files...
          </p>
        ) : files.length === 0 ? (
          <div style={{ textAlign: 'center', padding: '3.5rem 1rem', color: 'var(--text-muted)' }}>
            <FileCheck size={36} color="var(--text-dim)" style={{ margin: '0 auto 0.75rem', display: 'block' }} />
            <p style={{ fontWeight: 600, color: 'var(--text-secondary)', fontSize: '0.875rem' }}>No encrypted files found in this category.</p>
            <p style={{ fontSize: '0.8rem', color: 'var(--text-dim)', marginTop: '0.2rem' }}>
              Upload your ID card image, PDF/DOC/XLS document, or video to encrypt and store it.
            </p>
          </div>
        ) : (
          <div className="table-wrapper">
            <table className="data-table">
              <thead>
                <tr>
                  <th>File / Category</th>
                  <th>Original Size</th>
                  <th>AES-256-CBC</th>
                  <th>RC4-128</th>
                  <th>DES-CBC</th>
                  <th>Decrypt & Download</th>
                  <th>Benchmark</th>
                  <th style={{ textAlign: 'right' }}>Actions</th>
                </tr>
              </thead>
              <tbody>
                {files.map((f) => (
                  <tr key={f.id}>
                    <td>
                      <div style={{ display: 'flex', alignItems: 'center', gap: '0.55rem' }}>
                        {getCategoryIcon(f.category)}
                        <div>
                          <strong style={{ color: 'var(--text-main)', display: 'block' }}>{f.file_name}</strong>
                          <span style={{ fontSize: '0.72rem', color: 'var(--text-muted)' }}>
                            {getCategoryLabel(f.category)} • {f.mime_type}
                          </span>
                        </div>
                      </div>
                    </td>
                    <td className="tabular-nums">
                      <strong>{formatBytes(f.original_size)}</strong>
                    </td>
                    <td>
                      <span className="badge badge-aes tabular-nums">{formatBytes(f.aes_cipher_size)}</span>
                      <span className="tabular-nums" style={{ fontSize: '0.72rem', color: 'var(--text-muted)', display: 'block', marginTop: '0.15rem' }}>
                        {formatNs(f.aes_duration_ns)}
                      </span>
                    </td>
                    <td>
                      <span className="badge badge-rc4 tabular-nums">{formatBytes(f.rc4_cipher_size)}</span>
                      <span className="tabular-nums" style={{ fontSize: '0.72rem', color: 'var(--text-muted)', display: 'block', marginTop: '0.15rem' }}>
                        {formatNs(f.rc4_duration_ns)}
                      </span>
                    </td>
                    <td>
                      <span className="badge badge-des tabular-nums">{formatBytes(f.des_cipher_size)}</span>
                      <span className="tabular-nums" style={{ fontSize: '0.72rem', color: 'var(--text-muted)', display: 'block', marginTop: '0.15rem' }}>
                        {formatNs(f.des_duration_ns)}
                      </span>
                    </td>
                    <td>
                      {/* Decrypt & Download buttons for each algorithm */}
                      <div style={{ display: 'flex', gap: '0.25rem' }}>
                        <button
                          className="btn btn-secondary btn-sm"
                          onClick={() => handleDownload(f, 'aes')}
                          title="Decrypt & Download via AES-256-CBC"
                        >
                          <Download size={11} color="var(--aes-color)" />
                          <span>AES</span>
                        </button>
                        <button
                          className="btn btn-secondary btn-sm"
                          onClick={() => handleDownload(f, 'rc4')}
                          title="Decrypt & Download via RC4-128"
                        >
                          <Download size={11} color="var(--rc4-color)" />
                          <span>RC4</span>
                        </button>
                        <button
                          className="btn btn-secondary btn-sm"
                          onClick={() => handleDownload(f, 'des')}
                          title="Decrypt & Download via DES-CBC"
                        >
                          <Download size={11} color="var(--des-color)" />
                          <span>DES</span>
                        </button>
                      </div>
                    </td>
                    <td>
                      <button
                        className="btn btn-secondary btn-sm"
                        onClick={() => setSelectedFileForBench(f)}
                        title="Run multi-download benchmark"
                      >
                        <Activity size={12} color="var(--rc4-color)" />
                        <span>Run Test</span>
                      </button>
                    </td>
                    <td style={{ textAlign: 'right' }}>
                      <button
                        className="btn btn-danger btn-sm"
                        onClick={() => handleDelete(f.id)}
                        title="Delete File"
                      >
                        <Trash2 size={12} />
                      </button>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </div>

      {selectedFileForBench && (
        <BenchmarkModal
          file={selectedFileForBench}
          onClose={() => setSelectedFileForBench(null)}
        />
      )}
    </div>
  );
}
