const API_BASE = '/api';

export function getToken() {
  return localStorage.getItem('token');
}

export function setToken(token) {
  if (token) {
    localStorage.setItem('token', token);
  } else {
    localStorage.removeItem('token');
  }
}

async function request(url, options = {}) {
  const token = getToken();
  const headers = { ...options.headers };

  if (token) {
    headers['Authorization'] = `Bearer ${token}`;
  }

  if (!(options.body instanceof FormData) && !headers['Content-Type']) {
    headers['Content-Type'] = 'application/json';
  }

  const res = await fetch(`${API_BASE}${url}`, {
    ...options,
    headers,
  });

  if (res.status === 401) {
    setToken(null);
    window.dispatchEvent(new Event('auth:unauthorized'));
  }

  if (!res.ok) {
    let errorMsg = `HTTP error ${res.status}`;
    try {
      const data = await res.json();
      if (data.error) errorMsg = data.error;
    } catch {}
    throw new Error(errorMsg);
  }

  if (options.responseType === 'blob') {
    const blob = await res.blob();
    const decTimeNs = res.headers.get('X-Decryption-Time-Ns');
    const cipherUsed = res.headers.get('X-Cipher-Algorithm');
    return { blob, decTimeNs, cipherUsed };
  }

  return res.json();
}

export const api = {
  // Auth
  register: (username, password) =>
    request('/auth/register', {
      method: 'POST',
      body: JSON.stringify({ username, password }),
    }),

  login: (username, password) =>
    request('/auth/login', {
      method: 'POST',
      body: JSON.stringify({ username, password }),
    }),

  getMe: () => request('/auth/me'),

  // Personal Data (GDPR / UU PDP)
  getPersonalData: () => request('/personal-data'),

  storePersonalData: (label, data) =>
    request('/personal-data', {
      method: 'POST',
      body: JSON.stringify({ label, data }),
    }),

  decryptPersonalData: (id, cipher = 'aes') =>
    request(`/personal-data/${id}/decrypt?cipher=${cipher}`),

  deletePersonalData: (id) =>
    request(`/personal-data/${id}`, {
      method: 'DELETE',
    }),

  // Files
  getFiles: (category = '') => {
    const query = category ? `?category=${category}` : '';
    return request(`/files${query}`);
  },

  uploadFile: (file, category) => {
    const formData = new FormData();
    formData.append('file', file);
    formData.append('category', category);
    return request('/files/upload', {
      method: 'POST',
      body: formData,
    });
  },

  downloadFile: async (id, cipher, filename) => {
    const { blob, decTimeNs, cipherUsed } = await request(
      `/files/${id}/download?cipher=${cipher}`,
      { responseType: 'blob' }
    );
    const url = window.URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = filename;
    document.body.appendChild(a);
    a.click();
    window.URL.revokeObjectURL(url);
    document.body.removeChild(a);
    return { decTimeNs, cipherUsed };
  },

  deleteFile: (id) =>
    request(`/files/${id}`, {
      method: 'DELETE',
    }),

  // Benchmark
  runBenchmark: (fileId, iterations = 5) =>
    request('/benchmark/download', {
      method: 'POST',
      body: JSON.stringify({ file_id: fileId, iterations: Number(iterations) }),
    }),
};
