const SESSION_KEY = 'vigia.session';

export const session = {
  get() {
    try {
      const s = JSON.parse(sessionStorage.getItem(SESSION_KEY));
      return s && s.exp > Date.now() ? s : null;
    } catch {
      return null;
    }
  },
  set(s) {
    sessionStorage.setItem(SESSION_KEY, JSON.stringify(s));
  },
  clear() {
    sessionStorage.removeItem(SESSION_KEY);
  },
};

async function readJson(res) {
  return res.json().catch(() => ({}));
}

export async function login(username, password) {
  let res;
  try {
    res = await fetch('/api/login', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ username, password }),
    });
  } catch {
    throw new Error('No se pudo conectar con el servidor de VIGÍA.');
  }
  const data = await readJson(res);
  if (!res.ok) throw new Error(data.error || 'Error de autenticación.');
  return data;
}

export async function apiFetch(path, options = {}) {
  const s = session.get();
  const res = await fetch(path, {
    ...options,
    headers: {
      'Content-Type': 'application/json',
      ...(options.headers || {}),
      ...(s ? { Authorization: `Bearer ${s.token}` } : {}),
    },
  });
  const data = await readJson(res);
  if (res.status === 401) {
    session.clear();
    throw Object.assign(new Error(data.error || 'Sesión expirada.'), { status: 401 });
  }
  if (!res.ok) throw new Error(data.error || `Error ${res.status}`);
  return data;
}
