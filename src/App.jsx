import { useCallback, useEffect, useState } from 'react';
import { apiFetch, session } from './api.js';
import Login from './components/Login.jsx';
import Shell from './components/Shell.jsx';

export default function App() {
  const [sess, setSess] = useState(() => session.get());

  const logout = useCallback(() => {
    session.clear();
    setSess(null);
  }, []);

  // Valida contra el backend la sesión recuperada de sessionStorage
  useEffect(() => {
    if (sess) apiFetch('/api/me').catch(logout);
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  // Cierre automático al expirar la sesión
  useEffect(() => {
    if (!sess) return;
    const timer = setTimeout(logout, Math.max(0, sess.exp - Date.now()));
    return () => clearTimeout(timer);
  }, [sess, logout]);

  function handleLogin(data) {
    const s = { token: data.token, user: data.user, exp: Date.now() + data.expiresIn };
    session.set(s);
    setSess(s);
  }

  // Sin animación de salida: el cambio login ↔ aplicación no debe depender de que termine
  return sess ? <Shell key="app" user={sess.user} onLogout={logout} /> : <Login key="login" onSuccess={handleLogin} />;
}
