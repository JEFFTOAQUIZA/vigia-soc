import { useState } from 'react';
import { AnimatePresence, motion, useAnimationControls } from 'framer-motion';
import { login } from '../api.js';
import Logo from './Logo.jsx';
import { ThemeToggle } from '../theme.jsx';

const shake = { x: [0, -10, 10, -6, 6, 0], transition: { duration: 0.4 } };

export default function Login({ onSuccess }) {
  const [username, setUsername] = useState('');
  const [password, setPassword] = useState('');
  const [showPassword, setShowPassword] = useState(false);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState('');
  const controls = useAnimationControls();

  async function handleSubmit(e) {
    e.preventDefault();
    if (loading) return;
    setError('');
    if (!username.trim() || !password) {
      setError('Ingrese usuario y contraseña.');
      controls.start(shake);
      return;
    }
    setLoading(true);
    try {
      const data = await login(username.trim(), password);
      onSuccess(data);
    } catch (err) {
      setError(err.message);
      setPassword('');
      controls.start(shake);
      setLoading(false);
    }
  }

  return (
    <motion.div
      className="login-screen"
      initial={{ opacity: 0 }}
      animate={{ opacity: 1 }}
      exit={{ opacity: 0, scale: 0.98, transition: { duration: 0.3 } }}
    >
      <div className="login-bg" aria-hidden="true" />
      <ThemeToggle className="login-theme" />

      <motion.div
        className="login-card"
        initial={{ y: 24, opacity: 0 }}
        animate={{ y: 0, opacity: 1 }}
        transition={{ duration: 0.6, ease: [0.2, 0.8, 0.2, 1] }}
      >
        <motion.div animate={controls}>
          <div className="login-brand">
            <motion.div
              initial={{ scale: 0.6, opacity: 0 }}
              animate={{ scale: 1, opacity: 1 }}
              transition={{ delay: 0.2, type: 'spring', stiffness: 180, damping: 14 }}
            >
              <Logo size={60} />
            </motion.div>
            <h1>VIGÍA</h1>
            <p>Plataforma de Análisis de Incidentes · SOC Nivel 2</p>
          </div>

          <form onSubmit={handleSubmit} noValidate>
            <label className="field">
              <span>Usuario</span>
              <input
                autoFocus
                autoComplete="username"
                value={username}
                onChange={(e) => setUsername(e.target.value)}
                placeholder="Usuario"
                disabled={loading}
              />
            </label>

            <label className="field">
              <span>Contraseña</span>
              <div className="password-wrap">
                <input
                  type={showPassword ? 'text' : 'password'}
                  autoComplete="current-password"
                  value={password}
                  onChange={(e) => setPassword(e.target.value)}
                  placeholder="Contraseña"
                  disabled={loading}
                />
                <button
                  type="button"
                  className="link-btn"
                  onClick={() => setShowPassword((v) => !v)}
                  aria-label={showPassword ? 'Ocultar contraseña' : 'Mostrar contraseña'}
                >
                  {showPassword ? 'Ocultar' : 'Mostrar'}
                </button>
              </div>
            </label>

            <AnimatePresence>
              {error && (
                <motion.div
                  className="login-error"
                  role="alert"
                  initial={{ opacity: 0, height: 0 }}
                  animate={{ opacity: 1, height: 'auto' }}
                  exit={{ opacity: 0, height: 0 }}
                >
                  {error}
                </motion.div>
              )}
            </AnimatePresence>

            <button type="submit" className="btn btn-primary btn-block" disabled={loading}>
              {loading ? <span className="spinner" aria-label="Verificando" /> : 'Ingresar'}
            </button>
          </form>

          <footer className="login-footer">
            Acceso restringido · Información CONFIDENCIAL
            <br />
            Toda actividad en esta plataforma es registrada.
          </footer>
        </motion.div>
      </motion.div>
    </motion.div>
  );
}
