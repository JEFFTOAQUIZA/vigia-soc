import 'dotenv/config';
import crypto from 'node:crypto';
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import express from 'express';
import { AiError, aiStatus, draftNarrative } from './ai.js';

const PORT = Number(process.env.PORT) || 3001;
const APP_USER = process.env.APP_USER;
const APP_PASSWORD = process.env.APP_PASSWORD;
const SECRET = process.env.SESSION_SECRET || crypto.randomBytes(32).toString('hex');
const SESSION_TTL_MS = 8 * 60 * 60 * 1000;
const MAX_ATTEMPTS = 5;
const LOCKOUT_MS = 5 * 60 * 1000;

if (!APP_USER || !APP_PASSWORD) {
  console.error('Faltan APP_USER / APP_PASSWORD en el archivo .env (ver .env.example).');
  process.exit(1);
}

// ── Sesión: token firmado con HMAC (payload.firma) ──────────────────────────
const sign = (data) => crypto.createHmac('sha256', SECRET).update(data).digest('base64url');

// Comparación en tiempo constante (hash previo para igualar longitudes)
function safeEqual(a, b) {
  const ha = crypto.createHash('sha256').update(String(a)).digest();
  const hb = crypto.createHash('sha256').update(String(b)).digest();
  return crypto.timingSafeEqual(ha, hb);
}

function issueToken(user) {
  const payload = Buffer.from(JSON.stringify({ u: user, exp: Date.now() + SESSION_TTL_MS })).toString('base64url');
  return `${payload}.${sign(payload)}`;
}

function verifyToken(token) {
  const [payload, signature] = String(token || '').split('.');
  if (!payload || !signature || !safeEqual(signature, sign(payload))) return null;
  try {
    const data = JSON.parse(Buffer.from(payload, 'base64url').toString());
    return data.exp > Date.now() ? data : null;
  } catch {
    return null;
  }
}

function requireAuth(req, res, next) {
  const token = (req.headers.authorization || '').replace(/^Bearer\s+/i, '');
  const session = verifyToken(token);
  if (!session) return res.status(401).json({ error: 'Sesión inválida o expirada.' });
  req.session = session;
  next();
}

// ── API ─────────────────────────────────────────────────────────────────────
const app = express();
app.disable('x-powered-by');
app.use(express.json({ limit: '1mb' }));

const attempts = new Map(); // ip -> { count, lockedUntil }

app.post('/api/login', (req, res) => {
  const ip = req.ip;
  const entry = attempts.get(ip) || { count: 0, lockedUntil: 0 };

  if (entry.lockedUntil > Date.now()) {
    const minutes = Math.ceil((entry.lockedUntil - Date.now()) / 60000);
    return res.status(429).json({ error: `Acceso bloqueado por intentos fallidos. Intente de nuevo en ${minutes} min.` });
  }

  const { username, password } = req.body || {};
  if (typeof username !== 'string' || typeof password !== 'string' || !username || !password) {
    return res.status(400).json({ error: 'Ingrese usuario y contraseña.' });
  }

  const userOk = safeEqual(username, APP_USER);
  const passOk = safeEqual(password, APP_PASSWORD);
  if (!(userOk && passOk)) {
    entry.count += 1;
    const remaining = MAX_ATTEMPTS - entry.count;
    if (remaining <= 0) {
      entry.count = 0;
      entry.lockedUntil = Date.now() + LOCKOUT_MS;
      attempts.set(ip, entry);
      console.warn(`[auth] ${new Date().toISOString()} bloqueo de ${ip} tras ${MAX_ATTEMPTS} intentos fallidos`);
      return res.status(429).json({ error: `Demasiados intentos fallidos. Acceso bloqueado ${LOCKOUT_MS / 60000} min.` });
    }
    attempts.set(ip, entry);
    console.warn(`[auth] ${new Date().toISOString()} login fallido desde ${ip} (usuario="${username.slice(0, 40)}")`);
    return res.status(401).json({ error: `Usuario o contraseña incorrectos. Intentos restantes: ${remaining}.` });
  }

  attempts.delete(ip);
  console.log(`[auth] ${new Date().toISOString()} login correcto de ${APP_USER} desde ${ip}`);
  res.json({ token: issueToken(APP_USER), user: APP_USER, expiresIn: SESSION_TTL_MS });
});

app.get('/api/me', requireAuth, (req, res) => {
  res.json({ user: req.session.u, exp: req.session.exp });
});

app.get('/api/ai/status', requireAuth, (req, res) => res.json(aiStatus()));

app.post('/api/ai/narrative', requireAuth, async (req, res) => {
  const { audience, context } = req.body || {};
  if (!['ejecutivo', 'tecnico'].includes(audience) || !context || !Array.isArray(context.incidentes)) {
    return res.status(400).json({ error: 'Solicitud inválida: se requiere audiencia y contexto del análisis.' });
  }
  try {
    const result = await draftNarrative({ audience, context });
    console.log(`[ai] ${new Date().toISOString()} narrativa ${audience} generada (${result.usage.input}+${result.usage.output} tokens)`);
    res.json(result);
  } catch (err) {
    if (err instanceof AiError) return res.status(err.status).json({ error: err.message });
    console.error('[ai] error inesperado:', err);
    res.status(500).json({ error: 'Error inesperado al generar la redacción con IA.' });
  }
});

// ── Frontend compilado (modo producción: npm run build && npm start) ────────
const dist = path.join(path.dirname(fileURLToPath(import.meta.url)), '..', 'dist');
if (fs.existsSync(dist)) {
  app.use(express.static(dist));
  app.get(/^(?!\/api).*/, (req, res) => res.sendFile(path.join(dist, 'index.html')));
}

app.listen(PORT, () => console.log(`VIGÍA API escuchando en http://localhost:${PORT}`));
