// Prueba la redacción con IA contra el servidor en marcha: node scripts/check-ai.mjs <archivo.xlsx> [ejecutivo|tecnico]
import 'dotenv/config';
import fs from 'node:fs';
import path from 'node:path';
import { parseWorkbook } from '../src/lib/parse.js';
import { runAnalysis } from '../src/lib/engine.js';
import { buildAiContext, unknownLogIds } from '../src/lib/report.js';

const [filePath, audience = 'tecnico'] = process.argv.slice(2);
const base = `http://localhost:${process.env.PORT || 3001}`;
const buf = fs.readFileSync(filePath);
const dataset = await parseWorkbook({
  name: path.basename(filePath),
  size: buf.length,
  arrayBuffer: async () => buf.buffer.slice(buf.byteOffset, buf.byteOffset + buf.length),
});
const analysis = runAnalysis(dataset);

const login = await fetch(`${base}/api/login`, {
  method: 'POST',
  headers: { 'Content-Type': 'application/json' },
  body: JSON.stringify({ username: process.env.APP_USER, password: process.env.APP_PASSWORD }),
}).then((r) => r.json());
const headers = { 'Content-Type': 'application/json', Authorization: `Bearer ${login.token}` };

console.log('Estado IA:', await fetch(`${base}/api/ai/status`, { headers }).then((r) => r.json()));
const started = Date.now();
const res = await fetch(`${base}/api/ai/narrative`, {
  method: 'POST',
  headers,
  body: JSON.stringify({ audience, context: buildAiContext(dataset, analysis) }),
});
const data = await res.json();
console.log(`HTTP ${res.status} en ${((Date.now() - started) / 1000).toFixed(1)} s`);
if (!res.ok) {
  console.log('Error:', data.error);
  process.exit(1);
}

const n = data.narrative;
const expected = analysis.incidents.map((i) => i.id);
console.log('Modelo:', data.model, '| tokens:', data.usage);
console.log('Incidentes en la respuesta:', n.incidentes.map((i) => i.id).join(', '), '| esperados:', expected.join(', '));
console.log('Log_ID citados que no se enviaron (servidor):', data.unknownIds.length ? data.unknownIds : 'ninguno');
console.log('Log_ID citados que no existen en el Excel:', unknownLogIds(n, dataset).length ? unknownLogIds(n, dataset) : 'ninguno');
console.log('Log_ID distintos citados:', new Set(JSON.stringify(n).match(/EVT-\d{5}/g) || []).size);
console.log('Recomendaciones:', n.recomendaciones.length);
console.log('\n--- Resumen ejecutivo ---\n' + n.resumen_ejecutivo);
console.log('\n--- Valoración de riesgo ---\n' + n.valoracion_riesgo);
console.log(`\n--- Narrativa ${n.incidentes[0].id} ---\n` + n.incidentes[0].narrativa);
console.log('\n--- Limitaciones ---\n' + n.limitaciones);
