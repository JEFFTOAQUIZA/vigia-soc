// Verificación del lector de Excel fuera del navegador: node scripts/check-parse.mjs <archivo.xlsx>
import fs from 'node:fs';
import path from 'node:path';
import { parseWorkbook } from '../src/lib/parse.js';

const filePath = process.argv[2];
if (!filePath) {
  console.error('Uso: node scripts/check-parse.mjs <archivo.xlsx>');
  process.exit(1);
}
const buf = fs.readFileSync(filePath);
const file = {
  name: path.basename(filePath),
  size: buf.length,
  arrayBuffer: async () => buf.buffer.slice(buf.byteOffset, buf.byteOffset + buf.length),
};

const ds = await parseWorkbook(file);
console.log(JSON.stringify({ summary: { ...ds.summary, eventIds: undefined }, quality: ds.quality }, null, 2));
console.log('Primer evento:', ds.events[0]);
