// Ejecuta el motor de análisis fuera del navegador: node scripts/check-analysis.mjs <archivo.xlsx>
import fs from 'node:fs';
import path from 'node:path';
import { parseWorkbook } from '../src/lib/parse.js';
import { runAnalysis } from '../src/lib/engine.js';

const filePath = process.argv[2];
const buf = fs.readFileSync(filePath);
const ds = await parseWorkbook({
  name: path.basename(filePath),
  size: buf.length,
  arrayBuffer: async () => buf.buffer.slice(buf.byteOffset, buf.byteOffset + buf.length),
});
const a = runAnalysis(ds);

for (const inc of a.incidents) {
  console.log(`\n${inc.id} [${inc.level}] ${inc.title}  ${inc.start.slice(11)}–${inc.end.slice(11)}  (${inc.evidence.length} ev)`);
  console.log(`   ${inc.rationale}`);
  for (const f of inc.findings) {
    console.log(`  ${f.id} [${f.level}${f.escalated ? '↑' : ''}] ${f.category} | ${f.title}`);
    console.log(`     MITRE ${f.mitre.join(', ')} | ${f.evidence.length} ev: ${f.evidence.map((e) => e.Log_ID.slice(4)).join(' ')}`);
  }
}
console.log('\nDescartados:');
for (const f of a.discarded) console.log(`  ${f.id} ${f.title}`);
console.log('\nStats:', JSON.stringify({ ...a.stats, affectedHosts: a.stats.affectedHosts.length, affectedUsers: a.stats.affectedUsers.length }));
console.log('Categorías:', a.categoryStats.map((c) => `${c.category}=${c.findings.length}`).join(', '));
