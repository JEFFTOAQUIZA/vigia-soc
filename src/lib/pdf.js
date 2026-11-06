// Generación de los informes PDF (ejecutivo y técnico)
import { jsPDF } from 'jspdf';
import { autoTable } from 'jspdf-autotable';
import * as echarts from 'echarts';
import { LEVELS } from './engine.js';
import { MITRE } from './mitre.js';
import { LEVEL_COLORS, levelDonut, eventsOverTime, palette } from './charts.js';
import {
  PHASE_LABEL,
  actionPlan,
  consolidatedTimeline,
  evidenceExtract,
  extractIocs,
  mitreMapping,
  plainSummary,
  urgentActions,
  RULE_TABLE,
} from './report.js';

const PAGE_W = 210;
const PAGE_H = 297;
const M = 18;
const CONTENT_W = PAGE_W - 2 * M;
const ACCENT = [2, 132, 199];
const DARK = [15, 23, 42];
const MUTED = [91, 107, 133];

// Las fuentes estándar de PDF solo cubren Latin-1: se sustituyen los símbolos que no admiten
const SUBS = { '→': '->', '←': '<-', '↔': '<->', '↛': '-/->', '≥': '>=', '≤': '<=', '–': '-', '—': '-', '…': '...', '“': '"', '”': '"', '‘': "'", '’': "'", '•': '-', '↑': '^', '✓': 'OK' };
const clean = (s) =>
  String(s ?? '')
    .replace(/[→←↔↛≥≤–—…“”‘’•↑✓]/g, (ch) => SUBS[ch])
    .replace(/[^\u0000-ÿ\n]/g, '');

const hex = (h) => [1, 3, 5].map((i) => parseInt(h.slice(i, i + 2), 16));
const hhmm = (ts) => ts.slice(11, 19);

function chartImage(option, width = 900, height = 420) {
  const div = document.createElement('div');
  div.style.cssText = `position:fixed;left:-10000px;top:0;width:${width}px;height:${height}px;`;
  document.body.appendChild(div);
  const chart = echarts.init(div, null, { renderer: 'canvas' });
  chart.setOption({ ...option, animation: false });
  const url = chart.getDataURL({ type: 'png', pixelRatio: 2, backgroundColor: '#ffffff' });
  chart.dispose();
  div.remove();
  return url;
}

class PdfBuilder {
  constructor(meta, kind) {
    this.doc = new jsPDF({ unit: 'mm', format: 'a4', compress: true });
    this.meta = meta;
    this.kind = kind;
    this.y = M;
    this.toc = [];
  }

  newPage() {
    this.doc.addPage();
    this.y = M + 6;
  }

  ensure(h) {
    if (this.y + h > PAGE_H - 20) this.newPage();
  }

  h1(text, { toc = true, newPage = true } = {}) {
    if (newPage) this.newPage();
    else this.ensure(20);
    if (toc) this.toc.push({ text, page: this.doc.getNumberOfPages() });
    this.doc.setFont('helvetica', 'bold').setFontSize(16).setTextColor(...ACCENT);
    this.doc.text(clean(text), M, this.y);
    this.y += 3;
    this.doc.setDrawColor(...ACCENT).setLineWidth(0.6).line(M, this.y, M + 40, this.y);
    this.y += 8;
  }

  h2(text) {
    this.ensure(14);
    this.doc.setFont('helvetica', 'bold').setFontSize(12).setTextColor(...DARK);
    const lines = this.doc.splitTextToSize(clean(text), CONTENT_W);
    this.doc.text(lines, M, this.y);
    this.y += lines.length * 5.5 + 2;
  }

  p(text, { size = 10, color = DARK, bold = false, gap = 3 } = {}) {
    this.doc.setFont('helvetica', bold ? 'bold' : 'normal').setFontSize(size).setTextColor(...color);
    for (const para of clean(text).split('\n')) {
      const lines = this.doc.splitTextToSize(para || ' ', CONTENT_W);
      for (const line of lines) {
        this.ensure(size * 0.5);
        this.doc.text(line, M, this.y);
        this.y += size * 0.45;
      }
    }
    this.y += gap;
  }

  kv(pairs) {
    for (const [k, v] of pairs) {
      this.ensure(6);
      this.doc.setFont('helvetica', 'bold').setFontSize(9).setTextColor(...MUTED);
      this.doc.text(clean(k), M, this.y);
      this.doc.setFont('helvetica', 'normal').setTextColor(...DARK);
      const lines = this.doc.splitTextToSize(clean(v), CONTENT_W - 38);
      this.doc.text(lines, M + 38, this.y);
      this.y += Math.max(1, lines.length) * 4.3 + 1;
    }
    this.y += 2;
  }

  levelBox(level, text) {
    this.ensure(18);
    this.doc.setFillColor(...hex(LEVEL_COLORS[level])).roundedRect(M, this.y, 42, 12, 2, 2, 'F');
    this.doc.setFont('helvetica', 'bold').setFontSize(12).setTextColor(255, 255, 255);
    this.doc.text(clean(level.toUpperCase()), M + 21, this.y + 7.8, { align: 'center' });
    this.doc.setFont('helvetica', 'normal').setFontSize(9.5).setTextColor(...DARK);
    const lines = this.doc.splitTextToSize(clean(text), CONTENT_W - 48);
    this.doc.text(lines, M + 47, this.y + 4);
    this.y += Math.max(14, lines.length * 4.3 + 4);
  }

  table(head, body, { levelCol = -1, colWidths, fontSize = 8 } = {}) {
    autoTable(this.doc, {
      startY: this.y,
      head: [head.map(clean)],
      body: body.map((r) => r.map(clean)),
      margin: { left: M, right: M, top: M + 6, bottom: 20 },
      styles: { font: 'helvetica', fontSize, cellPadding: 1.6, overflow: 'linebreak', textColor: DARK, lineColor: [226, 232, 240], lineWidth: 0.1 },
      headStyles: { fillColor: DARK, textColor: 255, fontStyle: 'bold' },
      alternateRowStyles: { fillColor: [246, 248, 251] },
      columnStyles: colWidths ? Object.fromEntries(colWidths.map((w, i) => [i, { cellWidth: w }])) : {},
      didParseCell: (data) => {
        if (data.section === 'body' && data.column.index === levelCol) {
          const lvl = LEVELS.find((l) => clean(l) === data.cell.raw);
          if (lvl) {
            data.cell.styles.textColor = hex(LEVEL_COLORS[lvl]);
            data.cell.styles.fontStyle = 'bold';
          }
        }
      },
    });
    this.y = this.doc.lastAutoTable.finalY + 6;
  }

  image(dataUrl, w, h) {
    this.ensure(h + 4);
    this.doc.addImage(dataUrl, 'PNG', M + (CONTENT_W - w) / 2, this.y, w, h);
    this.y += h + 5;
  }

  cover(title, subtitle, globalLevel) {
    const d = this.doc;
    d.setFillColor(...DARK).rect(0, 0, PAGE_W, 110, 'F');
    d.setFillColor(...ACCENT).rect(0, 110, PAGE_W, 2.5, 'F');
    d.setFont('helvetica', 'bold').setFontSize(30).setTextColor(255, 255, 255).text('VIGIA', M, 40);
    d.setFont('helvetica', 'normal').setFontSize(10).setTextColor(148, 163, 184).text(clean('Plataforma de Análisis de Incidentes · SOC Nivel 2'), M, 48);
    d.setFont('helvetica', 'bold').setFontSize(22).setTextColor(255, 255, 255);
    d.text(d.splitTextToSize(clean(title), CONTENT_W), M, 78);
    d.setFont('helvetica', 'normal').setFontSize(11).setTextColor(203, 213, 225).text(clean(subtitle), M, 98);

    this.y = 130;
    this.kv([
      ['Cliente', this.meta.cliente],
      ['Elaborado por', this.meta.consultora],
      ['Analista', [this.meta.nombre, this.meta.apellido].filter(Boolean).join(' ') || this.meta.analista],
      ['Fecha', this.meta.fecha],
      ['Clasificación', this.meta.clasificacion],
    ]);
    this.y += 4;
    this.p('Nivel de riesgo global', { bold: true, size: 11 });
    this.levelBox(globalLevel, 'Determinado a partir de la matriz de criticidad del análisis (sección de criticidad y justificación).');
    d.setFillColor(254, 226, 226).rect(M, PAGE_H - 40, CONTENT_W, 14, 'F');
    d.setFont('helvetica', 'bold').setFontSize(9).setTextColor(153, 27, 27);
    d.text(clean(`DOCUMENTO ${this.meta.clasificacion}: uso exclusivo del cliente y del equipo de respuesta.`), PAGE_W / 2, PAGE_H - 31.5, { align: 'center' });
  }

  finish(fileName) {
    const total = this.doc.getNumberOfPages();
    const label = this.kind === 'ejecutivo' ? 'Informe ejecutivo' : 'Informe técnico';
    for (let i = 2; i <= total; i++) {
      this.doc.setPage(i);
      this.doc.setFont('helvetica', 'normal').setFontSize(7.5).setTextColor(...MUTED);
      this.doc.text(clean(`VIGIA · ${label} · ${this.meta.cliente}`), M, 10);
      this.doc.text(clean(this.meta.clasificacion), PAGE_W - M, 10, { align: 'right' });
      this.doc.setDrawColor(226, 232, 240).setLineWidth(0.2).line(M, 12, PAGE_W - M, 12);
      this.doc.text(clean(`Página ${i} de ${total}`), PAGE_W - M, PAGE_H - 10, { align: 'right' });
      this.doc.text(clean(`Generado por VIGIA el ${this.meta.fecha}`), M, PAGE_H - 10);
    }
    this.doc.save(fileName);
  }

  writeToc(page) {
    this.doc.setPage(page);
    let y = M + 6;
    this.doc.setFont('helvetica', 'bold').setFontSize(16).setTextColor(...ACCENT).text('Índice', M, y);
    y += 12;
    this.doc.setFontSize(10);
    for (const item of this.toc) {
      this.doc.setFont('helvetica', 'normal').setTextColor(...DARK).text(clean(item.text), M, y);
      this.doc.setTextColor(...MUTED).text(String(item.page), PAGE_W - M, y, { align: 'right' });
      const w = this.doc.getTextWidth(clean(item.text));
      this.doc.setDrawColor(203, 213, 225).setLineDashPattern([0.5, 1], 0).line(M + w + 2, y, PAGE_W - M - 8, y).setLineDashPattern([], 0);
      y += 7;
    }
  }
}

const incidentRows = (analysis, narrative) =>
  analysis.incidents.map((i) => [i.id, i.type === 'anomaly' ? `${i.title} (hipótesis)` : i.title, i.level, `${hhmm(i.start)}–${hhmm(i.end)}`, String(i.findings.length)]);

function aiNote(narrative) {
  return narrative.source === 'ia'
    ? `La redacción de los apartados narrativos fue asistida por IA (${narrative.model}) a partir de los hallazgos estructurados y revisada por el analista. Las detecciones y la criticidad provienen de reglas deterministas sobre los registros.`
    : 'Los apartados narrativos se generaron con plantillas deterministas a partir de los hallazgos; no se utilizó IA para este documento. Las detecciones y la criticidad provienen de reglas deterministas sobre los registros.';
}

export function exportExecutivePdf({ dataset, analysis, narrative, meta, fileName }) {
  const b = new PdfBuilder(meta, 'ejecutivo');
  const c = palette('light');
  b.cover('Informe ejecutivo de incidentes de seguridad', `Análisis de registros del SIEM · ${dataset.summary.first.slice(0, 10)}`, analysis.globalLevel);

  b.h1('Resumen ejecutivo', { toc: false });
  b.p(narrative.resumen_ejecutivo);
  b.h2('Nivel de riesgo global');
  b.levelBox(analysis.globalLevel, narrative.valoracion_riesgo);

  b.h2('Incidentes identificados');
  b.table(
    ['ID', 'Qué ocurrió', 'Criticidad', 'Hora'],
    analysis.incidents.map((i) => [i.id, plainSummary(i), i.level, `${hhmm(i.start)}–${hhmm(i.end)}`]),
    { levelCol: 2, colWidths: [18, 104, 20, 32] }
  );
  b.image(chartImage(levelDonut(analysis, c), 700, 380), 110, 60);

  b.h1('Impacto en el negocio', { toc: false });
  b.table(
    ['Incidente', 'Confidencialidad', 'Integridad', 'Disponibilidad', 'Operación', 'Reputación'],
    analysis.incidents.map((i) => [i.id, i.impact.confidencialidad, i.impact.integridad, i.impact.disponibilidad, i.impact.operacion, i.impact.reputacion])
  );
  for (const inc of analysis.incidents) {
    b.p(`${inc.id}: ${narrative.incidentes[inc.id]?.impacto || ''}`, { size: 9 });
  }

  b.h2('Acciones urgentes (próximas horas)');
  b.table(
    ['Prioridad', 'Acción', 'Responsable', 'Incidente'],
    urgentActions(analysis).map((r) => [r.p, r.text, r.owner, r.incident]),
    { colWidths: [18, 100, 36, 20] }
  );
  b.h2('Decisiones requeridas de la dirección');
  b.p(
    '- Autorizar el aislamiento de los equipos y servidores afectados aunque interrumpa servicios.\n' +
      '- Activar el plan de respuesta a incidentes y, si procede, el plan de continuidad.\n' +
      '- Involucrar a Legal y Cumplimiento para evaluar la notificación de la fuga de datos.\n' +
      '- Aprobar la implantación prioritaria de MFA, EDR y copias de seguridad inmutables.'
  );
  b.h2('Metodología y uso de IA');
  b.p(`Fuente: ${dataset.fileName} (${dataset.summary.total} eventos, ${dataset.summary.first} – ${dataset.summary.last}). ${aiNote(narrative)}`, { size: 9, color: MUTED });
  b.finish(fileName);
}

export function exportTechnicalPdf({ dataset, analysis, narrative, meta, fileName }) {
  const b = new PdfBuilder(meta, 'tecnico');
  const c = palette('light');
  b.cover('Informe técnico de investigación de incidentes', `Análisis de registros del SIEM · ${dataset.summary.first.slice(0, 10)}`, analysis.globalLevel);
  b.newPage(); // reservada para el índice
  const tocPage = b.doc.getNumberOfPages();

  b.h1('1. Resumen ejecutivo');
  b.p(narrative.resumen_ejecutivo);
  b.levelBox(analysis.globalLevel, narrative.valoracion_riesgo);

  b.h1('2. Alcance y metodología');
  b.kv([
    ['Fuente de datos', `${dataset.fileName}, hoja "${dataset.sheet}"`],
    ['Volumen', `${dataset.summary.total} eventos`],
    ['Ventana temporal', `${dataset.summary.first} – ${dataset.summary.last}`],
    ['Fuentes de log', Object.entries(dataset.summary.sources).map(([k, v]) => `${k} (${v})`).join(', ')],
    ['Herramienta', 'VIGIA – motor de reglas deterministas (R-01 a R-12) y correlación por IP, cuenta, equipo y tiempo'],
    ['Uso de IA', aiNote(narrative)],
  ]);
  b.p('Fases: preparación y validación de datos, línea base, detección por reglas, correlación en incidentes, clasificación según la matriz de criticidad y documentación con referencia a Log_ID. La columna Severity del SIEM se usó solo como referencia.', { size: 9 });
  b.image(chartImage(eventsOverTime(dataset, analysis, c, 15), 1000, 380), CONTENT_W, 62);

  b.h1('3. Hallazgos identificados');
  b.table(
    ['ID', 'Título', 'Categoría', 'Criticidad', 'Equipos', 'Cuentas', 'IPs'],
    analysis.findings.map((f) => [f.id, f.title, f.category, f.level, f.hosts.join(', '), f.users.join(', '), f.ips.join(', ')]),
    { levelCol: 3, colWidths: [12, 52, 22, 17, 24, 25, 22], fontSize: 7 }
  );
  b.h2('Incidentes (agrupación de hallazgos)');
  b.table(['ID', 'Título', 'Criticidad', 'Ventana', 'Hallazgos'], incidentRows(analysis, narrative), { levelCol: 2, colWidths: [18, 96, 20, 25, 15] });

  b.h1('4. Explicación técnica de cada hallazgo');
  for (const inc of analysis.incidents) {
    b.h2(`${inc.id} · ${inc.title}`);
    b.p(narrative.incidentes[inc.id]?.narrativa || '', { size: 9 });
    b.p(`Agrupación: ${inc.rationale}`, { size: 8.5, color: MUTED });
    for (const f of inc.findings) {
      b.p(`${f.id} – ${f.title}`, { bold: true, size: 9.5, gap: 1 });
      b.kv([
        ['Categoría', f.category],
        ['MITRE ATT&CK', f.mitre.map((m) => `${m} ${MITRE[m]?.name ?? ''}`).join('; ')],
        ['Ventana', `${f.start} – ${f.end}`],
        ['Detección', f.detection],
        ['Qué ocurrió', f.description],
      ]);
    }
  }

  b.h1('5. Evidencias encontradas en los logs');
  for (const f of analysis.findings) {
    b.h2(`${f.id} – ${f.title}`);
    b.table(
      ['Log_ID', 'Timestamp', 'Hostname', 'Event_ID', 'User', 'Source_IP', 'Extracto'],
      f.evidence.map((e) => [e.Log_ID, e.Timestamp.slice(11), e.Hostname, e.Event_ID, e.User, e.Source_IP, evidenceExtract(e)]),
      { colWidths: [17, 15, 19, 17, 25, 21, 60], fontSize: 6.8 }
    );
  }

  b.h1('6. Criticidad y justificación');
  b.p('Matriz: Crítico = compromiso confirmado con alto alcance; Alto = compromiso confirmado de cuenta o equipo; Medio = actividad sospechosa sin éxito o anomalía; Bajo = evento de bajo impacto o probable falso positivo. Con dos o más factores agravantes (activo crítico, cuenta privilegiada o de servicio, éxito, origen externo, evasión, exfiltración) se eleva un nivel.', { size: 9 });
  b.table(['ID', 'Criticidad', 'Justificación'], analysis.findings.map((f) => [f.id, f.level, f.justification]), { levelCol: 1, colWidths: [14, 20, 140] });

  b.h1('7. Posible impacto en la organización');
  b.table(
    ['Incidente', 'Confidencialidad', 'Integridad', 'Disponibilidad', 'Operación', 'Reputación'],
    analysis.incidents.map((i) => [i.id, i.impact.confidencialidad, i.impact.integridad, i.impact.disponibilidad, i.impact.operacion, i.impact.reputacion])
  );
  for (const inc of analysis.incidents) b.p(`${inc.id}: ${narrative.incidentes[inc.id]?.impacto || ''}`, { size: 9 });

  b.h1('8. Plan de acción');
  b.p('Prioridades: P1 inmediato (0–4 h), P2 en 24 h, P3 en 72 h. Fases: investigar, contener y remediar.', { size: 9 });
  b.table(
    ['Prior.', 'Fase', 'Acción', 'Responsable sugerido', 'Inc.'],
    actionPlan(analysis).map((r) => [r.p, PHASE_LABEL[r.phase], r.text, r.owner, r.incident]),
    { colWidths: [13, 18, 94, 33, 16], fontSize: 7.5 }
  );

  b.h1('9. Recomendaciones generales de seguridad');
  narrative.recomendaciones.forEach((r, i) => b.p(`${i + 1}. ${r}`, { gap: 1.5 }));

  b.h1('10. Línea de tiempo consolidada');
  b.table(
    ['Inicio', 'Fin', 'Incidente', 'Hallazgo', 'Criticidad'],
    consolidatedTimeline(analysis).map((f) => [hhmm(f.start), hhmm(f.end), f.incidentId, `${f.id} – ${f.title}`, f.level]),
    { levelCol: 4, colWidths: [16, 16, 18, 104, 20] }
  );

  b.h1('11. Indicadores de compromiso (IoC)');
  b.table(
    ['Tipo', 'Valor', 'Contexto', 'Incidentes', 'Log_ID'],
    extractIocs(analysis).map((i) => [i.type, i.value, i.context, i.incidents.join(', '), i.ids.slice(0, 4).join(', ')]),
    { colWidths: [18, 58, 46, 18, 34], fontSize: 7 }
  );
  b.p('No se observan dominios en los registros: las comunicaciones externas aparecen solo como direcciones IP.', { size: 8.5, color: MUTED });

  b.h1('12. Mapeo MITRE ATT&CK');
  b.table(
    ['Táctica', 'Técnica', 'Hallazgos', 'Criticidad'],
    mitreMapping(analysis).map((m) => [m.tactic, `${m.id} ${m.name}`, m.findings.join(', '), m.level]),
    { levelCol: 3, colWidths: [38, 78, 38, 20] }
  );

  b.h1('13. Conclusiones');
  b.p(narrative.conclusiones);
  b.h2('Limitaciones del análisis');
  b.p(narrative.limitaciones);

  b.h1('Anexo A. Reglas de detección utilizadas');
  b.table(
    ['Regla', 'Categoría', 'Descripción', 'Umbral', 'Hallazgos'],
    analysis.ruleStats.map((r) => [r.id, r.category, r.name, r.threshold, String(r.findings)]),
    { colWidths: [14, 28, 52, 64, 16], fontSize: 7.5 }
  );
  b.h2('Categorías sin evidencia');
  const empty = analysis.categoryStats.filter((cat) => cat.justification);
  b.p(empty.length ? empty.map((cat) => `${cat.category}: ${cat.justification}`).join('\n') : 'Las seis categorías presentan al menos un hallazgo.', { size: 9 });

  b.h1('Anexo B. Falsos positivos descartados');
  for (const f of analysis.discarded) {
    b.p(f.title, { bold: true, size: 9.5, gap: 1 });
    b.p(f.description, { size: 9 });
  }

  b.h1('Anexo C. Glosario');
  b.table(
    ['Término', 'Definición'],
    [
      ['SIEM', 'Plataforma que centraliza, normaliza y correlaciona logs de seguridad.'],
      ['IoC', 'Indicador de compromiso: IP, cuenta, hash, comando o dominio asociado a actividad maliciosa.'],
      ['Correlación', 'Relacionar eventos de distintas fuentes, equipos o tiempos para reconstruir una actividad.'],
      ['Movimiento lateral', 'Técnicas para pasar de un equipo comprometido a otros de la red.'],
      ['Password spraying', 'Probar pocas contraseñas comunes contra muchas cuentas para evitar bloqueos.'],
      ['Exfiltración', 'Extracción no autorizada de datos fuera de la organización.'],
      ['Persistencia', 'Mecanismos para mantener el acceso tras reinicios o cambios de credenciales.'],
      ['MITRE ATT&CK', 'Marco público que clasifica tácticas y técnicas de adversarios.'],
      ['Falso positivo', 'Alerta que parece maliciosa pero corresponde a actividad legítima.'],
    ],
    { colWidths: [36, 138] }
  );

  b.writeToc(tocPage);
  b.finish(fileName);
}
