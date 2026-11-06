// Contenido del informe: textos por plantilla (deterministas), plan de acción, IoC y MITRE
import { LEVELS, levelIndex, RULES, isExternalIp } from './engine.js';
import { MITRE, TACTIC_ORDER } from './mitre.js';

const hhmm = (ts) => ts.slice(11, 19);
const uniq = (arr) => [...new Set(arr.filter(Boolean))];
const cap = (s) => s.charAt(0).toUpperCase() + s.slice(1);
const fmtMB = (b) => `${(b / 1e6).toLocaleString('es', { maximumFractionDigits: 1 })} MB`;

export const PRIORITY = {
  Crítico: { p: 'P1', plazo: 'Inmediato (0–4 h)' },
  Alto: { p: 'P2', plazo: '24 h' },
  Medio: { p: 'P3', plazo: '72 h' },
  Bajo: { p: 'P4', plazo: 'Planificado' },
};
const PHASES = ['investigar', 'contener', 'remediar'];
export const PHASE_LABEL = { investigar: 'Investigar', contener: 'Contener', remediar: 'Remediar' };

export const plainSummary = (inc) => `${cap(uniq(inc.findings.map((f) => f.plain)).join('; '))}.`;

export function defaultMeta(user) {
  return {
    cliente: 'Cliente – infraestructura corporativa (Estocolmo, Suecia)',
    consultora: 'Consultora de ciberseguridad – SOC',
    analista: user || 'Analista SOC N2',
    apellido: '',
    nombre: '',
    fecha: new Date().toISOString().slice(0, 10),
    clasificacion: 'CONFIDENCIAL',
  };
}

export function defaultNarrative(dataset, analysis) {
  const { incidents, stats, globalLevel } = analysis;
  const real = incidents.filter((i) => i.type === 'incident');
  const anomalies = incidents.filter((i) => i.type === 'anomaly');
  const critical = real.filter((i) => i.level === 'Crítico');
  const all = analysis.findings;
  const has = (pred) => all.some(pred);
  const critHosts = uniq(all.flatMap((f) => f.factors.filter((x) => x.startsWith('Activo crítico')).map((x) => x.match(/\((.+)\)/)[1].split(', ')).flat()));
  const privUsers = uniq(all.filter((f) => ['R-01', 'R-02', 'R-03'].includes(f.rule)).flatMap((f) => f.factors.filter((x) => x.startsWith('Cuenta privilegiada')).map((x) => x.match(/\((.+)\)/)[1])));

  const resumen =
    `Se analizaron ${stats.totalEvents} eventos del SIEM del cliente (${dataset.summary.first.slice(0, 10)}, de ${hhmm(dataset.summary.first)} a ${hhmm(dataset.summary.last)}). ` +
    `El análisis identifica ${real.length} incidentes de seguridad independientes` +
    (anomalies.length ? ` y ${anomalies.length} anomalía pendiente de verificación` : '') +
    `; ${critical.length} de ellos tienen criticidad Crítica. En resumen:\n` +
    real.map((i) => `• ${i.id} (${i.level}): ${plainSummary(i)}`).join('\n') +
    (anomalies.length ? `\n${anomalies.map((i) => `• ${i.id} (${i.level}, hipótesis): ${plainSummary(i)}`).join('\n')}` : '') +
    `\n\nEl riesgo global es ${globalLevel.toUpperCase()}. Se requieren acciones inmediatas: bloquear las IPs externas implicadas, deshabilitar y restablecer las cuentas comprometidas, aislar los equipos afectados y verificar que existen copias de seguridad recuperables.`;

  const valoracion =
    `Riesgo global ${globalLevel}: ${critical.length} de ${real.length} incidentes son críticos. ` +
    [
      critHosts.length && `Se vieron afectados activos críticos (${critHosts.join(', ')}).`,
      privUsers.length && `Se comprometieron cuentas privilegiadas (${privUsers.join(', ')}).`,
      stats.exfilBytes && `Hay exfiltración confirmada de ${fmtMB(stats.exfilBytes)}.`,
      has((f) => f.mitre.includes('T1490')) && 'Se borraron copias de recuperación, indicio de preparación de ransomware.',
      has((f) => f.rule === 'R-06') && 'El atacante dejó mecanismos de persistencia en un servidor.',
    ]
      .filter(Boolean)
      .join(' ');

  const incidentes = Object.fromEntries(
    incidents.map((inc) => [
      inc.id,
      {
        narrativa: inc.findings.map((f) => `${f.id} – ${f.description}`).join('\n\n'),
        impacto:
          `Confidencialidad ${inc.impact.confidencialidad.toLowerCase()}, integridad ${inc.impact.integridad.toLowerCase()}, disponibilidad ${inc.impact.disponibilidad.toLowerCase()}, ` +
          `operación ${inc.impact.operacion.toLowerCase()} y reputación ${inc.impact.reputacion.toLowerCase()}. ` +
          uniq(inc.findings.map((f) => f.impact)).join(' '),
      },
    ])
  );

  const related = incidents.filter((i) => i.related?.length);
  const conclusiones =
    `Los registros evidencian ${real.length} incidentes con orígenes, cuentas y ventanas temporales distintos, por lo que se tratan por separado. ` +
    (related.length
      ? `Hipótesis: ${uniq(related.map((i) => `${i.id} y ${i.related.map((r) => r.id).join(', ')} comparten el equipo ${i.related.flatMap((r) => r.hosts).join(', ')}`)).slice(0, 1).join('')}; podría tratarse del mismo actor, pero no hay evidencia en los logs que lo confirme. `
      : '') +
    (anomalies.length ? `${anomalies.map((a) => a.id).join(', ')} se mantiene como anomalía hasta verificar el inventario de equipos y cuentas. ` : '') +
    `Se descartaron como falsos positivos ${analysis.discarded.map((d) => d.title.toLowerCase()).join(' y ')}.`;

  const recomendaciones = [
    'Exigir MFA en todos los accesos remotos y en cuentas privilegiadas; retirar RDP expuesto a Internet.',
    'Aplicar una política de bloqueo de cuentas y detección de password spraying en el controlador de dominio.',
    'Segmentar la red: impedir SMB entre servidores de aplicación y el servidor de archivos salvo necesidad.',
    'Desplegar EDR con reglas ASR, Script Block Logging y AMSI para bloquear PowerShell codificado.',
    'Mantener copias de seguridad inmutables y fuera de línea; alertar ante el uso de vssadmin o wbadmin.',
    'Implantar DLP y control de salida a Internet (proxy autenticado, bloqueo de destinos no categorizados).',
    'Endurecer el servidor web: prohibir ejecución en /uploads, validar subidas y desplegar WAF.',
    'Aplicar mínimo privilegio a cuentas de servicio y revisar trimestralmente los grupos privilegiados.',
    'Incorporar al SIEM las reglas R-01 a R-12 de este análisis con alertas en tiempo real.',
    'Formar al personal en phishing, uso de contraseñas y manejo de información sensible.',
  ];

  const limitaciones = [
    'El análisis se limita a los 715 eventos entregados de un solo día; no se tuvo acceso a los equipos ni a otras fuentes.',
    has((f) => f.mitre.includes('T1027')) && 'El contenido de los comandos PowerShell codificados está redactado en el log y no puede determinarse qué ejecutaron.',
    has((f) => f.rule === 'R-10' && f.baseLevel < 3) && 'Para la conexión saliente de PowerShell no hay registro del volumen transferido.',
    has((f) => f.rule === 'R-10' && f.baseLevel === 3) && 'No puede distinguirse si la exfiltración fue obra del propio usuario o de un tercero con su cuenta.',
    related.length && 'La relación entre incidentes que comparten equipo no puede confirmarse con estos registros.',
  ]
    .filter(Boolean)
    .join(' ');

  return { resumen_ejecutivo: resumen, valoracion_riesgo: valoracion, incidentes, conclusiones, recomendaciones, limitaciones, source: 'plantilla' };
}

// Convierte la respuesta de la IA al mismo formato que la plantilla
export function narrativeFromAi(ai, fallback) {
  return {
    ...fallback,
    resumen_ejecutivo: ai.resumen_ejecutivo,
    valoracion_riesgo: ai.valoracion_riesgo,
    incidentes: {
      ...fallback.incidentes,
      ...Object.fromEntries(ai.incidentes.filter((i) => fallback.incidentes[i.id]).map((i) => [i.id, { narrativa: i.narrativa, impacto: i.impacto }])),
    },
    conclusiones: ai.conclusiones,
    recomendaciones: ai.recomendaciones,
    limitaciones: ai.limitaciones,
  };
}

export function actionPlan(analysis) {
  const rows = [];
  const seen = new Set();
  for (const inc of analysis.incidents) {
    for (const f of inc.findings) {
      for (const phase of PHASES) {
        for (const a of f.actions[phase] || []) {
          const key = `${phase}|${a.text}`;
          if (seen.has(key)) continue;
          seen.add(key);
          rows.push({ incident: inc.id, finding: f.id, phase, text: a.text, owner: a.owner, level: f.level, ...PRIORITY[f.level] });
        }
      }
    }
  }
  return rows.sort((a, b) => levelIndex(b.level) - levelIndex(a.level) || PHASES.indexOf(a.phase) - PHASES.indexOf(b.phase) || a.incident.localeCompare(b.incident));
}

export const urgentActions = (analysis) => actionPlan(analysis).filter((r) => r.p === 'P1' && r.phase === 'contener');

const PATH_RE = /[A-Za-z]:\\[^\s;"']+\.\w{1,4}|\\\\[\w.-]+\\[\w$.-]+(\\[\w.-]+)*|\b[\w-]+\\[\w\\.-]+\.(xlsx|docx|zip|7z|pdf)\b/g;

export function extractIocs(analysis) {
  const map = new Map();
  const add = (type, value, context, inc, ids) => {
    const k = `${type}|${value}`;
    if (!map.has(k)) map.set(k, { type, value, context, incidents: new Set(), ids: new Set() });
    const item = map.get(k);
    item.incidents.add(inc);
    ids.forEach((id) => item.ids.add(id));
  };
  for (const inc of analysis.incidents) {
    for (const f of inc.findings) {
      const ids = (pred) => f.evidence.filter(pred).map((e) => e.Log_ID);
      for (const ip of f.externalIps) {
        const src = ids((e) => e.Source_IP === ip);
        if (src.length) add('IP', ip, 'Origen externo del ataque', inc.id, src.slice(0, 5));
        const dst = ids((e) => e.Destination.startsWith(ip));
        if (dst.length) add('IP', ip, 'Destino externo (exfiltración / C2)', inc.id, dst.slice(0, 5));
      }
      for (const u of f.users.filter((u) => u !== '-')) add('Cuenta', u, f.status === 'hypothesis' ? 'Cuenta anómala (hipótesis)' : 'Cuenta comprometida o usada por el atacante', inc.id, ids((e) => e.User === u).slice(0, 5));
      for (const h of f.hosts) add('Equipo', h, f.execHosts.includes(h) ? 'Equipo con ejecución maliciosa' : 'Equipo afectado', inc.id, ids((e) => e.Hostname === h).slice(0, 5));
      for (const e of f.evidence) {
        if (['4688', '4104', '4698', '7045'].includes(e.Event_ID) && !/^(explorer|notepad|svchost|taskhostw)\.exe$/i.test(e.Process_CommandLine)) {
          add('Comando', e.Event_ID === '4104' ? e.Event_Description.replace(/^PowerShell Script Block:\s*/i, '') : e.Process_CommandLine, `Ejecutado en ${e.Hostname} por ${e.User}`, inc.id, [e.Log_ID]);
        }
        if (e.Event_ID === 'HTTP_ACCESS') add('URI', e.Process_CommandLine, `Petición web a ${e.Hostname}`, inc.id, [e.Log_ID]);
        for (const p of `${e.Process_CommandLine} ${e.Event_Description} ${e.Destination}`.match(PATH_RE) || []) {
          add('Archivo / ruta', p, `Referenciado en ${e.Hostname}`, inc.id, [e.Log_ID]);
        }
      }
    }
  }
  const order = ['IP', 'Cuenta', 'Equipo', 'Comando', 'Archivo / ruta', 'URI'];
  return [...map.values()]
    .map((i) => ({ ...i, incidents: [...i.incidents], ids: [...i.ids] }))
    .sort((a, b) => order.indexOf(a.type) - order.indexOf(b.type) || a.value.localeCompare(b.value));
}

export function mitreMapping(analysis) {
  const map = new Map();
  for (const f of analysis.findings) {
    for (const id of f.mitre) {
      if (!map.has(id)) map.set(id, { id, ...MITRE[id], findings: [], level: 'Bajo' });
      const m = map.get(id);
      m.findings.push(f.id);
      if (levelIndex(f.level) > levelIndex(m.level)) m.level = f.level;
    }
  }
  return [...map.values()].sort((a, b) => TACTIC_ORDER.indexOf(a.tactic) - TACTIC_ORDER.indexOf(b.tactic) || a.id.localeCompare(b.id));
}

export const consolidatedTimeline = (analysis) =>
  analysis.findings.map((f) => ({ ...f })).sort((a, b) => a._start - b._start);

export const evidenceExtract = (e) =>
  [e.Event_Description, e.Process_CommandLine, e.Destination && `→ ${e.Destination}`, e.Result].filter(Boolean).join(' · ');

export function unknownLogIds(narrative, dataset) {
  const known = new Set(dataset.events.map((e) => e.Log_ID));
  const cited = JSON.stringify(narrative).match(/EVT-\d{5}/g) || [];
  return uniq(cited.filter((id) => !known.has(id)));
}

// Contexto estructurado que se envía a la IA (solo datos verificables)
export function buildAiContext(dataset, analysis) {
  return {
    alcance: {
      archivo: dataset.fileName,
      eventos: dataset.summary.total,
      ventana: `${dataset.summary.first} – ${dataset.summary.last}`,
      fuentes: dataset.summary.sources,
    },
    riesgo_global: analysis.globalLevel,
    exfiltracion_confirmada_bytes: analysis.stats.exfilBytes,
    incidentes: analysis.incidents.map((inc) => ({
      id: inc.id,
      tipo: inc.type === 'anomaly' ? 'anomalía (hipótesis)' : 'incidente',
      titulo: inc.title,
      criticidad: inc.level,
      ventana: `${inc.start} – ${inc.end}`,
      equipos: inc.hosts,
      cuentas: inc.users,
      ips_externas: inc.externalIps,
      tacticas: inc.tactics,
      impacto: inc.impact,
      motivo_agrupacion: inc.rationale,
      hallazgos: inc.findings.map((f) => ({
        id: f.id,
        titulo: f.title,
        categoria: f.category,
        criticidad: f.level,
        estado: f.status,
        justificacion: f.justification,
        mitre: f.mitre.map((m) => `${m} ${MITRE[m]?.name ?? ''}`),
        descripcion: f.description,
        total_evidencias: f.evidence.length,
        evidencias: f.evidence.slice(0, 12).map((e) => ({
          Log_ID: e.Log_ID,
          Timestamp: e.Timestamp,
          Hostname: e.Hostname,
          Event_ID: e.Event_ID,
          User: e.User,
          Source_IP: e.Source_IP,
          extracto: evidenceExtract(e),
        })),
      })),
    })),
    descartados: analysis.discarded.map((f) => ({ titulo: f.title, motivo: f.description })),
  };
}

export const RULE_TABLE = RULES;
export { LEVELS, isExternalIp };
