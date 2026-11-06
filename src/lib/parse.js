import * as XLSX from 'xlsx';

export const SHEET_NAME = 'SIEM Export';
export const REQUIRED_COLUMNS = [
  'Log_ID',
  'Timestamp',
  'Hostname',
  'Event_ID',
  'User',
  'Source_IP',
  'Destination',
  'Log_Source',
  'Event_Description',
  'Process_CommandLine',
  'Result',
  'Severity',
];
const MAX_FILE_BYTES = 25 * 1024 * 1024;

export class ValidationError extends Error {}

const pad = (n) => String(n).padStart(2, '0');

// Devuelve "YYYY-MM-DD HH:mm:ss" o null si el valor no es una fecha válida
function normalizeTimestamp(value) {
  if (value instanceof Date && !isNaN(value)) {
    return `${value.getFullYear()}-${pad(value.getMonth() + 1)}-${pad(value.getDate())} ${pad(value.getHours())}:${pad(value.getMinutes())}:${pad(value.getSeconds())}`;
  }
  if (typeof value === 'number') {
    const d = XLSX.SSF.parse_date_code(value);
    return d ? `${d.y}-${pad(d.m)}-${pad(d.d)} ${pad(d.H)}:${pad(d.M)}:${pad(Math.floor(d.S))}` : null;
  }
  const m = String(value).trim().match(/^(\d{4})-(\d{2})-(\d{2})[ T](\d{2}):(\d{2})(?::(\d{2}))?/);
  return m ? `${m[1]}-${m[2]}-${m[3]} ${m[4]}:${m[5]}:${m[6] || '00'}` : null;
}

// Epoch en UTC "ingenuo": el horario del SIEM se trata tal cual, sin zona horaria
function toEpoch(ts) {
  const [d, t] = ts.split(' ');
  const [y, mo, da] = d.split('-').map(Number);
  const [h, mi, s] = t.split(':').map(Number);
  return Date.UTC(y, mo - 1, da, h, mi, s);
}

export function isInternalIp(ip) {
  return /^10\./.test(ip) || /^192\.168\./.test(ip) || /^172\.(1[6-9]|2\d|3[01])\./.test(ip);
}

const isIp = (v) => /^\d{1,3}(\.\d{1,3}){3}$/.test(v);

const countBy = (items, key) =>
  items.reduce((acc, item) => {
    const k = item[key] || '(vacío)';
    acc[k] = (acc[k] || 0) + 1;
    return acc;
  }, {});

// Nombres casi idénticos: mismo texto alfanumérico o anagrama (DC01↔DC-01, svc_backup↔backupsvc)
function findLookalikes(names) {
  const norm = (n) => n.toLowerCase().replace(/^.*\\/, '').replace(/[^a-z0-9]/g, '');
  const pairs = [];
  for (let i = 0; i < names.length; i++) {
    for (let j = i + 1; j < names.length; j++) {
      const a = norm(names[i]);
      const b = norm(names[j]);
      if (a.length < 4 || b.length < 4) continue;
      const anagram = a.length === b.length && [...a].sort().join('') === [...b].sort().join('');
      if (a === b || anagram) pairs.push([names[i], names[j]]);
    }
  }
  return pairs;
}

export async function parseWorkbook(file) {
  if (!/\.xlsx$/i.test(file.name)) {
    throw new ValidationError('Formato no válido: se espera un archivo Excel (.xlsx).');
  }
  if (file.size > MAX_FILE_BYTES) {
    throw new ValidationError('El archivo supera el tamaño máximo permitido (25 MB).');
  }

  let workbook;
  try {
    workbook = XLSX.read(await file.arrayBuffer(), { type: 'array', cellDates: true });
  } catch {
    throw new ValidationError('No se pudo leer el archivo: está dañado o no es un Excel válido.');
  }

  if (!workbook.SheetNames.includes(SHEET_NAME)) {
    throw new ValidationError(
      `No se encontró la hoja "${SHEET_NAME}". Hojas presentes: ${workbook.SheetNames.join(', ') || 'ninguna'}.`
    );
  }
  const sheet = workbook.Sheets[SHEET_NAME];

  const header = (XLSX.utils.sheet_to_json(sheet, { header: 1 })[0] || []).map((h) => String(h).trim());
  const missing = REQUIRED_COLUMNS.filter((c) => !header.includes(c));
  if (missing.length) {
    throw new ValidationError(`Faltan columnas obligatorias: ${missing.join(', ')}.`);
  }

  const rows = XLSX.utils.sheet_to_json(sheet, { defval: '', raw: true });
  if (!rows.length) throw new ValidationError('La hoja no contiene eventos.');

  const seenIds = new Set();
  const duplicateIds = [];
  const invalidTimestamps = [];
  const events = [];

  rows.forEach((row, i) => {
    const ev = {};
    for (const col of REQUIRED_COLUMNS) ev[col] = String(row[col] ?? '').trim();
    ev._row = i + 2; // fila en Excel (la 1 es el encabezado)

    if (!ev.Log_ID || seenIds.has(ev.Log_ID)) duplicateIds.push(ev.Log_ID || `(fila ${ev._row})`);
    seenIds.add(ev.Log_ID);

    const ts = normalizeTimestamp(row.Timestamp);
    if (!ts) {
      invalidTimestamps.push(ev.Log_ID || `(fila ${ev._row})`);
      return;
    }
    ev.Timestamp = ts;
    ev._t = toEpoch(ts);
    events.push(ev);
  });

  events.sort((a, b) => a._t - b._t || a.Log_ID.localeCompare(b.Log_ID));

  const emptyByColumn = Object.fromEntries(
    REQUIRED_COLUMNS.map((c) => [c, events.filter((e) => !e[c]).length]).filter(([, n]) => n > 0)
  );

  const hosts = Object.keys(countBy(events, 'Hostname')).sort();
  const users = Object.keys(countBy(events, 'User')).filter((u) => u !== '-').sort();
  const ips = [...new Set(events.map((e) => e.Source_IP).filter(isIp))];
  const destIps = [
    ...new Set(events.map((e) => e.Destination.split(':')[0]).filter((d) => isIp(d) && !isInternalIp(d))),
  ];

  return {
    fileName: file.name,
    sheet: SHEET_NAME,
    loadedAt: new Date().toISOString(),
    events,
    summary: {
      total: events.length,
      first: events[0]?.Timestamp,
      last: events[events.length - 1]?.Timestamp,
      sources: countBy(events, 'Log_Source'),
      severities: countBy(events, 'Severity'),
      eventIds: countBy(events, 'Event_ID'),
      hosts,
      users,
      internalIps: ips.filter(isInternalIp).sort(),
      externalIps: ips.filter((ip) => !isInternalIp(ip)).sort(),
      externalDestinations: destIps.sort(),
    },
    quality: {
      columns: REQUIRED_COLUMNS.length,
      rowsRead: rows.length,
      duplicateIds,
      invalidTimestamps,
      emptyByColumn,
      lookalikeHosts: findLookalikes(hosts),
      lookalikeUsers: findLookalikes(users),
    },
  };
}
