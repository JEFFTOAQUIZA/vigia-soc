// Motor de detección y correlación de VIGÍA.
// Todas las conclusiones salen de reglas deterministas sobre los eventos cargados:
// el mismo archivo con la misma configuración produce siempre el mismo resultado.
import { isInternalIp } from './parse.js';
import { MITRE, TACTIC_ORDER } from './mitre.js';

const MIN = 60_000;

export const LEVELS = ['Bajo', 'Medio', 'Alto', 'Crítico'];
export const levelIndex = (level) => LEVELS.indexOf(level);

export const CATEGORIES = [
  'Fuerza bruta',
  'Inicios sospechosos',
  'Escalamiento',
  'Comandos y procesos',
  'Movimiento lateral',
  'Otras anomalías',
];

export const DEFAULT_CONFIG = {
  sprayWindowMin: 15,
  sprayMinAccounts: 5,
  bruteWindowMin: 10,
  bruteMinFailures: 3,
  successLookaheadMin: 30,
  massAccessWindowMin: 5,
  massAccessMin: 10,
  exfilMinMB: 50,
  webWindowMin: 10,
  webMinRequests: 10,
  commandGapMin: 30,
  correlationGapMin: 60,
  workStart: 7,
  workEnd: 19,
  criticalAssets: ['DC-01', 'FS-SRV01', 'DB-SRV01'],
  privilegedAccounts: ['CORP\\admin', 'CORP\\helpdesk', 'CORP\\backupsvc'],
  serviceAccounts: ['CORP\\backupsvc', 'CORP\\svc_backup'],
};

const OWNERS = {
  soc: 'SOC N2',
  iam: 'Administración AD / IAM',
  net: 'Redes / Firewall',
  infra: 'Infraestructura de servidores',
  web: 'Equipo web / DevOps',
  edr: 'Endpoint / EDR',
  legal: 'Legal y Cumplimiento',
  ciso: 'CISO / Dirección',
};

// ── Utilidades ──────────────────────────────────────────────────────────────
const isIp = (v) => /^\d{1,3}(\.\d{1,3}){3}$/.test(v);
export const isExternalIp = (v) => isIp(v) && !isInternalIp(v);
const destIp = (d) => String(d || '').split(':')[0];
const uniq = (arr) => [...new Set(arr.filter((x) => x && x !== '-'))];
const hhmm = (ts) => ts.slice(11, 19);
const plural = (n, s, p) => `${n} ${n === 1 ? s : p}`;
const fmtMB = (bytes) => `${(bytes / 1e6).toLocaleString('es', { maximumFractionDigits: 1 })} MB`;

function groupBy(list, keyFn) {
  const map = new Map();
  for (const item of list) {
    const k = keyFn(item);
    if (!map.has(k)) map.set(k, []);
    map.get(k).push(item);
  }
  return map;
}

function splitByGap(list, gapMs) {
  const groups = [];
  let current = [];
  for (const e of list) {
    if (current.length && e._t - current[current.length - 1]._t > gapMs) {
      groups.push(current);
      current = [];
    }
    current.push(e);
  }
  if (current.length) groups.push(current);
  return groups;
}

// Ventana deslizante con el mayor número de eventos (o de valores distintos)
function bestWindow(list, winMs, distinctFn) {
  let best = null;
  let j = 0;
  for (let i = 0; i < list.length; i++) {
    while (j < list.length && list[j]._t - list[i]._t <= winMs) j++;
    const slice = list.slice(i, j);
    const score = distinctFn ? new Set(slice.map(distinctFn)).size : slice.length;
    if (!best || score > best.score) best = { score, slice };
  }
  return best;
}

const avgIntervalSec = (list) =>
  list.length < 2 ? 0 : Math.round((list[list.length - 1]._t - list[0]._t) / (list.length - 1) / 1000);

// ── Construcción de hallazgos ───────────────────────────────────────────────
function computeFactors(ctx, { evidence, users, hosts, extra = [] }) {
  const factors = [];
  const ext = uniq(evidence.map((e) => e.Source_IP).filter(isExternalIp));
  if (ext.length) factors.push(`Origen externo (${ext.join(', ')})`);
  const us = users ?? uniq(evidence.map((e) => e.User));
  const priv = us.filter(ctx.isPrivileged);
  if (priv.length) factors.push(`Cuenta privilegiada (${priv.join(', ')})`);
  const svc = us.filter((u) => ctx.isService(u) && !priv.includes(u));
  if (svc.length) factors.push(`Cuenta de servicio (${svc.join(', ')})`);
  const hs = hosts ?? uniq(evidence.map((e) => e.Hostname));
  const crit = hs.filter(ctx.isCritical);
  if (crit.length) factors.push(`Activo crítico (${crit.join(', ')})`);
  return [...factors, ...extra];
}

function addFinding(ctx, f) {
  const evidence = [...new Map(f.evidence.map((e) => [e.Log_ID, e])).values()].sort((a, b) => a._t - b._t);
  const status = f.status ?? 'confirmed';
  const factors = status === 'fp' ? [] : computeFactors(ctx, { evidence, ...(f.factorOpts || {}) });
  let li = f.baseLevel;
  const escalated = status === 'confirmed' && li < 3 && factors.length >= 2;
  if (escalated) li += 1;

  const justification =
    `${f.baseReason} (nivel base: ${LEVELS[f.baseLevel]}).` +
    (factors.length ? ` Factores agravantes: ${factors.join('; ')}.` : ' Sin factores agravantes adicionales.') +
    (escalated ? ' Con dos o más factores agravantes se eleva un nivel según la matriz.' : '') +
    (status === 'hypothesis' ? ' Se mantiene como hipótesis: los registros no permiten confirmarlo.' : '');

  const finding = {
    execHosts: [],
    ...f,
    status,
    evidence,
    factors,
    escalated,
    level: LEVELS[li],
    justification,
    start: evidence[0].Timestamp,
    end: evidence[evidence.length - 1].Timestamp,
    _start: evidence[0]._t,
    _end: evidence[evidence.length - 1]._t,
    hosts: uniq(evidence.map((e) => e.Hostname)),
    // Cuentas implicadas: las que usa el atacante (en un spraying, solo las comprometidas; las atacadas van en la descripción)
    users: f.actorUsers ?? uniq(evidence.map((e) => e.User)),
    ips: uniq(evidence.map((e) => e.Source_IP)),
    externalIps: uniq([
      ...evidence.map((e) => e.Source_IP).filter(isExternalIp),
      ...evidence.map((e) => destIp(e.Destination)).filter(isExternalIp),
    ]),
    keys: uniq(f.keys),
    tactics: TACTIC_ORDER.filter((t) => f.mitre.some((m) => MITRE[m]?.tactic === t)),
  };
  if (f.consume !== false) evidence.forEach((e) => ctx.consumed.add(e.Log_ID));
  ctx.findings.push(finding);
  return finding;
}

const free = (ctx) => (e) => !ctx.consumed.has(e.Log_ID);

// ── Reglas ──────────────────────────────────────────────────────────────────
export const RULES = [
  { id: 'R-01', category: 'Fuerza bruta', name: 'Password spraying', threshold: (c) => `≥${c.sprayMinAccounts} cuentas distintas con 4625 desde una IP en ${c.sprayWindowMin} min` },
  { id: 'R-02', category: 'Fuerza bruta', name: 'Fuerza bruta contra una cuenta', threshold: (c) => `≥${c.bruteMinFailures} fallos 4625 usuario+IP en ${c.bruteWindowMin} min` },
  { id: 'R-03', category: 'Inicios sospechosos', name: 'Inicio exitoso desde IP externa o fuera de horario', threshold: (c) => `4624 desde IP pública o fuera de ${c.workStart}:00–${c.workEnd}:00` },
  { id: 'R-04', category: 'Movimiento lateral', name: 'Inicio de red entre equipos internos + acceso a recursos', threshold: () => '4624/4625 con source=EQUIPO + 5140/5145 posteriores' },
  { id: 'R-05', category: 'Otras anomalías', name: 'Explotación web / web shell', threshold: (c) => `≥${c.webMinRequests} peticiones IIS de una IP externa en ${c.webWindowMin} min o URI maliciosa` },
  { id: 'R-06', category: 'Comandos y procesos', name: 'Persistencia (tareas y servicios)', threshold: () => '4698 / 7045 + ejecuciones del binario registrado' },
  { id: 'R-07', category: 'Comandos y procesos', name: 'Comandos y herramientas sospechosas', threshold: () => 'PowerShell codificado, vssadmin, LOLBins, reconocimiento, compresión, rutas inusuales' },
  { id: 'R-08', category: 'Escalamiento', name: 'Privilegios especiales / cambios en cuentas', threshold: () => '4672 en cuentas no administrativas; 4720/4722/4728/4732/4756' },
  { id: 'R-09', category: 'Otras anomalías', name: 'Acceso masivo a archivos', threshold: (c) => `≥${c.massAccessMin} eventos 4663 usuario+equipo en ${c.massAccessWindowMin} min` },
  { id: 'R-10', category: 'Otras anomalías', name: 'Exfiltración / conexiones salientes', threshold: (c) => `bytes_out ≥ ${c.exfilMinMB} MB a un destino o conexión saliente de un intérprete` },
  { id: 'R-11', category: 'Otras anomalías', name: 'Equipos o cuentas con nombres casi idénticos', threshold: () => 'Nombre normalizado igual o anagrama' },
  { id: 'R-12', category: 'Otras anomalías', name: 'Borrado de registros / evasión', threshold: () => '1102 / 104' },
];

function ruleSpray(ctx) {
  const { cfg } = ctx;
  const fails = ctx.events.filter((e) => e.Event_ID === '4625');
  for (const [ip, list] of groupBy(fails, (e) => e.Source_IP)) {
    const best = bestWindow(list, cfg.sprayWindowMin * MIN, (e) => e.User);
    if (!best || best.score < cfg.sprayMinAccounts) continue;
    // El ataque completo: fallos de esa IP encadenados con pausas menores que la ventana
    const cluster = splitByGap(list, cfg.sprayWindowMin * MIN).find((g) => g.includes(best.slice[0]));
    const last = cluster[cluster.length - 1];
    const successes = ctx.events.filter(
      (e) => e.Event_ID === '4624' && e.Source_IP === ip && e._t >= cluster[0]._t && e._t - last._t <= cfg.successLookaheadMin * MIN
    );
    const compromised = uniq(successes.map((e) => e.User));
    const targets = uniq(cluster.map((e) => e.User));
    const victims = uniq(cluster.map((e) => e.Hostname));
    ctx.sprayIps.add(ip);
    addFinding(ctx, {
      rule: 'R-01',
      category: 'Fuerza bruta',
      short: 'Password spraying',
      plain: `desde Internet (${ip}) se probaron contraseñas contra ${targets.length} cuentas${compromised.length ? ` y se logró entrar con ${compromised.join(', ')}` : ''}`,
      title: `Password spraying desde ${ip} contra ${plural(targets.length, 'cuenta', 'cuentas')}${compromised.length ? ` con acceso logrado (${compromised.join(', ')})` : ''}`,
      baseLevel: compromised.length ? 2 : 1,
      baseReason: compromised.length ? 'Fuerza bruta con éxito posterior' : 'Fuerza bruta sin evidencia de éxito',
      factorOpts: { users: compromised, extra: compromised.length ? ['Ataque exitoso'] : [] },
      actorUsers: compromised,
      targets,
      mitre: ['T1110.003'],
      keys: [`ip:${ip}`],
      evidence: cluster,
      description:
        `Entre ${hhmm(cluster[0].Timestamp)} y ${hhmm(last.Timestamp)} la IP ${ip} generó ${cluster.length} inicios de sesión fallidos contra ${victims.join(', ')}, ` +
        `probando ${targets.length} cuentas distintas (${targets.join(', ')}) a intervalos regulares de ~${avgIntervalSec(cluster)} s: pocas contraseñas contra muchas cuentas para evitar bloqueos.` +
        (compromised.length
          ? ` Después se registra un inicio de sesión exitoso desde la misma IP con ${compromised.join(', ')} (${successes.map((e) => e.Log_ID).join(', ')}), por lo que el atacante obtuvo credenciales válidas.`
          : ' No se observa ningún inicio de sesión exitoso posterior desde esa IP.'),
      detection: `R-01: ${best.score} cuentas distintas con 4625 desde ${ip} en una ventana de ${cfg.sprayWindowMin} min (umbral ${cfg.sprayMinAccounts}).`,
      impact: compromised.length
        ? `Credenciales de dominio comprometidas (${compromised.join(', ')}); el atacante puede autenticarse en el controlador de dominio y otros sistemas.`
        : 'Riesgo de compromiso de credenciales y de bloqueo de cuentas.',
      actions: {
        investigar: [
          { text: `Revisar todos los inicios de sesión de ${compromised.join(', ') || 'las cuentas objetivo'} desde las 08:00 y la actividad posterior.`, owner: OWNERS.soc },
          { text: `Buscar la IP ${ip} en VPN, correo, proxy y firewall perimetral.`, owner: OWNERS.net },
        ],
        contener: [
          { text: `Bloquear ${ip} en el firewall perimetral.`, owner: OWNERS.net },
          ...(compromised.length ? [{ text: `Restablecer contraseña y revocar sesiones de ${compromised.join(', ')}.`, owner: OWNERS.iam }] : []),
        ],
        remediar: [
          { text: 'Aplicar MFA en todo acceso expuesto y política de bloqueo inteligente (smart lockout).', owner: OWNERS.iam },
          { text: `Forzar cambio de contraseña a las ${targets.length} cuentas atacadas y revisar exposición del DC a Internet.`, owner: OWNERS.iam },
        ],
      },
    });
  }
}

function ruleBrute(ctx) {
  const { cfg } = ctx;
  const fails = ctx.events.filter((e) => e.Event_ID === '4625' && free(ctx)(e) && !ctx.sprayIps.has(e.Source_IP));
  for (const [, list] of groupBy(fails, (e) => `${e.User}|${e.Source_IP}`)) {
    const best = bestWindow(list, cfg.bruteWindowMin * MIN);
    if (!best || best.score < cfg.bruteMinFailures) continue;
    const burst = best.slice;
    const { User: user, Source_IP: ip } = burst[0];
    const last = burst[burst.length - 1];
    const success = ctx.events.find(
      (e) => e.Event_ID === '4624' && e.User === user && e.Source_IP === ip && e._t >= last._t && e._t - last._t <= cfg.successLookaheadMin * MIN
    );
    const rdp = burst.some((e) => /RDP|LogonType=10/i.test(e.Event_Description));
    if (success) ctx.bruteSuccess.add(success.Log_ID);
    addFinding(ctx, {
      rule: 'R-02',
      category: 'Fuerza bruta',
      short: rdp ? 'Fuerza bruta RDP' : 'Fuerza bruta',
      plain: `${success ? 'se adivinó' : 'se intentó adivinar'} la contraseña de ${user}${rdp ? ' para entrar por escritorio remoto' : ''}${isExternalIp(ip) ? ` desde Internet (${ip})` : ''}`,
      title: `Fuerza bruta${rdp ? ' RDP' : ''} contra ${user} desde ${ip}${success ? ' con acceso logrado' : ''}`,
      baseLevel: success ? 2 : 1,
      baseReason: success ? 'Fuerza bruta con éxito posterior' : 'Fuerza bruta sin evidencia de éxito',
      factorOpts: { extra: success ? ['Ataque exitoso'] : [] },
      mitre: rdp ? ['T1110.001', 'T1133'] : ['T1110.001'],
      keys: [`user:${user}`, isExternalIp(ip) ? `ip:${ip}` : null],
      evidence: burst,
      description:
        `${plural(burst.length, 'intento fallido', 'intentos fallidos')} de inicio de sesión${rdp ? ' por RDP (LogonType 10)' : ''} contra ${user} desde ${ip} entre ${hhmm(burst[0].Timestamp)} y ${hhmm(last.Timestamp)}.` +
        (success ? ` Le sigue un inicio de sesión exitoso a las ${hhmm(success.Timestamp)} (${success.Log_ID}).` : ' No hay un inicio exitoso posterior.'),
      detection: `R-02: ${burst.length} fallos 4625 del par usuario+IP en ${cfg.bruteWindowMin} min (umbral ${cfg.bruteMinFailures}).`,
      impact: success ? `Compromiso de la cuenta ${user}.` : `Intento de compromiso de la cuenta ${user}.`,
      actions: {
        investigar: [{ text: `Validar con el propietario de ${user} si reconoce los accesos y revisar sus sesiones activas.`, owner: OWNERS.soc }],
        contener: [
          ...(isExternalIp(ip) ? [{ text: `Bloquear ${ip} y cerrar la exposición ${rdp ? 'RDP (3389)' : 'del servicio'} a Internet.`, owner: OWNERS.net }] : []),
          { text: `Deshabilitar temporalmente ${user} y restablecer su contraseña.`, owner: OWNERS.iam },
        ],
        remediar: [{ text: `Publicar ${rdp ? 'RDP' : 'el acceso'} solo tras VPN/RD Gateway con MFA; aplicar bloqueo de cuenta.`, owner: OWNERS.net }],
      },
    });
  }
}

function ruleLogins(ctx) {
  const { cfg } = ctx;
  const outOfHours = (e) => {
    const h = Number(e.Timestamp.slice(11, 13));
    return h < cfg.workStart || h >= cfg.workEnd;
  };
  const logins = ctx.events.filter((e) => e.Event_ID === '4624' && (isExternalIp(e.Source_IP) || outOfHours(e)));
  for (const [, list] of groupBy(logins, (e) => `${e.User}|${e.Source_IP}`)) {
    const { User: user, Source_IP: ip } = list[0];
    const external = isExternalIp(ip);
    const privs = ctx.events.filter(
      (e) => e.Event_ID === '4672' && e.User === user && e.Source_IP === ip && list.some((l) => e._t >= l._t && e._t - l._t <= 5 * MIN)
    );
    const afterAttack = ctx.sprayIps.has(ip) || list.some((e) => ctx.bruteSuccess.has(e.Log_ID));
    const rdp = list.some((e) => /RDP|LogonType=10/i.test(e.Event_Description));
    const hosts = uniq(list.map((e) => e.Hostname));
    addFinding(ctx, {
      rule: 'R-03',
      category: 'Inicios sospechosos',
      short: afterAttack ? 'Acceso con credenciales obtenidas' : 'Inicio sospechoso',
      plain: `hubo un acceso exitoso con ${user} ${external ? 'desde Internet' : 'fuera de horario'}${privs.length ? ' con permisos de administrador' : ''}`,
      title: `Inicio de sesión exitoso ${external ? `desde IP externa ${ip}` : 'fuera de horario'} con ${user}${afterAttack ? ' tras ataque de contraseñas' : ''}`,
      baseLevel: external ? 2 : 1,
      baseReason: external ? 'Compromiso confirmado de una cuenta desde Internet' : 'Inicio fuera de horario sin otra actividad maliciosa asociada',
      factorOpts: { extra: afterAttack ? ['Precedido de fuerza bruta / spraying'] : [] },
      mitre: rdp ? ['T1078', 'T1021.001', 'T1133'] : ['T1078'],
      keys: [`user:${user}`, external ? `ip:${ip}` : null],
      evidence: [...list, ...privs],
      description:
        `La cuenta ${user} inició sesión${rdp ? ' por RDP' : ''} en ${hosts.join(', ')} desde ${ip} (${list.map((e) => `${e.Log_ID} ${hhmm(e.Timestamp)}`).join(', ')}).` +
        (privs.length ? ` Inmediatamente se le asignan privilegios especiales (4672: ${privs.map((e) => `${e.Log_ID} en ${e.Hostname}`).join(', ')}).` : '') +
        (afterAttack ? ' El acceso ocurre tras un ataque de contraseñas desde el mismo origen, por lo que se considera uso de credenciales comprometidas.' : ''),
      detection: `R-03: 4624 ${external ? 'con IP de origen pública' : `fuera del horario ${cfg.workStart}:00–${cfg.workEnd}:00`}.`,
      impact: `Un actor no autorizado opera con la identidad de ${user}${privs.length ? ' con privilegios elevados' : ''}.`,
      actions: {
        investigar: [{ text: `Reconstruir toda la actividad de ${user} posterior a ${hhmm(list[0].Timestamp)} en todos los equipos.`, owner: OWNERS.soc }],
        // Si hubo ataque previo, el bloqueo de la IP y el cambio de contraseña ya figuran en ese hallazgo
        contener: [
          { text: `Revocar las sesiones activas y los tickets Kerberos de ${user}.`, owner: OWNERS.iam },
          ...(external && !afterAttack ? [{ text: `Bloquear ${ip} en el perímetro.`, owner: OWNERS.net }] : []),
        ],
        remediar: [{ text: 'Exigir MFA y acceso condicional para inicios desde Internet.', owner: OWNERS.iam }],
      },
    });
  }
}

function ruleLateral(ctx) {
  const logons = ctx.events.filter(
    (e) => ['4624', '4625'].includes(e.Event_ID) && free(ctx)(e) && /source=([\w-]+)/i.test(e.Event_Description)
  );
  const adminShares = ctx.events.filter((e) => /\\(ADMIN|C|IPC)\$/i.test(`${e.Destination} ${e.Event_Description}`));
  for (const [, list] of groupBy(logons, (e) => `${e.User}|${e.Hostname}`)) {
    const { User: user, Hostname: target } = list[0];
    const source = list[0].Event_Description.match(/source=([\w-]+)/i)[1];
    if (source === target) continue;
    const success = list.find((e) => e.Event_ID === '4624');
    const shares = ctx.events.filter(
      (e) =>
        ['5140', '5145'].includes(e.Event_ID) &&
        e.User === user &&
        e.Hostname === target &&
        e._t >= list[0]._t &&
        e._t - list[list.length - 1]._t <= 15 * MIN &&
        /\\/.test(`${e.Destination}${e.Event_Description}`)
    );
    const resources = uniq(shares.map((e) => e.Event_Description.split(': ').slice(1).join(': ') || e.Destination));
    addFinding(ctx, {
      rule: 'R-04',
      category: 'Movimiento lateral',
      short: 'Movimiento lateral',
      plain: `el atacante saltó de ${source} al servidor ${target}${resources.length ? ` y abrió ${resources.join(', ')}` : ''}`,
      title: `Movimiento lateral ${source} → ${target} con ${user}${resources.length ? ` y acceso a ${resources.join(', ')}` : ''}`,
      baseLevel: 2,
      baseReason: 'Movimiento lateral entre equipos con autenticación exitosa',
      factorOpts: { extra: success ? ['Ataque exitoso'] : [] },
      mitre: shares.length ? ['T1021.002', 'T1039'] : ['T1021.002'],
      keys: [`user:${user}`],
      evidence: [...list, ...shares, ...adminShares.filter((e) => e.User === user)],
      description:
        `La cuenta ${user} se autentica por red (LogonType 3) desde ${source} hacia ${target} (${list.map((e) => `${e.Log_ID} ${e.Result}`).join(', ')}).` +
        (shares.length ? ` A continuación accede a ${resources.join(', ')} (${shares.map((e) => e.Log_ID).join(', ')}).` : ''),
      detection: 'R-04: inicio de sesión de red con equipo de origen interno distinto del destino, seguido de acceso a recursos compartidos.',
      impact: `El atacante alcanzó ${target}${shares.length ? ' y accedió a información sensible' : ''}.`,
      actions: {
        investigar: [{ text: `Revisar en ${target} todos los accesos de ${user} y los archivos leídos o copiados.`, owner: OWNERS.soc }],
        contener: [{ text: `Aislar ${source} de la red y bloquear el tráfico SMB entre servidores no necesario.`, owner: OWNERS.edr }],
        remediar: [{ text: 'Segmentar la red (servidores de aplicación ↛ servidor de archivos) y aplicar el modelo de niveles para cuentas administrativas.', owner: OWNERS.infra }],
      },
    });
  }
}

function ruleWeb(ctx) {
  const { cfg } = ctx;
  const reqs = ctx.events.filter((e) => e.Event_ID === 'HTTP_ACCESS' || e.Log_Source === 'IIS');
  const badUri = /cmd=|\.\.\/|union\s+select|<script|\/etc\/passwd|\.(aspx|php|jsp)\?(cmd|exec)/i;
  for (const [ip, list] of groupBy(reqs, (e) => e.Source_IP)) {
    if (!isExternalIp(ip)) continue;
    const best = bestWindow(list, cfg.webWindowMin * MIN);
    const malicious = list.filter((e) => badUri.test(e.Process_CommandLine));
    if (best.score < cfg.webMinRequests && !malicious.length) continue;
    const hosts = uniq(list.map((e) => e.Hostname));
    const last = list[list.length - 1];
    const rce = ctx.events.filter(
      (e) => e.Event_ID === '4688' && hosts.includes(e.Hostname) && /IIS APPPOOL|w3wp/i.test(`${e.User} ${e.Process_CommandLine}`) && e._t >= list[0]._t && e._t - last._t <= 30 * MIN
    );
    const codes = list.reduce((acc, e) => ((acc[e.Result] = (acc[e.Result] || 0) + 1), acc), {});
    const uris = uniq(list.map((e) => e.Process_CommandLine));
    const ok = list.filter((e) => e.Result === '200');
    addFinding(ctx, {
      rule: 'R-05',
      category: 'Otras anomalías',
      short: rce.length ? 'Explotación web (web shell)' : 'Escaneo web',
      plain: rce.length
        ? `un atacante desde Internet (${ip}) aprovechó un archivo malicioso en la web pública (${hosts.join(', ')}) para ejecutar comandos en el servidor`
        : `se detectó un escaneo del servidor web desde ${ip}`,
      title: `${rce.length ? 'Explotación web con ejecución de comandos' : 'Escaneo / ataque web'} en ${hosts.join(', ')} desde ${ip}`,
      baseLevel: rce.length ? 2 : 1,
      baseReason: rce.length ? 'Ejecución remota de código confirmada en el servidor web' : 'Peticiones maliciosas sin evidencia de éxito',
      mitre: rce.length ? ['T1190', 'T1505.003', 'T1059.003', 'T1033'] : ['T1190'],
      keys: [`ip:${ip}`],
      evidence: [...list, ...rce],
      execHosts: rce.length ? hosts : [],
      description:
        `${list.length} peticiones HTTP desde ${ip} entre ${hhmm(list[0].Timestamp)} y ${hhmm(last.Timestamp)} a ${uris.join(', ')} ` +
        `(respuestas: ${Object.entries(codes).map(([k, v]) => `${v}×${k}`).join(', ')}).` +
        (rce.length
          ? ` A las ${hhmm(rce[0].Timestamp)} el usuario del pool de IIS ejecuta "${rce[0].Process_CommandLine}" (${rce.map((e) => e.Log_ID).join(', ')}): el web shell /uploads/test.aspx permite ejecutar comandos en el servidor.`
          : '') +
        (ok.some((e) => /export/i.test(e.Process_CommandLine))
          ? ` Hipótesis: las respuestas 200 a /api/v1/export (${ok.filter((e) => /export/i.test(e.Process_CommandLine)).map((e) => e.Log_ID).join(', ')}) podrían implicar extracción de datos; se requiere el log de la aplicación para confirmarlo.`
          : ''),
      detection: `R-05: ${best.score} peticiones en ${cfg.webWindowMin} min (umbral ${cfg.webMinRequests}) y ${malicious.length} URI con patrón de ejecución de comandos.`,
      impact: rce.length ? 'Control del servidor web expuesto a Internet con la identidad del pool de aplicaciones.' : 'Reconocimiento del servidor web.',
      actions: {
        investigar: [
          { text: `Revisar el contenido y la fecha de creación de /uploads/test.aspx y los logs completos de IIS de ${ip}.`, owner: OWNERS.web },
          { text: 'Determinar qué devolvió /api/v1/export a la IP atacante.', owner: OWNERS.web },
        ],
        contener: [
          { text: `Bloquear ${ip} en el WAF/firewall y retirar el archivo test.aspx.`, owner: OWNERS.web },
          { text: 'Aislar WEB-01 para análisis forense si hay más procesos lanzados por w3wp.', owner: OWNERS.edr },
        ],
        remediar: [{ text: 'Impedir la ejecución de scripts en /uploads, validar subidas de archivos y desplegar WAF.', owner: OWNERS.web }],
      },
    });
  }
}

function rulePersistence(ctx) {
  const creations = ctx.events.filter((e) => ['4698', '7045', '4697'].includes(e.Event_ID) && free(ctx)(e));
  for (const [, list] of groupBy(creations, (e) => `${e.Hostname}|${e.User}`)) {
    const { Hostname: host, User: user } = list[0];
    const artifacts = uniq(list.flatMap((e) => e.Process_CommandLine.match(/[A-Za-z]:\\[^;\s]+\.(exe|ps1|bat|dll|vbs)/gi) || []));
    const runs = ctx.events.filter(
      (e) => e.Event_ID === '4688' && e.Hostname === host && artifacts.some((a) => e.Process_CommandLine.toLowerCase().includes(a.toLowerCase()))
    );
    const intervals = runs.slice(1).map((e, i) => Math.round((e._t - runs[i]._t) / MIN));
    const periodic = runs.length >= 3 && Math.max(...intervals) - Math.min(...intervals) <= 1;
    // Sesión desde la que se instaló la persistencia
    const session = ctx.events.filter(
      (e) => e.Event_ID === '4624' && e.User === user && e.Hostname === host && e._t <= list[0]._t && list[0]._t - e._t <= 10 * MIN
    );
    const masquerade = list.some((e) => /\\Microsoft\\Windows|Update|WinUpdate/i.test(e.Process_CommandLine));
    const mitre = [
      ...(list.some((e) => e.Event_ID === '4698') ? ['T1053.005'] : []),
      ...(list.some((e) => ['7045', '4697'].includes(e.Event_ID)) ? ['T1543.003'] : []),
      ...(masquerade ? ['T1036.004'] : []),
    ];
    addFinding(ctx, {
      rule: 'R-06',
      category: 'Comandos y procesos',
      short: 'Persistencia',
      plain: `se instaló en ${host} un programa que se ejecuta solo de forma periódica${masquerade ? ', disfrazado de actualización de Windows' : ''}, lo que permite al atacante volver a entrar`,
      title: `Persistencia en ${host}: ${list.map((e) => (e.Event_ID === '4698' ? 'tarea programada' : 'servicio')).join(' + ')} creados por ${user}`,
      baseLevel: 2,
      baseReason: 'Mecanismo de persistencia instalado y ejecutándose',
      factorOpts: { extra: masquerade ? ['Evasión (nombres que imitan componentes de Windows)'] : [] },
      mitre,
      keys: [`user:${user}`],
      evidence: [...session, ...list, ...runs],
      execHosts: [host],
      description:
        (session.length ? `${user} inicia sesión en ${host} desde ${session[0].Source_IP} (${session.map((e) => e.Log_ID).join(', ')}) y ` : `${user} `) +
        `crea en ${host} ${list.map((e) => `${e.Event_ID === '4698' ? 'la tarea' : 'el servicio'} "${e.Process_CommandLine}" (${e.Log_ID})`).join(' y ')}.` +
        (masquerade ? ' Los nombres imitan componentes legítimos de Windows Update para pasar desapercibidos.' : '') +
        (runs.length ? ` El binario ${artifacts.find((a) => /\.exe$/i.test(a)) || artifacts[0]} se ejecuta ${runs.length} veces (${runs.map((e) => hhmm(e.Timestamp)).join(', ')})` : '') +
        (periodic ? `, cada ${intervals[0]} minutos exactos: patrón compatible con un beacon de mando y control (hipótesis, no hay registro de red asociado).` : '.'),
      detection: 'R-06: creación de tarea (4698) o servicio (7045) con binario en ruta no estándar, seguida de ejecuciones (4688).',
      impact: 'El atacante mantiene acceso al servidor aunque se cambien las contraseñas.',
      actions: {
        investigar: [{ text: `Obtener ${artifacts.join(', ')} para análisis (hash, sandbox) y revisar conexiones de red de ${host}.`, owner: OWNERS.soc }],
        contener: [{ text: `Aislar ${host}; deshabilitar la tarea y el servicio; bloquear los hash en el EDR.`, owner: OWNERS.edr }],
        remediar: [
          { text: `Eliminar los artefactos persistentes y revisar la cuenta ${user} (origen de la creación).`, owner: OWNERS.infra },
          { text: 'Alertar en el SIEM ante cualquier 4698/7045 con binarios en ProgramData, Temp o Public.', owner: OWNERS.soc },
        ],
      },
    });
  }
}

const CMD_PATTERNS = [
  { re: /mimikatz|sekurlsa|procdump.*lsass|lsass\.dmp/i, label: 'volcado de credenciales', level: 3, mitre: ['T1003'] },
  { re: /vssadmin(\.exe)?\s+delete\s+shadows|wbadmin\s+delete|wmic\s+shadowcopy\s+delete|bcdedit.*recoveryenabled\s+no/i, label: 'borrado de copias de seguridad (shadow copies)', level: 3, mitre: ['T1490'] },
  { re: /wevtutil\s+cl|Clear-EventLog/i, label: 'borrado de registros', level: 3, mitre: ['T1070.001'] },
  { re: /-enc(odedcommand)?\b/i, label: 'PowerShell codificado', level: 2, mitre: ['T1059.001', 'T1027'] },
  { re: /\b(iex|invoke-expression|downloadstring|downloadfile)\b|-w(indowstyle)?\s+hidden/i, label: 'PowerShell de descarga u oculto', level: 2, mitre: ['T1059.001'] },
  { re: /\b(certutil|bitsadmin|mshta|rundll32|regsvr32)(\.exe)?\b/i, label: 'binario LOLBin', level: 2, mitre: ['T1218'] },
  { re: /\b(7z|7za|rar|tar|makecab)(\.exe)?\s+(a|-a|-c|-cf)\b|Compress-Archive/i, label: 'compresión de datos para extracción', level: 2, mitre: ['T1560.001'] },
  { re: /\\(ProgramData|Users\\Public|Temp)\\[^\\\s]+\.(exe|dll|ps1|bat|vbs)\b/i, label: 'ejecución desde ruta inusual', level: 2, mitre: ['T1036.005'] },
  { re: /\bwhoami\b/i, label: 'reconocimiento de identidad', level: 1, mitre: ['T1033'] },
  { re: /\bnet(\.exe)?\s+view\b|Get-SmbShare/i, label: 'descubrimiento de recursos compartidos', level: 1, mitre: ['T1135'] },
  { re: /\bnet(\.exe)?\s+(user|group|localgroup)\b|Get-LocalGroupMember|nltest/i, label: 'descubrimiento de cuentas y grupos', level: 1, mitre: ['T1087.001'] },
];

function ruleCommands(ctx) {
  const { cfg } = ctx;
  const hits = [];
  for (const e of ctx.events) {
    if (!['4688', '4104'].includes(e.Event_ID) || !free(ctx)(e)) continue;
    const text = `${e.Process_CommandLine} ${e.Event_ID === '4104' ? e.Event_Description : ''}`;
    const matched = CMD_PATTERNS.filter((p) => p.re.test(text));
    if (matched.length) hits.push({ e, matched });
  }
  for (const [user, list] of groupBy(hits, (h) => h.e.User)) {
    for (const group of splitByGap(list.map((h) => Object.assign(h, { _t: h.e._t })), cfg.commandGapMin * MIN)) {
      const evs = group.map((h) => h.e);
      const patterns = [...new Map(group.flatMap((h) => h.matched).map((p) => [p.label, p])).values()];
      const top = patterns.reduce((a, b) => (b.level > a.level ? b : a));
      const hosts = uniq(evs.map((e) => e.Hostname));
      const staging = patterns.some((p) => p.mitre.includes('T1560.001'));
      // Contexto de recolección: accesos a recursos compartidos justo antes de comprimir
      const collection = staging
        ? ctx.events.filter(
            (e) => ['5140', '5145'].includes(e.Event_ID) && free(ctx)(e) && e.User === user && /\\\\/.test(`${e.Destination}${e.Event_Description}`) && e._t <= evs[evs.length - 1]._t && evs[0]._t - e._t <= 15 * MIN
          )
        : [];
      addFinding(ctx, {
        rule: 'R-07',
        category: 'Comandos y procesos',
        short: staging && patterns.length === 1 ? 'Preparación de datos' : top.level === 3 ? 'Sabotaje / evasión' : 'Ejecución maliciosa',
        plain: patterns.some((p) => p.mitre.includes('T1490'))
          ? `en ${hosts.join(', ')} se ejecutaron comandos ocultos y se borraron las copias de recuperación de Windows, paso típico antes de un ataque de ransomware`
          : staging && patterns.length === 1
            ? `se comprimieron documentos en ${hosts.join(', ')} para sacarlos de la organización`
            : `en ${hosts.join(', ')} se ejecutaron comandos ocultos y de reconocimiento${staging ? ' y se empaquetaron datos para extraerlos' : ''}`,
        title: `Ejecución sospechosa en ${hosts.join(', ')} por ${user}: ${patterns.map((p) => p.label).join(', ')}`,
        baseLevel: top.level,
        baseReason: `Peor patrón observado: ${top.label}`,
        mitre: uniq([...patterns.flatMap((p) => p.mitre), ...(collection.length ? ['T1039'] : [])]),
        keys: [`user:${user}`, ...evs.map((e) => e.Source_IP).filter(isExternalIp).map((ip) => `ip:${ip}`)],
        evidence: [...evs, ...collection],
        execHosts: hosts,
        description:
          `${user} ejecuta en ${hosts.join(', ')}: ` +
          evs.map((e) => `"${e.Event_ID === '4104' ? e.Event_Description.replace(/^PowerShell Script Block:\s*/i, '') : e.Process_CommandLine}" (${e.Log_ID}, ${hhmm(e.Timestamp)})`).join('; ') +
          '.' +
          (collection.length ? ` Antes accede a ${uniq(collection.map((e) => e.Destination || e.Event_Description)).join(', ')} (${collection.map((e) => e.Log_ID).join(', ')}).` : '') +
          (patterns.some((p) => p.mitre.includes('T1490')) ? ' Eliminar las shadow copies impide recuperar archivos y es un paso habitual previo al cifrado por ransomware.' : '') +
          (patterns.some((p) => p.mitre.includes('T1027')) ? ' El contenido del comando codificado está oculto en el log: no puede determinarse qué ejecutó.' : ''),
        detection: `R-07: coincidencia con ${patterns.length} patrón(es) de comandos maliciosos en 4688/4104.`,
        impact: patterns.some((p) => p.mitre.includes('T1490'))
          ? 'Riesgo inminente de ransomware: sin copias de recuperación, un cifrado afectaría la disponibilidad de los datos.'
          : staging
            ? 'Datos preparados para ser sacados de la organización.'
            : 'Ejecución de código del atacante y reconocimiento del entorno.',
        actions: {
          investigar: [{ text: `Recuperar el script completo (Script Block Logging) y el árbol de procesos en ${hosts.join(', ')}.`, owner: OWNERS.soc }],
          contener: [
            { text: `Aislar ${hosts.join(', ')} mediante el EDR.`, owner: OWNERS.edr },
            { text: `Deshabilitar ${user} hasta concluir la investigación.`, owner: OWNERS.iam },
          ],
          remediar: [
            ...(patterns.some((p) => p.mitre.includes('T1490')) ? [{ text: 'Verificar copias de seguridad fuera de línea e inmutables; restringir vssadmin a administradores de backup.', owner: OWNERS.infra }] : []),
            { text: 'Bloquear PowerShell codificado mediante AMSI/Constrained Language Mode y reglas ASR.', owner: OWNERS.edr },
          ],
        },
      });
    }
  }
}

function ruleEscalation(ctx) {
  const changes = ctx.events.filter((e) => ['4720', '4722', '4728', '4732', '4756', '4738'].includes(e.Event_ID));
  for (const [user, list] of groupBy(changes, (e) => e.User)) {
    addFinding(ctx, {
      rule: 'R-08',
      category: 'Escalamiento',
      short: 'Cambio de privilegios',
      plain: `se modificaron cuentas o grupos de seguridad (${user})`,
      title: `Creación o modificación de cuentas/grupos por ${user}`,
      baseLevel: 2,
      baseReason: 'Cambio en cuentas o grupos de seguridad',
      mitre: ['T1098'],
      keys: [`user:${user}`],
      evidence: list,
      description: `${user} realiza cambios de cuentas o grupos: ${list.map((e) => `${e.Event_ID} ${e.Event_Description} (${e.Log_ID})`).join('; ')}.`,
      detection: 'R-08: eventos 4720/4722/4728/4732/4756/4738.',
      impact: 'Posible persistencia o elevación de privilegios en el dominio.',
      actions: {
        investigar: [{ text: 'Validar con el área responsable si el cambio estaba autorizado.', owner: OWNERS.iam }],
        contener: [{ text: 'Revertir el cambio si no está autorizado.', owner: OWNERS.iam }],
        remediar: [{ text: 'Alertar ante cambios en grupos privilegiados.', owner: OWNERS.soc }],
      },
    });
  }
  const privs = ctx.events.filter((e) => e.Event_ID === '4672' && free(ctx)(e) && !ctx.isPrivileged(e.User));
  for (const [user, list] of groupBy(privs, (e) => e.User)) {
    const lookalikeHosts = uniq(list.map((e) => e.Hostname)).filter((h) => ctx.lookalikeHosts.has(h));
    addFinding(ctx, {
      rule: 'R-08',
      category: 'Escalamiento',
      short: 'Privilegios en cuenta no administrativa',
      plain: `la cuenta ${user} recibió privilegios de administración sin estar autorizada para ello`,
      title: `Privilegios especiales (4672) asignados a ${user}, que no figura como cuenta administrativa`,
      baseLevel: 1,
      baseReason: 'Anomalía de privilegios sin evidencia de uso malicioso',
      mitre: ['T1078.002'],
      keys: [`user:${user}`, ...lookalikeHosts.map((h) => `host:${h}`)],
      evidence: list,
      description: `${user} recibe privilegios especiales en ${uniq(list.map((e) => e.Hostname)).join(', ')} (${list.map((e) => e.Log_ID).join(', ')}) sin pertenecer a la lista de cuentas privilegiadas configurada. No se observan comandos maliciosos asociados.`,
      detection: 'R-08: 4672 para una cuenta fuera de la lista de cuentas privilegiadas.',
      impact: 'Posible exceso de permisos o uso indebido de una cuenta.',
      actions: {
        investigar: [{ text: `Confirmar la pertenencia de ${user} a grupos administrativos y si esos privilegios están justificados.`, owner: OWNERS.iam }],
        contener: [{ text: 'Retirar privilegios no justificados.', owner: OWNERS.iam }],
        remediar: [{ text: 'Revisión trimestral de grupos privilegiados (mínimo privilegio).', owner: OWNERS.iam }],
      },
    });
  }
}

function ruleMassAccess(ctx) {
  const { cfg } = ctx;
  const access = ctx.events.filter((e) => e.Event_ID === '4663' && free(ctx)(e));
  for (const [, list] of groupBy(access, (e) => `${e.User}|${e.Hostname}`)) {
    const best = bestWindow(list, cfg.massAccessWindowMin * MIN);
    if (!best || best.score < cfg.massAccessMin) continue;
    const burst = best.slice;
    const { User: user, Hostname: host } = burst[0];
    const shares = ctx.events.filter(
      (e) => ['5140', '5145'].includes(e.Event_ID) && free(ctx)(e) && e.User === user && e.Hostname === host && Math.abs(e._t - burst[burst.length - 1]._t) <= 10 * MIN && /\\\\/.test(e.Destination)
    );
    const folders = uniq(burst.map((e) => (e.Process_CommandLine.match(/File access:\s*(.+)\\[^\\]+$/) || [])[1]));
    const secs = Math.round((burst[burst.length - 1]._t - burst[0]._t) / 1000);
    addFinding(ctx, {
      rule: 'R-09',
      category: 'Otras anomalías',
      short: 'Recolección masiva de archivos',
      plain: `se leyeron ${burst.length} archivos de ${folders.join(', ') || host} en pocos minutos de forma automatizada`,
      title: `Acceso masivo a ${plural(burst.length, 'archivo', 'archivos')} de ${folders.join(', ') || host} por ${user}`,
      baseLevel: 2,
      baseReason: 'Recolección automatizada de datos sensibles',
      mitre: ['T1039'],
      keys: [`user:${user}`],
      evidence: [...burst, ...shares],
      description: `${user} abre ${burst.length} archivos de ${folders.join(', ')} en ${host} en ${secs} s (uno cada ~${avgIntervalSec(burst)} s), ritmo propio de un script y no de una persona.${shares.length ? ` Se registra además acceso al recurso ${uniq(shares.map((e) => e.Destination)).join(', ')} (${shares.map((e) => e.Log_ID).join(', ')}).` : ''}`,
      detection: `R-09: ${burst.length} eventos 4663 en ${cfg.massAccessWindowMin} min (umbral ${cfg.massAccessMin}).`,
      impact: 'Exposición de información financiera; patrón compatible con recolección previa a exfiltración o cifrado.',
      actions: {
        investigar: [{ text: `Determinar si los archivos fueron copiados o modificados y desde qué equipo actuó ${user}.`, owner: OWNERS.soc }],
        contener: [{ text: `Retirar a ${user} el acceso al recurso y deshabilitar la cuenta.`, owner: OWNERS.iam }],
        remediar: [{ text: 'Restringir el acceso de cuentas de servicio a recursos de negocio; activar alertas por volumen en el servidor de archivos.', owner: OWNERS.infra }],
      },
    });
  }
}

function ruleExfil(ctx) {
  const { cfg } = ctx;
  const proxy = ctx.events.filter((e) => /bytes_out=\d+/.test(e.Process_CommandLine));
  for (const [, list] of groupBy(proxy, (e) => `${e.User}|${e.Destination}`)) {
    const bytes = list.reduce((s, e) => s + Number(e.Process_CommandLine.match(/bytes_out=(\d+)/)[1]), 0);
    if (bytes < cfg.exfilMinMB * 1e6) continue;
    const { User: user, Destination: dest, Hostname: host } = list[0];
    ctx.exfilBytes += bytes;
    addFinding(ctx, {
      rule: 'R-10',
      category: 'Otras anomalías',
      short: 'Exfiltración',
      plain: `se enviaron ${fmtMB(bytes)} de información a un servidor externo (${destIp(dest)})`,
      title: `Exfiltración de ${fmtMB(bytes)} desde ${host} hacia ${dest} (${user})`,
      baseLevel: 3,
      baseReason: 'Exfiltración de datos confirmada por volumen transferido',
      mitre: ['T1048', 'T1567'],
      keys: [`user:${user}`, `ip:${destIp(dest)}`],
      evidence: list,
      bytes,
      description: `${list.length} peticiones HTTPS POST desde ${host} hacia ${dest} entre ${hhmm(list[0].Timestamp)} y ${hhmm(list[list.length - 1].Timestamp)}, con ${fmtMB(bytes)} enviados en total (${list.map((e) => e.Log_ID).slice(0, 3).join(', ')} … ${list[list.length - 1].Log_ID}).`,
      detection: `R-10: suma de bytes_out a un mismo destino ${fmtMB(bytes)} ≥ umbral ${cfg.exfilMinMB} MB.`,
      impact: 'Pérdida de confidencialidad confirmada: posible obligación de notificación regulatoria y daño reputacional.',
      actions: {
        investigar: [
          { text: `Identificar exactamente qué archivos se enviaron a ${dest} (proxy con inspección TLS, DLP).`, owner: OWNERS.soc },
          { text: `Determinar si ${user} actuó por su cuenta (insider) o con su cuenta comprometida.`, owner: OWNERS.legal },
        ],
        contener: [
          { text: `Bloquear ${destIp(dest)} en proxy y firewall.`, owner: OWNERS.net },
          { text: `Aislar ${host} y suspender la cuenta ${user}.`, owner: OWNERS.edr },
        ],
        remediar: [
          { text: 'Implantar DLP y alertas por volumen de subida a destinos no categorizados.', owner: OWNERS.net },
          { text: 'Evaluar obligaciones legales de notificación de la fuga.', owner: OWNERS.legal },
        ],
      },
    });
  }
  const outbound = ctx.events.filter(
    (e) => free(ctx)(e) && isExternalIp(destIp(e.Destination)) && /outbound|permitted|allowed/i.test(e.Event_Description) && /powershell|cmd\.exe|wscript|cscript|rundll32|mshta/i.test(`${e.Event_Description} ${e.Process_CommandLine}`)
  );
  for (const [, list] of groupBy(outbound, (e) => `${e.User}|${e.Destination}`)) {
    const { User: user, Destination: dest, Hostname: host } = list[0];
    addFinding(ctx, {
      rule: 'R-10',
      category: 'Otras anomalías',
      short: 'Conexión saliente sospechosa',
      plain: `el servidor ${host} abrió una conexión hacia Internet (${destIp(dest)}), posible salida de datos`,
      title: `Conexión saliente de PowerShell desde ${host} hacia ${dest} (${user})`,
      baseLevel: 2,
      baseReason: 'Intérprete de comandos conectando con Internet',
      factorOpts: { extra: ['Destino externo'] },
      mitre: ['T1071.001', 'T1041'],
      keys: [`user:${user}`, `ip:${destIp(dest)}`],
      evidence: list,
      description: `El firewall permite una conexión saliente de ${list[0].Event_Description.match(/process=([\w.]+)/i)?.[1] || 'un intérprete'} desde ${host} hacia ${dest} (${list.map((e) => e.Log_ID).join(', ')}). Hipótesis: canal de exfiltración o C2; el log no registra el volumen transferido.`,
      detection: 'R-10: conexión saliente permitida a IP pública iniciada por un intérprete de comandos.',
      impact: 'Posible salida de datos o control remoto del equipo.',
      actions: {
        investigar: [{ text: `Revisar en el firewall/NetFlow el volumen enviado a ${dest}.`, owner: OWNERS.net }],
        contener: [{ text: `Bloquear ${destIp(dest)} y aislar ${host}.`, owner: OWNERS.net }],
        remediar: [{ text: 'Denegar por defecto la salida a Internet desde servidores; solo vía proxy autenticado.', owner: OWNERS.net }],
      },
    });
  }
}

function ruleLookalike(ctx, quality) {
  const count = (field, v) => ctx.events.filter((e) => e[field] === v).length;
  const suspicious = (pairs, field) =>
    pairs.map(([a, b]) => ({ legit: count(field, a) >= count(field, b) ? a : b, odd: count(field, a) >= count(field, b) ? b : a }));
  const hosts = suspicious(quality.lookalikeHosts, 'Hostname');
  const users = suspicious(quality.lookalikeUsers, 'User');
  hosts.forEach((h) => ctx.lookalikeHosts.add(h.odd));
  users.forEach((u) => ctx.lookalikeUsers.add(u.odd));
  return { hosts, users };
}

function addLookalikeFinding(ctx, { hosts, users }) {
  if (!hosts.length && !users.length) return;
  const evidence = ctx.events.filter((e) => free(ctx)(e) && (ctx.lookalikeHosts.has(e.Hostname) || ctx.lookalikeUsers.has(e.User)));
  if (!evidence.length) return;
  const ips = Object.entries(evidence.reduce((acc, e) => ((acc[e.Source_IP] = (acc[e.Source_IP] || 0) + 1), acc), {})).sort((a, b) => b[1] - a[1]);
  const pairs = [...hosts, ...users].map((p) => `${p.odd} (frente a ${p.legit})`);
  addFinding(ctx, {
    rule: 'R-11',
    category: 'Otras anomalías',
    short: 'Nombres suplantados (hipótesis)',
    plain: `aparecen equipos o cuentas con nombres casi idénticos a los legítimos (${[...hosts, ...users].map((p) => p.odd).join(', ')}), pendientes de verificar`,
    title: `Equipos/cuentas con nombres casi idénticos a los legítimos: ${pairs.join(', ')}`,
    baseLevel: 1,
    baseReason: 'Anomalía que requiere investigación',
    status: 'hypothesis',
    mitre: ['T1036.005'],
    keys: [...[...ctx.lookalikeHosts].map((h) => `host:${h}`), ...[...ctx.lookalikeUsers].map((u) => `user:${u}`)],
    evidence,
    description:
      `Aparecen ${pairs.join(' y ')} con ${evidence.length} eventos entre ${hhmm(evidence[0].Timestamp)} y ${hhmm(evidence[evidence.length - 1].Timestamp)}, ` +
      `principalmente desde ${ips.slice(0, 2).map(([ip, n]) => `${ip} (${n})`).join(', ')}. La actividad registrada es benigna (explorer, notepad, svchost), pero incluye privilegios especiales. ` +
      'Puede tratarse de un error de normalización de nombres en el SIEM o de equipos/cuentas creados para camuflarse. Para confirmarlo se necesita el inventario de Active Directory y de la CMDB.',
    detection: 'R-11: nombre normalizado idéntico o anagrama de otro equipo/cuenta; se marca como sospechoso el de menor actividad.',
    impact: 'Si fueran suplantados, un atacante tendría un equipo o una cuenta camuflada dentro del dominio.',
    actions: {
      investigar: [{ text: `Verificar en AD/CMDB la existencia y propietario de ${[...hosts, ...users].map((p) => p.odd).join(', ')}.`, owner: OWNERS.iam }],
      contener: [{ text: 'Si no constan en el inventario, deshabilitar la cuenta y aislar el equipo.', owner: OWNERS.iam }],
      remediar: [{ text: 'Normalizar los nombres en el SIEM y alertar ante altas de equipos/cuentas con nombres similares a activos críticos.', owner: OWNERS.soc }],
    },
  });
}

function ruleLogClear(ctx) {
  const list = ctx.events.filter((e) => ['1102', '104'].includes(e.Event_ID));
  if (!list.length) return;
  addFinding(ctx, {
    rule: 'R-12',
    category: 'Otras anomalías',
    short: 'Borrado de registros',
    plain: 'se borraron registros de auditoría para ocultar rastros',
    title: `Borrado de registros de auditoría en ${uniq(list.map((e) => e.Hostname)).join(', ')}`,
    baseLevel: 3,
    baseReason: 'Evasión: eliminación de evidencias',
    mitre: ['T1070.001'],
    keys: uniq(list.map((e) => `user:${e.User}`)),
    evidence: list,
    description: `Se borran registros de auditoría (${list.map((e) => e.Log_ID).join(', ')}).`,
    detection: 'R-12: eventos 1102/104.',
    impact: 'Pérdida de trazabilidad.',
    actions: {
      investigar: [{ text: 'Recuperar logs desde el SIEM o reenviadores.', owner: OWNERS.soc }],
      contener: [{ text: 'Aislar el equipo afectado.', owner: OWNERS.edr }],
      remediar: [{ text: 'Enviar logs en tiempo real a un almacenamiento inmutable.', owner: OWNERS.soc }],
    },
  });
}

function ruleNoise(ctx) {
  const { cfg } = ctx;
  const fails = ctx.events.filter((e) => e.Event_ID === '4625' && free(ctx)(e));
  if (fails.length) {
    const byUser = groupBy(fails, (e) => e.User);
    const maxWin = Math.max(...[...groupBy(fails, (e) => `${e.User}|${e.Source_IP}`).values()].map((l) => bestWindow(l, cfg.bruteWindowMin * MIN).score));
    addFinding(ctx, {
      rule: 'R-02',
      category: 'Fuerza bruta',
      short: 'Ruido',
      title: `${fails.length} fallos de autenticación internos dispersos (probable falso positivo)`,
      baseLevel: 0,
      baseReason: 'Fallos aislados de contraseña de bajo impacto',
      status: 'fp',
      mitre: [],
      keys: [],
      evidence: fails,
      consume: false,
      description: `${fails.length} eventos 4625 desde IPs internas repartidos entre ${byUser.size} cuentas a lo largo de toda la jornada. Ningún par usuario+IP supera ${maxWin} fallos en ${cfg.bruteWindowMin} min (umbral ${cfg.bruteMinFailures}) ni hay ráfagas: corresponde a errores de contraseña habituales.`,
      detection: 'Descartado por R-01/R-02: no alcanza los umbrales de fuerza bruta.',
      impact: 'Ninguno relevante.',
      actions: { investigar: [], contener: [], remediar: [] },
    });
  }
  const access = ctx.events.filter((e) => e.Event_ID === '4663' && free(ctx)(e));
  if (access.length) {
    addFinding(ctx, {
      rule: 'R-09',
      category: 'Otras anomalías',
      short: 'Ruido',
      title: `${access.length} accesos a objetos aislados (actividad normal)`,
      baseLevel: 0,
      baseReason: 'Accesos puntuales sin patrón masivo',
      status: 'fp',
      mitre: [],
      keys: [],
      evidence: access,
      consume: false,
      description: `${access.length} eventos 4663 repartidos entre equipos y usuarios sin concentración temporal: no alcanzan el umbral de ${cfg.massAccessMin} en ${cfg.massAccessWindowMin} min.`,
      detection: 'Descartado por R-09.',
      impact: 'Ninguno relevante.',
      actions: { investigar: [], contener: [], remediar: [] },
    });
  }
}

// ── Correlación en incidentes ───────────────────────────────────────────────
const CIA_RULES = {
  'R-01': { C: 2, I: 1, D: 1 },
  'R-02': { C: 2, I: 1, D: 0 },
  'R-03': { C: 2, I: 1, D: 0 },
  'R-04': { C: 2, I: 1, D: 0 },
  'R-05': { C: 2, I: 2, D: 1 },
  'R-06': { C: 1, I: 2, D: 1 },
  'R-07': { C: 1, I: 2, D: 1 },
  'R-08': { C: 1, I: 1, D: 0 },
  'R-09': { C: 3, I: 1, D: 0 },
  'R-10': { C: 3, I: 0, D: 0 },
  'R-11': { C: 1, I: 1, D: 0 },
  'R-12': { C: 1, I: 3, D: 1 },
};
const CIA_LABEL = ['Nulo', 'Bajo', 'Medio', 'Alto'];

function incidentImpact(findings) {
  const cia = { C: 0, I: 0, D: 0 };
  for (const f of findings) {
    const r = CIA_RULES[f.rule] || {};
    for (const k of ['C', 'I', 'D']) cia[k] = Math.max(cia[k], r[k] || 0);
    if (f.mitre.includes('T1490')) cia.D = 3;
    if (f.mitre.includes('T1505.003') || f.rule === 'R-06') cia.I = 3;
  }
  const confirmedExfil = findings.some((f) => f.rule === 'R-10' && f.baseLevel === 3);
  const external = findings.some((f) => f.externalIps.length);
  const crit = findings.some((f) => f.factors.some((x) => x.startsWith('Activo crítico')));
  return {
    confidencialidad: CIA_LABEL[cia.C],
    integridad: CIA_LABEL[cia.I],
    disponibilidad: CIA_LABEL[cia.D],
    operacion: cia.D >= 3 ? 'Alto' : crit ? 'Medio' : 'Bajo',
    reputacion: confirmedExfil ? 'Alto' : external ? 'Medio' : 'Bajo',
  };
}

function correlate(ctx) {
  const { cfg } = ctx;
  const active = ctx.findings.filter((f) => f.status !== 'fp');
  const parent = active.map((_, i) => i);
  const find = (i) => (parent[i] === i ? i : (parent[i] = find(parent[i])));
  const gap = cfg.correlationGapMin * MIN;
  for (let i = 0; i < active.length; i++) {
    for (let j = i + 1; j < active.length; j++) {
      const a = active[i];
      const b = active[j];
      const shared = a.keys.filter((k) => b.keys.includes(k));
      const distance = Math.max(0, Math.max(a._start, b._start) - Math.min(a._end, b._end));
      if (shared.length && distance <= gap) parent[find(i)] = find(j);
    }
  }
  const groups = [...groupBy(active.map((f, i) => ({ f, root: find(i) })), (x) => x.root).values()].map((g) =>
    g.map((x) => x.f).sort((a, b) => a._start - b._start)
  );
  groups.sort((a, b) => a[0]._start - b[0]._start);

  let nInc = 0;
  let nAn = 0;
  const incidents = groups.map((findings) => {
    const anomaly = findings.every((f) => f.status === 'hypothesis' || levelIndex(f.level) <= 1) && findings.some((f) => f.status === 'hypothesis');
    const id = anomaly ? `AN-${String(++nAn).padStart(2, '0')}` : `INC-${String(++nInc).padStart(2, '0')}`;
    const level = LEVELS[Math.max(...findings.map((f) => levelIndex(f.level)))];
    const evidence = [...new Map(findings.flatMap((f) => f.evidence).map((e) => [e.Log_ID, e])).values()].sort((a, b) => a._t - b._t);
    const externalIps = uniq(findings.flatMap((f) => f.externalIps));
    const users = uniq(findings.flatMap((f) => f.users));
    const sourceIps = uniq(evidence.map((e) => e.Source_IP).filter(isExternalIp));
    const actor = sourceIps.length ? sourceIps[0] : findings[0].users[0];
    const shorts = uniq(findings.map((f) => f.short));
    const mitre = uniq(findings.flatMap((f) => f.mitre));
    return {
      id,
      type: anomaly ? 'anomaly' : 'incident',
      title: `${actor}: ${shorts.join(' → ')}`,
      level,
      findings,
      evidence,
      start: evidence[0].Timestamp,
      end: evidence[evidence.length - 1].Timestamp,
      _start: evidence[0]._t,
      _end: evidence[evidence.length - 1]._t,
      hosts: uniq(findings.flatMap((f) => f.hosts)),
      users,
      externalIps,
      execHosts: uniq(findings.flatMap((f) => f.execHosts)),
      mitre,
      tactics: TACTIC_ORDER.filter((t) => mitre.some((m) => MITRE[m]?.tactic === t)),
      keys: uniq(findings.flatMap((f) => f.keys)),
      impact: incidentImpact(findings),
    };
  });

  // Asignar ID a hallazgos (en orden de incidente) y relaciones entre incidentes
  let n = 0;
  for (const inc of incidents) for (const f of inc.findings) (f.id = `H-${String(++n).padStart(2, '0')}`), (f.incidentId = inc.id);
  for (const f of ctx.findings.filter((x) => x.status === 'fp')) f.id = `FP-${String(++n).padStart(2, '0')}`;

  for (const inc of incidents) {
    const others = incidents.filter((o) => o !== inc);
    inc.related = others
      .map((o) => ({ id: o.id, hosts: inc.execHosts.filter((h) => o.execHosts.includes(h)) }))
      .filter((r) => r.hosts.length);
    inc.rationale =
      `Agrupa ${plural(inc.findings.length, 'hallazgo', 'hallazgos')} que comparten ${describeKeys(inc.keys)} en una ventana continua (${hhmm(inc.start)}–${hhmm(inc.end)}). ` +
      `Se separa del resto porque ningún otro incidente comparte ese origen o esas cuentas en un intervalo de ${cfg.correlationGapMin} min.` +
      (inc.related.length
        ? ` Hipótesis: comparte equipo comprometido (${inc.related.map((r) => `${r.hosts.join(', ')} con ${r.id}`).join('; ')}); con los registros disponibles no puede afirmarse que sea el mismo actor.`
        : '');
  }
  return incidents;
}

function describeKeys(keys) {
  const ips = keys.filter((k) => k.startsWith('ip:')).map((k) => k.slice(3));
  const users = keys.filter((k) => k.startsWith('user:')).map((k) => k.slice(5));
  const hosts = keys.filter((k) => k.startsWith('host:')).map((k) => k.slice(5));
  return [ips.length && `IP ${ips.join(', ')}`, users.length && `cuenta(s) ${users.join(', ')}`, hosts.length && `equipo(s) ${hosts.join(', ')}`]
    .filter(Boolean)
    .join(' y ');
}

// ── Punto de entrada ────────────────────────────────────────────────────────
export function runAnalysis(dataset, cfg = DEFAULT_CONFIG) {
  const events = dataset.events;
  const lc = (list) => list.map((x) => x.toLowerCase());
  const priv = new Set(lc(cfg.privilegedAccounts));
  const svc = new Set(lc(cfg.serviceAccounts));
  const crit = new Set(lc(cfg.criticalAssets));
  const ctx = {
    cfg,
    events,
    consumed: new Set(),
    findings: [],
    sprayIps: new Set(),
    bruteSuccess: new Set(),
    lookalikeHosts: new Set(),
    lookalikeUsers: new Set(),
    exfilBytes: 0,
    isPrivileged: (u) => priv.has(String(u).toLowerCase()),
    isService: (u) => svc.has(String(u).toLowerCase()) || /\\(svc|service)|svc$/i.test(u),
    isCritical: (h) => crit.has(String(h).toLowerCase()),
  };

  const lookalikes = ruleLookalike(ctx, dataset.quality);
  ruleSpray(ctx);
  ruleBrute(ctx);
  ruleLogins(ctx);
  ruleLateral(ctx);
  ruleWeb(ctx);
  rulePersistence(ctx);
  ruleCommands(ctx);
  ruleMassAccess(ctx);
  ruleExfil(ctx);
  ruleLogClear(ctx);
  ruleEscalation(ctx);
  addLookalikeFinding(ctx, lookalikes);
  ruleNoise(ctx);

  const incidents = correlate(ctx);
  const findings = incidents.flatMap((i) => i.findings);
  const discarded = ctx.findings.filter((f) => f.status === 'fp');

  // Criticidad del analista por evento (máxima de los hallazgos que lo citan)
  const eventLevel = new Map();
  const eventFinding = new Map();
  for (const f of findings) {
    for (const e of f.evidence) {
      if (!eventLevel.has(e.Log_ID) || levelIndex(f.level) > levelIndex(eventLevel.get(e.Log_ID))) eventLevel.set(e.Log_ID, f.level);
      if (!eventFinding.has(e.Log_ID)) eventFinding.set(e.Log_ID, []);
      eventFinding.get(e.Log_ID).push(f.id);
    }
  }

  const ruleStats = RULES.map((r) => ({
    ...r,
    threshold: r.threshold(cfg),
    findings: findings.filter((f) => f.rule === r.id).length,
    events: uniq(findings.filter((f) => f.rule === r.id).flatMap((f) => f.evidence.map((e) => e.Log_ID))).length,
  }));
  const categoryStats = CATEGORIES.map((c) => ({
    category: c,
    findings: findings.filter((f) => f.category === c),
    justification:
      findings.some((f) => f.category === c)
        ? null
        : 'Sin evidencia en los registros: ninguna regla de esta categoría alcanzó su umbral.',
  }));

  const real = incidents.filter((i) => i.type === 'incident');
  const globalLevel = incidents.length ? LEVELS[Math.max(...incidents.map((i) => levelIndex(i.level)))] : 'Bajo';

  return {
    config: cfg,
    incidents,
    findings,
    discarded,
    eventLevel,
    eventFinding,
    ruleStats,
    categoryStats,
    globalLevel,
    stats: {
      totalEvents: events.length,
      suspiciousEvents: eventLevel.size,
      incidents: real.length,
      anomalies: incidents.length - real.length,
      findings: findings.length,
      byLevel: Object.fromEntries(LEVELS.map((l) => [l, findings.filter((f) => f.level === l).length])),
      affectedHosts: uniq(findings.flatMap((f) => f.hosts)),
      affectedUsers: uniq(findings.flatMap((f) => f.users)),
      externalIps: uniq(findings.flatMap((f) => f.externalIps)),
      exfilBytes: ctx.exfilBytes,
    },
  };
}
