import { useEffect, useLayoutEffect, useMemo, useRef, useState } from 'react';
import { AnimatePresence, motion } from 'framer-motion';
import { apiFetch } from '../api.js';
import LevelBadge from '../components/LevelBadge.jsx';
import { MITRE } from '../lib/mitre.js';
import {
  PHASE_LABEL,
  actionPlan,
  buildAiContext,
  consolidatedTimeline,
  defaultNarrative,
  evidenceExtract,
  extractIocs,
  mitreMapping,
  narrativeFromAi,
  plainSummary,
  unknownLogIds,
  urgentActions,
} from '../lib/report.js';

const hhmm = (ts) => ts.slice(11, 19);

export default function Report({ dataset, analysis, narratives, setNarratives, meta, setMeta, audience, setAudience, nav }) {
  const narrative = narratives[audience];
  const [busy, setBusy] = useState(false);
  const [aiError, setAiError] = useState('');
  const [aiStatus, setAiStatus] = useState(null);
  const unknown = useMemo(() => unknownLogIds(narrative, dataset), [narrative, dataset]);

  useEffect(() => {
    apiFetch('/api/ai/status').then(setAiStatus).catch(() => setAiStatus(null));
  }, []);

  const update = (patch) => setNarratives((n) => ({ ...n, [audience]: { ...n[audience], ...patch, edited: true } }));
  const updateIncident = (id, patch) => update({ incidentes: { ...narrative.incidentes, [id]: { ...narrative.incidentes[id], ...patch } } });

  async function draftWithAi() {
    setBusy(true);
    setAiError('');
    try {
      const res = await apiFetch('/api/ai/narrative', {
        method: 'POST',
        body: JSON.stringify({ audience, context: buildAiContext(dataset, analysis) }),
      });
      const merged = narrativeFromAi(res.narrative, defaultNarrative(dataset, analysis));
      setNarratives((n) => ({ ...n, [audience]: { ...merged, source: 'ia', model: res.model, edited: false } }));
      if (res.unknownIds?.length) setAiError(`La IA citó Log_ID que no se le enviaron: ${res.unknownIds.join(', ')}. Revíselos antes de exportar.`);
    } catch (err) {
      setAiError(err.message);
      if (err.status === 401) nav.logout();
    } finally {
      setBusy(false);
    }
  }

  function resetTemplate() {
    setNarratives((n) => ({ ...n, [audience]: defaultNarrative(dataset, analysis) }));
    setAiError('');
  }

  return (
    <div className="page report-page">
      <div className="report-toolbar card">
        <div className="seg big">
          {['ejecutivo', 'tecnico'].map((a) => (
            <button key={a} className={audience === a ? 'active' : ''} onClick={() => setAudience(a)}>
              {a === 'ejecutivo' ? 'Informe ejecutivo' : 'Informe técnico'}
            </button>
          ))}
        </div>
        <div className="toolbar-right">
          <span className={`chip ${aiStatus?.configured ? '' : 'warn'}`} title="Modelo de IA configurado en el servidor">
            <span className={`dot ${aiStatus?.configured ? 'ok' : 'off'}`} /> IA: {aiStatus?.model || '—'}
            {aiStatus && !aiStatus.configured && ' (sin clave)'}
          </span>
          <button className="btn btn-primary" onClick={draftWithAi} disabled={busy}>
            {busy ? <span className="spinner" /> : '✦ Redactar con IA'}
          </button>
          <button className="btn btn-ghost" onClick={resetTemplate} disabled={busy}>
            Restablecer plantilla
          </button>
          <button className="btn btn-ghost" onClick={() => nav.go('export')}>
            Exportar PDF →
          </button>
        </div>
      </div>

      <AnimatePresence>
        {aiError && (
          <motion.div className="alert alert-error" initial={{ opacity: 0, y: -6 }} animate={{ opacity: 1, y: 0 }} exit={{ opacity: 0 }}>
            {aiError}
          </motion.div>
        )}
      </AnimatePresence>
      {unknown.length > 0 && (
        <div className="alert alert-error">
          <strong>Validación de evidencias:</strong> el texto cita Log_ID que no existen en el archivo: {unknown.join(', ')}. Corríjalos antes de exportar.
        </div>
      )}
      <div className="alert alert-info">
        Origen del texto: <b>{narrative.source === 'ia' ? `IA (${narrative.model})` : 'plantilla determinista'}</b>
        {narrative.edited && ' · editado por el analista'}. Los bloques con borde punteado son editables; revise todo el contenido
        antes de exportar.
      </div>

      <MetaForm meta={meta} setMeta={setMeta} />

      <AnimatePresence mode="wait">
        <motion.article key={audience} className="paper" initial={{ opacity: 0, y: 14 }} animate={{ opacity: 1, y: 0 }} exit={{ opacity: 0, y: -8 }}>
          <header className="paper-cover">
            <small>VIGÍA · {meta.clasificacion}</small>
            <h1>{audience === 'ejecutivo' ? 'Informe ejecutivo de incidentes de seguridad' : 'Informe técnico de investigación de incidentes'}</h1>
            <p>
              {meta.cliente} · {meta.fecha} · Analista: {[meta.nombre, meta.apellido].filter(Boolean).join(' ') || meta.analista}
            </p>
            <div className="cover-risk">
              Riesgo global <LevelBadge level={analysis.globalLevel} />
            </div>
          </header>
          {audience === 'ejecutivo' ? (
            <Executive analysis={analysis} n={narrative} update={update} updateIncident={updateIncident} />
          ) : (
            <Technical dataset={dataset} analysis={analysis} n={narrative} update={update} updateIncident={updateIncident} nav={nav} />
          )}
        </motion.article>
      </AnimatePresence>
    </div>
  );
}

function MetaForm({ meta, setMeta }) {
  const field = (key, label, type = 'text') => (
    <label className="field compact">
      <span>{label}</span>
      <input className="input" type={type} value={meta[key]} onChange={(e) => setMeta({ ...meta, [key]: e.target.value })} />
    </label>
  );
  return (
    <details className="card meta-form">
      <summary>Datos de portada (cliente, analista, fecha)</summary>
      <div className="meta-grid">
        {field('cliente', 'Cliente')}
        {field('consultora', 'Elaborado por')}
        {field('nombre', 'Nombre del analista')}
        {field('apellido', 'Apellido del analista')}
        {field('fecha', 'Fecha', 'date')}
        {field('clasificacion', 'Clasificación')}
      </div>
    </details>
  );
}

function Editable({ value, onChange, className = '' }) {
  const ref = useRef(null);
  useLayoutEffect(() => {
    if (ref.current) {
      ref.current.style.height = 'auto';
      ref.current.style.height = `${ref.current.scrollHeight + 2}px`;
    }
  }, [value]);
  return <textarea ref={ref} className={`editable ${className}`} value={value} onChange={(e) => onChange(e.target.value)} spellCheck />;
}

function Section({ n, title, children }) {
  return (
    <section className="paper-section">
      <h2>
        {n && <span className="sec-n">{n}</span>}
        {title}
      </h2>
      {children}
    </section>
  );
}

function ImpactTable({ analysis }) {
  return (
    <table className="data paper-table">
      <thead>
        <tr>
          <th>Incidente</th>
          <th>Confidencialidad</th>
          <th>Integridad</th>
          <th>Disponibilidad</th>
          <th>Operación</th>
          <th>Reputación</th>
        </tr>
      </thead>
      <tbody>
        {analysis.incidents.map((i) => (
          <tr key={i.id}>
            <td className="mono">{i.id}</td>
            {['confidencialidad', 'integridad', 'disponibilidad', 'operacion', 'reputacion'].map((k) => (
              <td key={k} className={`impact ${i.impact[k]}`}>
                {i.impact[k]}
              </td>
            ))}
          </tr>
        ))}
      </tbody>
    </table>
  );
}

function Executive({ analysis, n, update, updateIncident }) {
  return (
    <>
      <Section title="Resumen ejecutivo">
        <Editable value={n.resumen_ejecutivo} onChange={(v) => update({ resumen_ejecutivo: v })} />
      </Section>
      <Section title="Nivel de riesgo global">
        <div className="risk-box">
          <LevelBadge level={analysis.globalLevel} />
          <Editable value={n.valoracion_riesgo} onChange={(v) => update({ valoracion_riesgo: v })} />
        </div>
      </Section>
      <Section title="Incidentes identificados">
        <table className="data paper-table">
          <thead>
            <tr>
              <th>ID</th>
              <th>Qué ocurrió</th>
              <th>Criticidad</th>
              <th>Hora</th>
            </tr>
          </thead>
          <tbody>
            {analysis.incidents.map((i) => (
              <tr key={i.id}>
                <td className="mono">{i.id}</td>
                <td>{plainSummary(i)}</td>
                <td>
                  <LevelBadge level={i.level} small />
                </td>
                <td className="mono small">
                  {hhmm(i.start)}–{hhmm(i.end)}
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </Section>
      <Section title="Impacto en el negocio">
        <ImpactTable analysis={analysis} />
        {analysis.incidents.map((i) => (
          <div key={i.id} className="inc-block">
            <b className="mono">{i.id}</b>
            <Editable value={n.incidentes[i.id]?.impacto || ''} onChange={(v) => updateIncident(i.id, { impacto: v })} />
          </div>
        ))}
      </Section>
      <Section title="Acciones urgentes">
        <table className="data paper-table">
          <thead>
            <tr>
              <th>Prioridad</th>
              <th>Acción</th>
              <th>Responsable</th>
              <th>Incidente</th>
            </tr>
          </thead>
          <tbody>
            {urgentActions(analysis).map((r) => (
              <tr key={r.text}>
                <td className="mono">{r.p}</td>
                <td>{r.text}</td>
                <td className="small">{r.owner}</td>
                <td className="mono">{r.incident}</td>
              </tr>
            ))}
          </tbody>
        </table>
      </Section>
    </>
  );
}

function Technical({ dataset, analysis, n, update, updateIncident, nav }) {
  const plan = useMemo(() => actionPlan(analysis), [analysis]);
  const iocs = useMemo(() => extractIocs(analysis), [analysis]);
  return (
    <>
      <Section n="1" title="Resumen ejecutivo">
        <Editable value={n.resumen_ejecutivo} onChange={(v) => update({ resumen_ejecutivo: v })} />
        <div className="risk-box">
          <LevelBadge level={analysis.globalLevel} />
          <Editable value={n.valoracion_riesgo} onChange={(v) => update({ valoracion_riesgo: v })} />
        </div>
      </Section>

      <Section n="2" title="Alcance y metodología">
        <p>
          Fuente: <b>{dataset.fileName}</b> (hoja {dataset.sheet}), {dataset.summary.total} eventos entre {dataset.summary.first} y {dataset.summary.last}. Fuentes:{' '}
          {Object.entries(dataset.summary.sources).map(([k, v]) => `${k} (${v})`).join(', ')}. Detección con 12 reglas deterministas (R-01 a R-12),
          correlación por IP, cuenta, equipo y tiempo, y clasificación con la matriz de criticidad. {n.source === 'ia' ? `Redacción asistida por IA (${n.model}) y revisada por el analista.` : 'Redacción por plantilla, sin IA.'}
        </p>
      </Section>

      <Section n="3" title="Hallazgos identificados">
        <table className="data paper-table">
          <thead>
            <tr>
              <th>ID</th>
              <th>Título</th>
              <th>Categoría</th>
              <th>Criticidad</th>
              <th>Equipos / cuentas / IPs</th>
            </tr>
          </thead>
          <tbody>
            {analysis.findings.map((f) => (
              <tr key={f.id} onClick={() => nav.openFinding(f.id)}>
                <td className="mono">{f.id}</td>
                <td>{f.title}</td>
                <td>{f.category}</td>
                <td>
                  <LevelBadge level={f.level} small />
                </td>
                <td className="small">{[...f.hosts, ...f.users, ...f.ips].join(', ')}</td>
              </tr>
            ))}
          </tbody>
        </table>
      </Section>

      <Section n="4" title="Explicación técnica de cada hallazgo">
        {analysis.incidents.map((i) => (
          <div key={i.id} className="inc-block">
            <h3>
              {i.id} · {i.title} <LevelBadge level={i.level} small />
            </h3>
            <Editable value={n.incidentes[i.id]?.narrativa || ''} onChange={(v) => updateIncident(i.id, { narrativa: v })} />
            <p className="muted small">{i.rationale}</p>
            <p className="small">
              <b>MITRE:</b> {i.mitre.map((m) => `${m} ${MITRE[m]?.name ?? ''}`).join(' · ')}
            </p>
          </div>
        ))}
      </Section>

      <Section n="5" title="Evidencias encontradas en los logs">
        <p className="muted small">Vista previa: primeras evidencias por hallazgo. El PDF incluye la tabla completa de cada uno.</p>
        {analysis.findings.map((f) => (
          <div key={f.id} className="inc-block">
            <b>
              {f.id} – {f.title}
            </b>{' '}
            <span className="muted small">({f.evidence.length} eventos)</span>
            <table className="data paper-table compact">
              <tbody>
                {f.evidence.slice(0, 4).map((e) => (
                  <tr key={e.Log_ID}>
                    <td className="mono">{e.Log_ID}</td>
                    <td className="mono">{e.Timestamp.slice(11)}</td>
                    <td>{e.Hostname}</td>
                    <td className="mono">{e.Event_ID}</td>
                    <td>{e.User}</td>
                    <td className="mono">{e.Source_IP}</td>
                    <td className="small">{evidenceExtract(e)}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        ))}
      </Section>

      <Section n="6" title="Criticidad y justificación">
        <table className="data paper-table">
          <tbody>
            {analysis.findings.map((f) => (
              <tr key={f.id}>
                <td className="mono">{f.id}</td>
                <td>
                  <LevelBadge level={f.level} small />
                </td>
                <td className="small">{f.justification}</td>
              </tr>
            ))}
          </tbody>
        </table>
      </Section>

      <Section n="7" title="Posible impacto en la organización">
        <ImpactTable analysis={analysis} />
        {analysis.incidents.map((i) => (
          <div key={i.id} className="inc-block">
            <b className="mono">{i.id}</b>
            <Editable value={n.incidentes[i.id]?.impacto || ''} onChange={(v) => updateIncident(i.id, { impacto: v })} />
          </div>
        ))}
      </Section>

      <Section n="8" title="Plan de acción">
        <table className="data paper-table">
          <thead>
            <tr>
              <th>Prior.</th>
              <th>Fase</th>
              <th>Acción</th>
              <th>Responsable</th>
              <th>Inc.</th>
            </tr>
          </thead>
          <tbody>
            {plan.map((r) => (
              <tr key={`${r.phase}${r.text}`}>
                <td className="mono">{r.p}</td>
                <td>{PHASE_LABEL[r.phase]}</td>
                <td>{r.text}</td>
                <td className="small">{r.owner}</td>
                <td className="mono">{r.incident}</td>
              </tr>
            ))}
          </tbody>
        </table>
      </Section>

      <Section n="9" title="Recomendaciones generales de seguridad">
        <p className="muted small">Una recomendación por línea.</p>
        <Editable value={n.recomendaciones.join('\n')} onChange={(v) => update({ recomendaciones: v.split('\n').filter((x) => x.trim()) })} />
      </Section>

      <Section n="10" title="Línea de tiempo consolidada">
        <table className="data paper-table compact">
          <tbody>
            {consolidatedTimeline(analysis).map((f) => (
              <tr key={f.id}>
                <td className="mono">
                  {hhmm(f.start)}–{hhmm(f.end)}
                </td>
                <td className="mono">{f.incidentId}</td>
                <td>
                  <b>{f.id}</b> {f.title}
                </td>
                <td>
                  <LevelBadge level={f.level} small />
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </Section>

      <Section n="11" title="Indicadores de compromiso (IoC)">
        <p>
          {iocs.length} indicadores ({['IP', 'Cuenta', 'Equipo', 'Comando', 'Archivo / ruta', 'URI'].map((t) => `${iocs.filter((i) => i.type === t).length} ${t}`).join(', ')}).{' '}
          <button className="link-btn" onClick={() => nav.go('mitre')}>
            Ver tabla completa
          </button>
        </p>
      </Section>

      <Section n="12" title="Mapeo MITRE ATT&CK">
        <table className="data paper-table compact">
          <tbody>
            {mitreMapping(analysis).map((m) => (
              <tr key={m.id}>
                <td>{m.tactic}</td>
                <td>
                  <b className="mono">{m.id}</b> {m.name}
                </td>
                <td className="mono">{m.findings.join(', ')}</td>
              </tr>
            ))}
          </tbody>
        </table>
      </Section>

      <Section n="13" title="Conclusiones">
        <Editable value={n.conclusiones} onChange={(v) => update({ conclusiones: v })} />
        <h3>Limitaciones</h3>
        <Editable value={n.limitaciones} onChange={(v) => update({ limitaciones: v })} />
      </Section>
    </>
  );
}
