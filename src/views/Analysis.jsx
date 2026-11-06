import { useEffect, useState } from 'react';
import { AnimatePresence, motion } from 'framer-motion';
import LevelBadge from '../components/LevelBadge.jsx';
import CountUp from '../components/CountUp.jsx';
import { MITRE } from '../lib/mitre.js';
import { PHASE_LABEL } from '../lib/report.js';

const TABS = [
  { id: 'incidents', label: 'Incidentes' },
  { id: 'findings', label: 'Hallazgos' },
  { id: 'rules', label: 'Reglas y categorías' },
  { id: 'discarded', label: 'Descartados' },
];
const hhmm = (ts) => ts.slice(11, 19);

export default function Analysis({ analysis, focus, nav }) {
  const [tab, setTab] = useState('incidents');
  const [openIncident, setOpenIncident] = useState(analysis.incidents[0]?.id);
  const [openFinding, setOpenFinding] = useState(null);

  useEffect(() => {
    if (!focus) return;
    const f = analysis.findings.find((x) => x.id === focus);
    if (!f) return;
    setTab('incidents');
    setOpenIncident(f.incidentId);
    setOpenFinding(f.id);
    setTimeout(() => document.getElementById(`finding-${f.id}`)?.scrollIntoView({ behavior: 'smooth', block: 'center' }), 350);
  }, [focus, analysis]);

  const { stats } = analysis;
  return (
    <div className="page">
      <div className="stat-grid">
        <Stat label="Incidentes" value={stats.incidents} cls="critical" />
        <Stat label="Anomalías (hipótesis)" value={stats.anomalies} cls="medium" />
        <Stat label="Hallazgos" value={stats.findings} />
        <Stat label="Eventos sospechosos" value={stats.suspiciousEvents} />
        <Stat label="Riesgo global" text={analysis.globalLevel} cls="critical" />
      </div>

      <div className="tabs">
        {TABS.map((t) => (
          <button key={t.id} className={`tab${tab === t.id ? ' active' : ''}`} onClick={() => setTab(t.id)}>
            {t.label}
            {tab === t.id && <span className="tab-underline" />}
          </button>
        ))}
      </div>

      <AnimatePresence mode="wait">
        <motion.div key={tab} initial={{ opacity: 0, y: 8 }} animate={{ opacity: 1, y: 0 }} exit={{ opacity: 0 }} transition={{ duration: 0.2 }}>
          {tab === 'incidents' && (
            <div className="stack">
              {analysis.incidents.map((inc, i) => (
                <IncidentCard
                  key={inc.id}
                  inc={inc}
                  index={i}
                  open={openIncident === inc.id}
                  onToggle={() => setOpenIncident(openIncident === inc.id ? null : inc.id)}
                  openFinding={openFinding}
                  setOpenFinding={setOpenFinding}
                  nav={nav}
                />
              ))}
            </div>
          )}
          {tab === 'findings' && <FindingsTable analysis={analysis} onOpen={(id) => nav.openFinding(id)} />}
          {tab === 'rules' && <RulesView analysis={analysis} />}
          {tab === 'discarded' && (
            <div className="stack">
              <p className="lead">Actividad revisada y descartada como falso positivo o ruido, con su justificación.</p>
              {analysis.discarded.map((f) => (
                <div key={f.id} className="card">
                  <div className="row-between">
                    <h4 className="plain">
                      <LevelBadge level="Bajo" small /> {f.title}
                    </h4>
                    <button className="btn btn-ghost sm" onClick={() => nav.showEvents({ ids: f.evidence.map((e) => e.Log_ID), label: f.title })}>
                      Ver {f.evidence.length} eventos
                    </button>
                  </div>
                  <p>{f.description}</p>
                  <p className="muted small">{f.detection}</p>
                </div>
              ))}
            </div>
          )}
        </motion.div>
      </AnimatePresence>
    </div>
  );
}

function Stat({ label, value, text, cls = '' }) {
  return (
    <div className={`stat card ${cls}`}>
      <div className="stat-value">{text ?? <CountUp value={value} />}</div>
      <div className="stat-label">{label}</div>
    </div>
  );
}

function IncidentCard({ inc, index, open, onToggle, openFinding, setOpenFinding, nav }) {
  return (
    <motion.article
      className={`incident card lvl-${inc.level}`}
      initial={{ opacity: 0, y: 16 }}
      animate={{ opacity: 1, y: 0 }}
      transition={{ delay: index * 0.06 }}
      layout
    >
      <button className="incident-head" onClick={onToggle} aria-expanded={open}>
        <span className="incident-id">{inc.id}</span>
        <LevelBadge level={inc.level} />
        <span className="incident-title">
          {inc.title}
          {inc.type === 'anomaly' && <em className="hyp"> · hipótesis</em>}
        </span>
        <span className="muted mono small">
          {hhmm(inc.start)}–{hhmm(inc.end)}
        </span>
        <span className="chev">{open ? '▾' : '▸'}</span>
      </button>

      <div className="chain">
        {inc.tactics.map((t, i) => (
          <motion.span key={t} className="chain-step" initial={{ opacity: 0, x: -8 }} animate={{ opacity: 1, x: 0 }} transition={{ delay: 0.1 + i * 0.08 }}>
            {t}
          </motion.span>
        ))}
      </div>

      <AnimatePresence initial={false}>
        {open && (
          <motion.div initial={{ height: 0, opacity: 0 }} animate={{ height: 'auto', opacity: 1 }} exit={{ height: 0, opacity: 0 }} className="incident-body">
            <EntityFlow inc={inc} />
            <p className="rationale">{inc.rationale}</p>
            <div className="row-between">
              <h4>
                {inc.findings.length} hallazgos · {inc.evidence.length} eventos de evidencia
              </h4>
              <button className="btn btn-ghost sm" onClick={() => nav.showEvents({ ids: inc.evidence.map((e) => e.Log_ID), label: `Evidencias de ${inc.id}` })}>
                Ver todas las evidencias
              </button>
            </div>
            {inc.findings.map((f) => (
              <FindingCard key={f.id} f={f} open={openFinding === f.id} onToggle={() => setOpenFinding(openFinding === f.id ? null : f.id)} nav={nav} />
            ))}
          </motion.div>
        )}
      </AnimatePresence>
    </motion.article>
  );
}

function EntityFlow({ inc }) {
  const src = [...new Set(inc.evidence.map((e) => e.Source_IP))].filter((ip) => inc.externalIps.includes(ip));
  const dst = inc.externalIps.filter((ip) => !src.includes(ip));
  const cols = [
    { label: 'Origen', items: src.length ? src : ['Red interna'] },
    { label: 'Cuentas', items: inc.users },
    { label: 'Equipos', items: inc.hosts },
    ...(dst.length ? [{ label: 'Destino externo', items: dst }] : []),
  ];
  return (
    <div className="flow">
      {cols.map((c, i) => (
        <div key={c.label} className="flow-col">
          <small>{c.label}</small>
          {c.items.map((x, j) => (
            <motion.span key={x} className="flow-node" initial={{ opacity: 0, scale: 0.8 }} animate={{ opacity: 1, scale: 1 }} transition={{ delay: i * 0.12 + j * 0.04 }}>
              {x}
            </motion.span>
          ))}
          {i < cols.length - 1 && <span className="flow-arrow">→</span>}
        </div>
      ))}
    </div>
  );
}

function FindingCard({ f, open, onToggle, nav }) {
  return (
    <div id={`finding-${f.id}`} className={`finding${open ? ' open' : ''}`}>
      <button className="finding-head" onClick={onToggle} aria-expanded={open}>
        <b className="mono">{f.id}</b>
        <LevelBadge level={f.level} small />
        <span className="finding-title">{f.title}</span>
        <span className="tag-cat">{f.category}</span>
      </button>
      <AnimatePresence initial={false}>
        {open && (
          <motion.div initial={{ height: 0, opacity: 0 }} animate={{ height: 'auto', opacity: 1 }} exit={{ height: 0, opacity: 0 }} className="finding-body">
            <div className="two-col">
              <div>
                <h5>Qué ocurrió</h5>
                <p>{f.description}</p>
                <h5>Cómo se detectó</h5>
                <p className="muted">{f.detection}</p>
                <h5>MITRE ATT&CK</h5>
                <div className="tags">
                  {f.mitre.map((m) => (
                    <span key={m} className="tag tag-mitre" title={MITRE[m]?.tactic}>
                      {m} · {MITRE[m]?.name}
                    </span>
                  ))}
                </div>
              </div>
              <div>
                <h5>Criticidad y justificación</h5>
                <p>
                  <LevelBadge level={f.level} /> {f.escalated && <span className="muted small">(elevado por factores agravantes)</span>}
                </p>
                <p className="small">{f.justification}</p>
                {f.factors.length > 0 && (
                  <div className="tags">
                    {f.factors.map((x) => (
                      <span key={x} className="tag tag-warn">
                        {x}
                      </span>
                    ))}
                  </div>
                )}
                <h5>Impacto</h5>
                <p className="small">{f.impact}</p>
              </div>
            </div>

            <h5>Evidencias ({f.evidence.length})</h5>
            <div className="evidence-ids">
              {f.evidence.map((e) => (
                <button key={e.Log_ID} className="id-chip" title={`${e.Timestamp} · ${e.Hostname} · ${e.Event_ID} · ${e.User}`} onClick={() => nav.showEvents({ ids: [e.Log_ID], label: e.Log_ID })}>
                  {e.Log_ID}
                </button>
              ))}
              <button className="btn btn-ghost sm" onClick={() => nav.showEvents({ ids: f.evidence.map((e) => e.Log_ID), label: `Evidencias de ${f.id}` })}>
                Ver en tabla
              </button>
            </div>

            <h5>Acciones</h5>
            <div className="actions-grid">
              {Object.entries(f.actions).map(([phase, list]) => (
                <div key={phase}>
                  <small className="phase">{PHASE_LABEL[phase]}</small>
                  <ul>
                    {list.map((a) => (
                      <li key={a.text}>
                        {a.text} <span className="muted small">— {a.owner}</span>
                      </li>
                    ))}
                  </ul>
                </div>
              ))}
            </div>
          </motion.div>
        )}
      </AnimatePresence>
    </div>
  );
}

function FindingsTable({ analysis, onOpen }) {
  return (
    <div className="table-wrap card">
      <table className="data">
        <thead>
          <tr>
            <th>ID</th>
            <th>Incidente</th>
            <th>Título</th>
            <th>Categoría</th>
            <th>MITRE</th>
            <th>Criticidad</th>
            <th>Ventana</th>
            <th>Activos</th>
            <th>Evid.</th>
          </tr>
        </thead>
        <tbody>
          {analysis.findings.map((f) => (
            <tr key={f.id} onClick={() => onOpen(f.id)}>
              <td className="mono">{f.id}</td>
              <td className="mono">{f.incidentId}</td>
              <td>{f.title}</td>
              <td>{f.category}</td>
              <td className="mono small">{f.mitre.join(', ')}</td>
              <td>
                <LevelBadge level={f.level} small />
              </td>
              <td className="mono small">
                {hhmm(f.start)}–{hhmm(f.end)}
              </td>
              <td className="small">{[...f.hosts, ...f.users].join(', ')}</td>
              <td>{f.evidence.length}</td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}

function RulesView({ analysis }) {
  return (
    <div className="stack">
      <div className="cat-grid">
        {analysis.categoryStats.map((c, i) => (
          <motion.div key={c.category} className="card cat-card" initial={{ opacity: 0, y: 10 }} animate={{ opacity: 1, y: 0 }} transition={{ delay: i * 0.05 }}>
            <div className="row-between">
              <h4 className="plain">{c.category}</h4>
              <span className={`count ${c.findings.length ? 'hit' : ''}`}>{c.findings.length}</span>
            </div>
            {c.findings.length ? (
              <ul className="small">
                {c.findings.map((f) => (
                  <li key={f.id}>
                    <b>{f.id}</b> {f.title}
                  </li>
                ))}
              </ul>
            ) : (
              <p className="muted small">{c.justification}</p>
            )}
          </motion.div>
        ))}
      </div>
      <div className="table-wrap card">
        <table className="data">
          <thead>
            <tr>
              <th>Regla</th>
              <th>Categoría</th>
              <th>Descripción</th>
              <th>Umbral</th>
              <th>Hallazgos</th>
              <th>Eventos</th>
            </tr>
          </thead>
          <tbody>
            {analysis.ruleStats.map((r) => (
              <tr key={r.id}>
                <td className="mono">{r.id}</td>
                <td>{r.category}</td>
                <td>{r.name}</td>
                <td className="small">{r.threshold}</td>
                <td>{r.findings}</td>
                <td>{r.events}</td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
      <p className="muted small">Los umbrales se pueden ajustar en Configuración; el análisis se recalcula al instante y es reproducible con el mismo archivo.</p>
    </div>
  );
}
