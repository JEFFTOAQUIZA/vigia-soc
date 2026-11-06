import { useEffect, useMemo, useState } from 'react';
import { AnimatePresence, motion } from 'framer-motion';
import { LEVELS } from '../lib/engine.js';
import LevelBadge from './LevelBadge.jsx';

const PAGE_SIZE = 25;
const EMPTY = { q: '', host: '', user: '', ip: '', eventId: '', source: '', level: '', from: '', to: '', ids: null, label: '' };
const options = (events, key) => [...new Set(events.map((e) => e[key]))].sort();

export default function EventsTable({ dataset, analysis, filter, onClearFilter, onOpenFinding }) {
  const [f, setF] = useState({ ...EMPTY, ...filter });
  const [page, setPage] = useState(0);
  const [selected, setSelected] = useState(null);

  useEffect(() => {
    setF({ ...EMPTY, ...filter });
    setPage(0);
  }, [filter]);

  const set = (key) => (e) => {
    setF((prev) => ({ ...prev, [key]: e.target.value }));
    setPage(0);
  };

  const rows = useMemo(() => {
    const q = f.q.trim().toLowerCase();
    const idSet = f.ids ? new Set(f.ids) : null;
    return dataset.events.filter((e) => {
      if (idSet && !idSet.has(e.Log_ID)) return false;
      if (f.host && e.Hostname !== f.host) return false;
      if (f.user && e.User !== f.user) return false;
      if (f.ip && e.Source_IP !== f.ip && !e.Destination.startsWith(f.ip)) return false;
      if (f.eventId && e.Event_ID !== f.eventId) return false;
      if (f.source && e.Log_Source !== f.source) return false;
      const lvl = analysis.eventLevel.get(e.Log_ID);
      if (f.level === 'sospechoso' && !lvl) return false;
      if (f.level && f.level !== 'sospechoso' && lvl !== f.level) return false;
      const t = e.Timestamp.slice(11, 16);
      if (f.from && t < f.from) return false;
      if (f.to && t > f.to) return false;
      if (q && !Object.values(e).some((v) => typeof v === 'string' && v.toLowerCase().includes(q))) return false;
      return true;
    });
  }, [dataset, analysis, f]);

  const pages = Math.max(1, Math.ceil(rows.length / PAGE_SIZE));
  const visible = rows.slice(page * PAGE_SIZE, (page + 1) * PAGE_SIZE);
  const active = Object.entries(f).some(([k, v]) => k !== 'label' && (Array.isArray(v) ? v.length : v));

  function reset() {
    setF(EMPTY);
    setPage(0);
    onClearFilter?.();
  }

  return (
    <div className="events-table">
      {f.label && (
        <div className="filter-banner">
          Mostrando: <strong>{f.label}</strong>
          <button className="link-btn" onClick={reset}>
            Quitar filtro
          </button>
        </div>
      )}

      <div className="filters card">
        <input className="input grow" placeholder="Buscar en todos los campos…" value={f.q} onChange={set('q')} />
        <select className="input" value={f.host} onChange={set('host')}>
          <option value="">Equipo</option>
          {options(dataset.events, 'Hostname').map((v) => (
            <option key={v}>{v}</option>
          ))}
        </select>
        <select className="input" value={f.user} onChange={set('user')}>
          <option value="">Usuario</option>
          {options(dataset.events, 'User').map((v) => (
            <option key={v}>{v}</option>
          ))}
        </select>
        <select className="input" value={f.ip} onChange={set('ip')}>
          <option value="">IP</option>
          {options(dataset.events, 'Source_IP').map((v) => (
            <option key={v}>{v}</option>
          ))}
        </select>
        <select className="input" value={f.eventId} onChange={set('eventId')}>
          <option value="">Event_ID</option>
          {options(dataset.events, 'Event_ID').map((v) => (
            <option key={v}>{v}</option>
          ))}
        </select>
        <select className="input" value={f.source} onChange={set('source')}>
          <option value="">Fuente</option>
          {options(dataset.events, 'Log_Source').map((v) => (
            <option key={v}>{v}</option>
          ))}
        </select>
        <select className="input" value={f.level} onChange={set('level')}>
          <option value="">Criticidad</option>
          <option value="sospechoso">Solo sospechosos</option>
          {[...LEVELS].reverse().map((l) => (
            <option key={l}>{l}</option>
          ))}
        </select>
        <label className="time-range">
          <input className="input" type="time" value={f.from} onChange={set('from')} title="Desde" />
          <span>–</span>
          <input className="input" type="time" value={f.to} onChange={set('to')} title="Hasta" />
        </label>
        {active && (
          <button className="btn btn-ghost" onClick={reset}>
            Limpiar
          </button>
        )}
      </div>

      <div className="table-meta">
        <span>
          <b>{rows.length}</b> de {dataset.events.length} eventos
        </span>
        <Pager page={page} pages={pages} setPage={setPage} />
      </div>

      <div className="table-wrap card">
        <table className="data">
          <thead>
            <tr>
              <th>Log_ID</th>
              <th>Hora</th>
              <th>Equipo</th>
              <th>Event_ID</th>
              <th>Usuario</th>
              <th>IP origen</th>
              <th>Destino</th>
              <th>Descripción / comando</th>
              <th>Resultado</th>
              <th>Severity SIEM</th>
              <th>Criticidad</th>
            </tr>
          </thead>
          <tbody>
            {visible.map((e) => {
              const lvl = analysis.eventLevel.get(e.Log_ID);
              return (
                <tr key={e.Log_ID} className={lvl ? 'flagged' : ''} onClick={() => setSelected(e)}>
                  <td className="mono">{e.Log_ID}</td>
                  <td className="mono">{e.Timestamp.slice(11)}</td>
                  <td>{e.Hostname}</td>
                  <td className="mono">{e.Event_ID}</td>
                  <td>{e.User}</td>
                  <td className="mono">{e.Source_IP}</td>
                  <td className="mono ellipsis">{e.Destination}</td>
                  <td className="ellipsis wide" title={`${e.Event_Description} ${e.Process_CommandLine}`}>
                    {e.Process_CommandLine ? <code>{e.Process_CommandLine}</code> : e.Event_Description}
                  </td>
                  <td>{e.Result}</td>
                  <td className="muted">{e.Severity}</td>
                  <td>
                    <LevelBadge level={lvl} small />
                  </td>
                </tr>
              );
            })}
            {!visible.length && (
              <tr>
                <td colSpan={11} className="empty">
                  Ningún evento coincide con los filtros.
                </td>
              </tr>
            )}
          </tbody>
        </table>
      </div>

      <AnimatePresence>
        {selected && (
          <EventDrawer
            event={selected}
            analysis={analysis}
            onClose={() => setSelected(null)}
            onOpenFinding={(id) => {
              setSelected(null);
              onOpenFinding?.(id);
            }}
          />
        )}
      </AnimatePresence>
    </div>
  );
}

function Pager({ page, pages, setPage }) {
  return (
    <div className="pager">
      <button className="btn btn-ghost sm" disabled={page === 0} onClick={() => setPage(0)}>
        «
      </button>
      <button className="btn btn-ghost sm" disabled={page === 0} onClick={() => setPage(page - 1)}>
        ‹
      </button>
      <span>
        Página {page + 1} / {pages}
      </span>
      <button className="btn btn-ghost sm" disabled={page >= pages - 1} onClick={() => setPage(page + 1)}>
        ›
      </button>
      <button className="btn btn-ghost sm" disabled={page >= pages - 1} onClick={() => setPage(pages - 1)}>
        »
      </button>
    </div>
  );
}

function EventDrawer({ event, analysis, onClose, onOpenFinding }) {
  const findingIds = analysis.eventFinding.get(event.Log_ID) || [];
  const findings = analysis.findings.filter((f) => findingIds.includes(f.id));
  const fields = Object.entries(event).filter(([k]) => !k.startsWith('_'));
  return (
    <>
      <motion.div className="backdrop" initial={{ opacity: 0 }} animate={{ opacity: 1 }} exit={{ opacity: 0 }} onClick={onClose} />
      <motion.aside
        className="drawer"
        initial={{ x: '100%' }}
        animate={{ x: 0 }}
        exit={{ x: '100%' }}
        transition={{ type: 'spring', stiffness: 260, damping: 30 }}
      >
        <div className="drawer-head">
          <h3 className="mono">{event.Log_ID}</h3>
          <button className="btn btn-ghost sm" onClick={onClose}>
            Cerrar ✕
          </button>
        </div>
        <dl className="kv-list">
          {fields.map(([k, v]) => (
            <div key={k}>
              <dt>{k}</dt>
              <dd className={k === 'Process_CommandLine' ? 'mono' : ''}>{v || '—'}</dd>
            </div>
          ))}
          <div>
            <dt>Fila en Excel</dt>
            <dd>{event._row}</dd>
          </div>
        </dl>
        <h4>Hallazgos que lo citan como evidencia</h4>
        {findings.length ? (
          findings.map((f) => (
            <button key={f.id} className="finding-link" onClick={() => onOpenFinding(f.id)}>
              <LevelBadge level={f.level} small /> <b>{f.id}</b> {f.title}
            </button>
          ))
        ) : (
          <p className="muted small">Este evento no forma parte de ningún hallazgo: se considera actividad normal.</p>
        )}
      </motion.aside>
    </>
  );
}
