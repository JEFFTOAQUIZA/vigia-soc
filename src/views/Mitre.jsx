import { useMemo, useState } from 'react';
import { motion } from 'framer-motion';
import LevelBadge, { levelClass } from '../components/LevelBadge.jsx';
import { TACTIC_ORDER } from '../lib/mitre.js';
import { extractIocs, mitreMapping } from '../lib/report.js';

const TYPES = ['Todos', 'IP', 'Cuenta', 'Equipo', 'Comando', 'Archivo / ruta', 'URI'];

function downloadCsv(rows) {
  const esc = (v) => `"${String(v).replace(/"/g, '""')}"`;
  const lines = [['Tipo', 'Valor', 'Contexto', 'Incidentes', 'Log_ID'], ...rows.map((r) => [r.type, r.value, r.context, r.incidents.join(' '), r.ids.join(' ')])];
  const blob = new Blob(['﻿' + lines.map((l) => l.map(esc).join(';')).join('\r\n')], { type: 'text/csv;charset=utf-8' });
  const a = Object.assign(document.createElement('a'), { href: URL.createObjectURL(blob), download: 'IoC_VIGIA.csv' });
  a.click();
  URL.revokeObjectURL(a.href);
}

export default function Mitre({ analysis, nav }) {
  const mapping = useMemo(() => mitreMapping(analysis), [analysis]);
  const iocs = useMemo(() => extractIocs(analysis), [analysis]);
  const [type, setType] = useState('Todos');
  const tactics = TACTIC_ORDER.filter((t) => mapping.some((m) => m.tactic === t));
  const shown = type === 'Todos' ? iocs : iocs.filter((i) => i.type === type);

  return (
    <div className="page">
      <h3 className="section-title">Matriz MITRE ATT&CK observada</h3>
      <p className="lead">Táctica → técnica → hallazgo. El color indica la criticidad más alta de los hallazgos que usan la técnica.</p>
      <div className="mitre-matrix">
        {tactics.map((t, i) => (
          <motion.div key={t} className="mitre-col" initial={{ opacity: 0, y: 12 }} animate={{ opacity: 1, y: 0 }} transition={{ delay: i * 0.05 }}>
            <div className="mitre-tactic">{t}</div>
            {mapping
              .filter((m) => m.tactic === t)
              .map((m) => (
                <button key={m.id} className={`mitre-tech ${levelClass(m.level)}`} onClick={() => nav.openFinding(m.findings[0])} title={`Hallazgos: ${m.findings.join(', ')}`}>
                  <b className="mono">{m.id}</b>
                  <span>{m.name}</span>
                  <small>{m.findings.join(' · ')}</small>
                </button>
              ))}
          </motion.div>
        ))}
      </div>

      <div className="row-between section-title">
        <h3 className="plain">Indicadores de compromiso (IoC)</h3>
        <button className="btn btn-ghost" onClick={() => downloadCsv(shown)}>
          Exportar CSV
        </button>
      </div>
      <div className="seg">
        {TYPES.map((t) => (
          <button key={t} className={type === t ? 'active' : ''} onClick={() => setType(t)}>
            {t} <span className="muted">({t === 'Todos' ? iocs.length : iocs.filter((i) => i.type === t).length})</span>
          </button>
        ))}
      </div>
      <div className="table-wrap card">
        <table className="data">
          <thead>
            <tr>
              <th>Tipo</th>
              <th>Valor</th>
              <th>Contexto</th>
              <th>Incidentes</th>
              <th>Log_ID</th>
            </tr>
          </thead>
          <tbody>
            {shown.map((i) => (
              <tr key={`${i.type}|${i.value}`}>
                <td>{i.type}</td>
                <td className="mono break">{i.value}</td>
                <td className="small">{i.context}</td>
                <td className="mono">{i.incidents.join(', ')}</td>
                <td>
                  <button className="link-btn mono" onClick={() => nav.showEvents({ ids: i.ids, label: `IoC ${i.value}` })}>
                    {i.ids.slice(0, 3).join(', ')}
                    {i.ids.length > 3 ? ' …' : ''}
                  </button>
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
      <p className="muted small">No se observan dominios en los registros: las comunicaciones externas aparecen solo como direcciones IP.</p>

      <h3 className="section-title">Técnicas por criticidad</h3>
      <div className="table-wrap card">
        <table className="data">
          <thead>
            <tr>
              <th>Táctica</th>
              <th>Técnica</th>
              <th>Hallazgos</th>
              <th>Criticidad</th>
            </tr>
          </thead>
          <tbody>
            {mapping.map((m) => (
              <tr key={m.id} onClick={() => nav.openFinding(m.findings[0])}>
                <td>{m.tactic}</td>
                <td>
                  <b className="mono">{m.id}</b> {m.name}
                </td>
                <td className="mono">{m.findings.join(', ')}</td>
                <td>
                  <LevelBadge level={m.level} small />
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </div>
  );
}
