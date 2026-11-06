import { useState } from 'react';
import { AnimatePresence, motion } from 'framer-motion';
import { exportExecutivePdf, exportTechnicalPdf } from '../lib/pdf.js';
import { unknownLogIds } from '../lib/report.js';

const slug = (s) =>
  String(s || '')
    .normalize('NFD')
    .replace(/[̀-ͯ]/g, '')
    .replace(/[^A-Za-z0-9]+/g, '')
    .slice(0, 30);

export default function Export({ dataset, analysis, narratives, meta, setMeta, nav }) {
  const [busy, setBusy] = useState('');
  const [done, setDone] = useState([]);
  const [error, setError] = useState('');
  const who = [slug(meta.apellido), slug(meta.nombre)].filter(Boolean).join('_') || 'Apellido_Nombre';
  const files = {
    tecnico: `Informe_SOC_L2_${who}.pdf`,
    ejecutivo: `Informe_Ejecutivo_SOC_L2_${who}.pdf`,
  };
  const unknown = [...unknownLogIds(narratives.ejecutivo, dataset), ...unknownLogIds(narratives.tecnico, dataset)];

  function generate(kind) {
    setBusy(kind);
    setError('');
    // Deja pintar el indicador de progreso antes del trabajo síncrono de jsPDF
    setTimeout(() => {
      try {
        const args = { dataset, analysis, narrative: narratives[kind], meta, fileName: files[kind] };
        if (kind === 'ejecutivo') exportExecutivePdf(args);
        else exportTechnicalPdf(args);
        setDone((d) => [...new Set([...d, kind])]);
      } catch (err) {
        console.error(err);
        setError(`No se pudo generar el PDF: ${err.message}`);
      } finally {
        setBusy('');
      }
    }, 60);
  }

  const cards = [
    {
      kind: 'ejecutivo',
      title: 'Informe ejecutivo',
      audience: 'Dirección y negocio',
      items: ['Portada con riesgo global', 'Resumen en lenguaje no técnico', 'Incidentes y gráfico de criticidad', 'Impacto en el negocio (CID, operación, reputación)', 'Acciones urgentes y decisiones requeridas'],
    },
    {
      kind: 'tecnico',
      title: 'Informe técnico (entregable)',
      audience: 'Equipo SOC / TI',
      items: ['Portada e índice', 'Las 8 secciones obligatorias', 'Evidencias completas con Log_ID', 'Línea de tiempo, IoC y mapeo MITRE', 'Anexos: reglas, falsos positivos, glosario'],
    },
  ];

  return (
    <div className="page">
      <div className="card meta-inline">
        <label className="field compact">
          <span>Apellido</span>
          <input className="input" value={meta.apellido} onChange={(e) => setMeta({ ...meta, apellido: e.target.value })} placeholder="Apellido" />
        </label>
        <label className="field compact">
          <span>Nombre</span>
          <input className="input" value={meta.nombre} onChange={(e) => setMeta({ ...meta, nombre: e.target.value })} placeholder="Nombre" />
        </label>
        <p className="muted small">
          Se usan en la portada y en el nombre del archivo, como sugiere la guía: <code>Informe_SOC_L2_Apellido_Nombre.pdf</code>.
        </p>
      </div>

      {unknown.length > 0 && (
        <div className="alert alert-error">
          El texto del informe cita Log_ID inexistentes ({[...new Set(unknown)].join(', ')}).{' '}
          <button className="link-btn" onClick={() => nav.go('report')}>
            Corregir en Informe
          </button>
        </div>
      )}
      {error && <div className="alert alert-error">{error}</div>}

      <div className="export-grid">
        {cards.map((c, i) => (
          <motion.div key={c.kind} className="card export-card" initial={{ opacity: 0, y: 16 }} animate={{ opacity: 1, y: 0 }} transition={{ delay: i * 0.1 }}>
            <div className="pdf-icon">PDF</div>
            <h3>{c.title}</h3>
            <p className="muted small">Para: {c.audience}</p>
            <ul className="small">
              {c.items.map((x) => (
                <li key={x}>{x}</li>
              ))}
            </ul>
            <p className="small">
              Texto: <b>{narratives[c.kind].source === 'ia' ? `IA (${narratives[c.kind].model})` : 'plantilla'}</b>
              {narratives[c.kind].edited ? ' · revisado por el analista' : ''}
            </p>
            <code className="file-name">{files[c.kind]}</code>
            <button className="btn btn-primary btn-block" onClick={() => generate(c.kind)} disabled={!!busy}>
              {busy === c.kind ? <span className="spinner" /> : 'Descargar PDF'}
            </button>
            <AnimatePresence>
              {done.includes(c.kind) && (
                <motion.p className="ok-msg" initial={{ opacity: 0, scale: 0.9 }} animate={{ opacity: 1, scale: 1 }}>
                  ✓ Generado
                </motion.p>
              )}
            </AnimatePresence>
          </motion.div>
        ))}
      </div>
      <p className="muted small">
        Antes de exportar, revise el texto en el módulo <button className="link-btn" onClick={() => nav.go('report')}>Informe</button>. El PDF incluye los
        gráficos del dashboard en versión de impresión.
      </p>
    </div>
  );
}
