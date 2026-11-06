import { useRef, useState } from 'react';
import { AnimatePresence, motion } from 'framer-motion';
import { parseWorkbook, ValidationError, REQUIRED_COLUMNS, SHEET_NAME } from '../lib/parse.js';
import CountUp from '../components/CountUp.jsx';

const container = { hidden: {}, show: { transition: { staggerChildren: 0.07 } } };
const item = { hidden: { opacity: 0, y: 14 }, show: { opacity: 1, y: 0 } };

export default function Upload({ dataset, onLoaded, onNext }) {
  const inputRef = useRef(null);
  const [dragging, setDragging] = useState(false);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState('');

  async function handleFile(file) {
    if (!file) return;
    setError('');
    setLoading(true);
    try {
      onLoaded(await parseWorkbook(file));
    } catch (err) {
      setError(err instanceof ValidationError ? err.message : 'Error inesperado al procesar el archivo.');
      if (!(err instanceof ValidationError)) console.error(err);
    } finally {
      setLoading(false);
      if (inputRef.current) inputRef.current.value = '';
    }
  }

  function onDrop(e) {
    e.preventDefault();
    setDragging(false);
    handleFile(e.dataTransfer.files?.[0]);
  }

  return (
    <div className="upload">
      <motion.div
        className={`dropzone${dragging ? ' dragging' : ''}${dataset ? ' compact' : ''}`}
        onDragOver={(e) => {
          e.preventDefault();
          setDragging(true);
        }}
        onDragLeave={() => setDragging(false)}
        onDrop={onDrop}
        onClick={() => !loading && inputRef.current?.click()}
        role="button"
        tabIndex={0}
        onKeyDown={(e) => (e.key === 'Enter' || e.key === ' ') && inputRef.current?.click()}
        whileHover={{ scale: 1.005 }}
        layout
      >
        <input
          ref={inputRef}
          type="file"
          accept=".xlsx,application/vnd.openxmlformats-officedocument.spreadsheetml.sheet"
          hidden
          onChange={(e) => handleFile(e.target.files?.[0])}
        />
        {loading ? (
          <>
            <span className="spinner big" />
            <p>Procesando y validando eventos…</p>
          </>
        ) : (
          <>
            <motion.div
              className="drop-icon"
              animate={{ y: dragging ? -6 : 0 }}
              transition={{ type: 'spring', stiffness: 300 }}
            >
              ⇪
            </motion.div>
            <p>
              <strong>{dataset ? 'Cargar otro archivo' : 'Arrastre aquí el export del SIEM'}</strong>
              <br />o haga clic para seleccionarlo (.xlsx)
            </p>
            {!dataset && (
              <small className="muted">
                Hoja esperada: <code>{SHEET_NAME}</code> · {REQUIRED_COLUMNS.length} columnas obligatorias. El archivo
                original no se modifica.
              </small>
            )}
          </>
        )}
      </motion.div>

      <AnimatePresence>
        {error && (
          <motion.div
            className="alert alert-error"
            role="alert"
            initial={{ opacity: 0, y: -6 }}
            animate={{ opacity: 1, y: 0 }}
            exit={{ opacity: 0 }}
          >
            <strong>Archivo no válido.</strong> {error}
          </motion.div>
        )}
      </AnimatePresence>

      {dataset && !loading && <DatasetSummary key={dataset.loadedAt} dataset={dataset} onNext={onNext} />}
    </div>
  );
}

function DatasetSummary({ dataset, onNext }) {
  const { summary, quality } = dataset;
  const maxSource = Math.max(...Object.values(summary.sources));
  const anomalies = [...quality.lookalikeHosts, ...quality.lookalikeUsers];

  const stats = [
    { label: 'Eventos', value: summary.total },
    { label: 'Fuentes de log', value: Object.keys(summary.sources).length },
    { label: 'Equipos', value: summary.hosts.length },
    { label: 'Cuentas', value: summary.users.length },
    { label: 'IPs internas', value: summary.internalIps.length },
    { label: 'IPs externas', value: summary.externalIps.length + summary.externalDestinations.length, warn: true },
  ];

  return (
    <motion.div variants={container} initial="hidden" animate="show" className="summary">
      <motion.div variants={item} className="alert alert-ok">
        <strong>Archivo validado.</strong> {dataset.fileName} · hoja <code>{dataset.sheet}</code> · ventana{' '}
        <code>{summary.first}</code> → <code>{summary.last}</code>
      </motion.div>

      <div className="stat-grid">
        {stats.map((s) => (
          <motion.div key={s.label} variants={item} className={`stat card${s.warn ? ' warn' : ''}`}>
            <div className="stat-value">
              <CountUp value={s.value} />
            </div>
            <div className="stat-label">{s.label}</div>
          </motion.div>
        ))}
      </div>

      <div className="two-col">
        <motion.section variants={item} className="card">
          <h4>Eventos por fuente</h4>
          {Object.entries(summary.sources)
            .sort((a, b) => b[1] - a[1])
            .map(([name, n], i) => (
              <div key={name} className="bar-row">
                <span>{name}</span>
                <div className="bar-track">
                  <motion.div
                    className="bar-fill"
                    initial={{ width: 0 }}
                    animate={{ width: `${(n / maxSource) * 100}%` }}
                    transition={{ delay: 0.3 + i * 0.08, duration: 0.7, ease: 'easeOut' }}
                  />
                </div>
                <b>{n}</b>
              </div>
            ))}
          <h4 className="mt">IPs externas observadas</h4>
          <div className="tags">
            {summary.externalIps.map((ip) => (
              <span key={ip} className="tag tag-danger" title="IP de origen externa">
                {ip}
              </span>
            ))}
            {summary.externalDestinations.map((ip) => (
              <span key={ip} className="tag tag-warn" title="Destino externo">
                → {ip}
              </span>
            ))}
          </div>
        </motion.section>

        <motion.section variants={item} className="card">
          <h4>Calidad de los datos</h4>
          <ul className="checklist">
            <Check ok label={`Columnas obligatorias: ${quality.columns}/${quality.columns}`} />
            <Check ok={!quality.duplicateIds.length} label={`Log_ID duplicados o vacíos: ${quality.duplicateIds.length}`} />
            <Check
              ok={!quality.invalidTimestamps.length}
              label={`Timestamps inválidos: ${quality.invalidTimestamps.length}`}
              detail={quality.invalidTimestamps.slice(0, 5).join(', ')}
            />
            {Object.entries(quality.emptyByColumn).map(([col, n]) => (
              <Check
                key={col}
                info
                label={`${col} vacío en ${n} eventos`}
                detail="Esperado: no todos los eventos tienen este dato"
              />
            ))}
            <Check
              ok={!anomalies.length}
              warn={anomalies.length > 0}
              label={`Nombres casi idénticos: ${anomalies.length}`}
              detail={anomalies.map(([a, b]) => `${a} ↔ ${b}`).join(' · ')}
            />
          </ul>
          {anomalies.length > 0 && (
            <p className="muted small">
              Los nombres casi idénticos pueden deberse a un error de normalización o a equipos/cuentas suplantados. Se
              evaluarán en el módulo de Análisis.
            </p>
          )}
        </motion.section>
      </div>

      <motion.div variants={item} className="actions">
        <button className="btn btn-primary" onClick={onNext}>
          Ver análisis →
        </button>
      </motion.div>
    </motion.div>
  );
}

function Check({ ok, warn, info, label, detail }) {
  const cls = info ? 'info' : warn ? 'warn' : ok ? 'ok' : 'bad';
  const icon = info ? 'i' : warn ? '!' : ok ? '✓' : '✕';
  return (
    <li className={`check ${cls}`}>
      <span className="check-icon">{icon}</span>
      <div>
        {label}
        {detail && <small>{detail}</small>}
      </div>
    </li>
  );
}
