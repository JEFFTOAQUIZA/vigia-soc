import { useEffect, useMemo, useState } from 'react';
import { motion } from 'framer-motion';
import Logo from './Logo.jsx';
import LevelBadge from './LevelBadge.jsx';
import { ThemeToggle } from '../theme.jsx';
import { DEFAULT_CONFIG, runAnalysis } from '../lib/engine.js';
import { defaultMeta, defaultNarrative } from '../lib/report.js';
import Upload from '../views/Upload.jsx';
import Events from '../views/Events.jsx';
import Analysis from '../views/Analysis.jsx';
import Timeline from '../views/Timeline.jsx';
import Dashboard from '../views/Dashboard.jsx';
import Mitre from '../views/Mitre.jsx';
import Report from '../views/Report.jsx';
import Export from '../views/Export.jsx';
import Config from '../views/Config.jsx';

export const NAV = [
  { id: 'upload', step: '1', label: 'Carga', title: 'Carga de archivo' },
  { id: 'events', step: '2', label: 'Eventos', title: 'Explorador de eventos', needsData: true },
  { id: 'analysis', step: '3', label: 'Análisis', title: 'Análisis de seguridad', needsData: true },
  { id: 'timeline', step: '4', label: 'Línea de tiempo', title: 'Línea de tiempo del ataque', needsData: true },
  { id: 'dashboard', step: '5', label: 'Dashboard', title: 'Dashboard', needsData: true },
  { id: 'mitre', step: '6', label: 'MITRE / IoC', title: 'MITRE ATT&CK e indicadores de compromiso', needsData: true },
  { id: 'report', step: '7', label: 'Informe', title: 'Informe ejecutivo y técnico', needsData: true },
  { id: 'export', step: '8', label: 'Exportar PDF', title: 'Exportación a PDF', needsData: true },
  { id: 'config', step: '⚙', label: 'Configuración', title: 'Configuración' },
];

export default function Shell({ user, onLogout }) {
  const [view, setView] = useState('upload');
  const [dataset, setDataset] = useState(null);
  const [config, setConfig] = useState(DEFAULT_CONFIG);
  const [eventsFilter, setEventsFilter] = useState({});
  const [focus, setFocus] = useState(null);
  const [narratives, setNarratives] = useState(null);
  const [meta, setMeta] = useState(() => defaultMeta(user));
  const [audience, setAudience] = useState('ejecutivo');

  const analysis = useMemo(() => (dataset ? runAnalysis(dataset, config) : null), [dataset, config]);

  // Los textos del informe se regeneran por plantilla cuando cambia el análisis
  useEffect(() => {
    if (!analysis) return setNarratives(null);
    const n = defaultNarrative(dataset, analysis);
    setNarratives({ ejecutivo: n, tecnico: n });
  }, [analysis, dataset]);

  const current = NAV.find((n) => n.id === view);
  const nav = {
    go: setView,
    logout: onLogout,
    showEvents: (filter) => {
      setEventsFilter(filter);
      setView('events');
    },
    openFinding: (id) => {
      setFocus(id);
      setView('analysis');
    },
  };

  function renderView() {
    const ready = dataset && analysis && narratives;
    if (current.needsData && !ready) return null;
    switch (view) {
      case 'upload':
        return <Upload dataset={dataset} onLoaded={setDataset} onNext={() => setView('analysis')} />;
      case 'events':
        return <Events dataset={dataset} analysis={analysis} filter={eventsFilter} onClearFilter={() => setEventsFilter({})} nav={nav} />;
      case 'analysis':
        return <Analysis analysis={analysis} focus={focus} nav={nav} />;
      case 'timeline':
        return <Timeline dataset={dataset} analysis={analysis} nav={nav} />;
      case 'dashboard':
        return <Dashboard dataset={dataset} analysis={analysis} nav={nav} />;
      case 'mitre':
        return <Mitre analysis={analysis} nav={nav} />;
      case 'report':
        return (
          <Report
            dataset={dataset}
            analysis={analysis}
            narratives={narratives}
            setNarratives={setNarratives}
            meta={meta}
            setMeta={setMeta}
            audience={audience}
            setAudience={setAudience}
            nav={nav}
          />
        );
      case 'export':
        return <Export dataset={dataset} analysis={analysis} narratives={narratives} meta={meta} setMeta={setMeta} nav={nav} />;
      case 'config':
        return <Config config={config} setConfig={setConfig} analysis={analysis} />;
      default:
        return null;
    }
  }

  return (
    <motion.div className="shell" initial={{ opacity: 0 }} animate={{ opacity: 1 }} exit={{ opacity: 0 }} transition={{ duration: 0.4 }}>
      <aside className="sidebar">
        <div className="sidebar-brand">
          <Logo size={34} />
          <div>
            <strong>VIGÍA</strong>
            <small>SOC Nivel 2</small>
          </div>
        </div>

        <nav>
          {NAV.map((item, i) => {
            const disabled = item.needsData && !dataset;
            return (
              <motion.button
                key={item.id}
                className={`nav-item${view === item.id ? ' active' : ''}`}
                disabled={disabled}
                title={disabled ? 'Cargue primero el archivo de logs' : item.title}
                onClick={() => {
                  if (item.id === 'events') setEventsFilter({});
                  if (item.id === 'analysis') setFocus(null);
                  setView(item.id);
                }}
                initial={{ opacity: 0, x: -12 }}
                animate={{ opacity: 1, x: 0 }}
                transition={{ delay: 0.05 * i }}
              >
                <span className="nav-step">{item.step}</span>
                {item.label}
                {view === item.id && <motion.span layoutId="nav-indicator" className="nav-indicator" />}
              </motion.button>
            );
          })}
        </nav>

        {analysis && (
          <div className="sidebar-risk">
            <small>Riesgo global</small>
            <LevelBadge level={analysis.globalLevel} />
            <small>
              {analysis.stats.incidents} incidentes · {analysis.stats.findings} hallazgos
            </small>
          </div>
        )}
        <div className="sidebar-foot">Clasificación: CONFIDENCIAL</div>
      </aside>

      <div className="main">
        <header className="topbar">
          <h2>{current.title}</h2>
          <div className="topbar-right">
            {dataset && (
              <span className="chip" title={dataset.fileName}>
                <span className="dot ok" /> {dataset.fileName} · {dataset.events.length} eventos
              </span>
            )}
            <ThemeToggle />
            <span className="chip">
              <span className="avatar">{user.slice(0, 1).toUpperCase()}</span> {user}
            </span>
            <button className="btn btn-ghost" onClick={onLogout}>
              Cerrar sesión
            </button>
          </div>
        </header>

        {/* Solo animación de entrada: esperar la salida de una vista con animaciones de layout
            internas podía dejar la navegación bloqueada en una pantalla vacía */}
        <motion.main
          key={view}
          className="content"
          initial={{ opacity: 0, y: 12 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ duration: 0.25 }}
        >
          {renderView()}
        </motion.main>
      </div>
    </motion.div>
  );
}
