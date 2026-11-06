import { useMemo, useState } from 'react';
import { motion } from 'framer-motion';
import EChart from '../components/EChart.jsx';
import CountUp from '../components/CountUp.jsx';
import EventsTable from '../components/EventsTable.jsx';
import { LEVELS } from '../lib/engine.js';
import { LEVEL_COLORS, eventsOverTime, hostHourHeatmap, levelDonut, palette, siemVsAnalyst, topBar } from '../lib/charts.js';
import { useTheme } from '../theme.jsx';

const top = (events, key, n = 8) =>
  Object.entries(events.reduce((acc, e) => ((acc[e[key]] = (acc[e[key]] || 0) + 1), acc), {}))
    .sort((a, b) => b[1] - a[1])
    .slice(0, n);
const hhmm = (t) => new Date(t).toISOString().slice(11, 16);

export default function Dashboard({ dataset, analysis, nav }) {
  const { theme } = useTheme();
  const c = palette(theme);
  const [filter, setFilter] = useState({ level: 'sospechoso', label: 'Eventos sospechosos (todos los incidentes)' });

  const suspicious = useMemo(() => dataset.events.filter((e) => analysis.eventLevel.has(e.Log_ID)), [dataset, analysis]);
  const timeOpt = useMemo(() => eventsOverTime(dataset, analysis, c, 10), [dataset, analysis, c]);
  const charts = useMemo(
    () => ({
      donut: levelDonut(analysis, c),
      ips: topBar(top(suspicious, 'Source_IP'), c, '#ea580c'),
      users: topBar(top(suspicious, 'User'), c, '#ca8a04'),
      hosts: topBar(top(suspicious, 'Hostname'), c, c.accent),
      eventIds: topBar(top(dataset.events, 'Event_ID', 15), c, '#64748b'),
      heat: hostHourHeatmap(dataset, analysis, c),
      siem: siemVsAnalyst(dataset, analysis, c),
    }),
    [dataset, analysis, suspicious, c]
  );

  const { stats } = analysis;
  const kpis = [
    { label: 'Eventos analizados', value: stats.totalEvents },
    { label: 'Eventos sospechosos', value: stats.suspiciousEvents, cls: 'high' },
    { label: 'Incidentes', value: stats.incidents, cls: 'critical' },
    { label: 'Hallazgos críticos', value: stats.byLevel.Crítico, cls: 'critical' },
    { label: 'Hallazgos altos', value: stats.byLevel.Alto, cls: 'high' },
    { label: 'Hallazgos medios', value: stats.byLevel.Medio, cls: 'medium' },
    { label: 'Equipos afectados', value: stats.affectedHosts.length },
    { label: 'Cuentas implicadas', value: stats.affectedUsers.length },
    { label: 'MB exfiltrados', value: Math.round(stats.exfilBytes / 1e6), cls: 'critical' },
  ];

  const pick = (next) => {
    setFilter(next);
    setTimeout(() => document.getElementById('dash-table')?.scrollIntoView({ behavior: 'smooth', block: 'start' }), 50);
  };

  return (
    <div className="page">
      <motion.div className="kpi-grid" initial="hidden" animate="show" variants={{ show: { transition: { staggerChildren: 0.05 } } }}>
        {kpis.map((k) => (
          <motion.div key={k.label} className={`stat card ${k.cls || ''}`} variants={{ hidden: { opacity: 0, y: 12 }, show: { opacity: 1, y: 0 } }}>
            <div className="stat-value">
              <CountUp value={k.value} />
            </div>
            <div className="stat-label">{k.label}</div>
          </motion.div>
        ))}
      </motion.div>

      <div className="dash-grid">
        <Panel title="Hallazgos por criticidad" hint="Clic en un segmento para filtrar">
          <EChart option={charts.donut} height={280} onClick={(p) => pick({ level: p.name, label: `Eventos de criticidad ${p.name}` })} />
        </Panel>
        <Panel title="Eventos en el tiempo (10 min)" hint="Clic en una barra para ver ese intervalo" wide>
          <EChart
            option={timeOpt}
            height={280}
            onClick={(p) => {
              const start = timeOpt._buckets[p.dataIndex];
              const end = start + timeOpt._bucketSize - 60_000;
              pick({ from: hhmm(start), to: hhmm(end), level: p.seriesName === 'Normal' ? '' : p.seriesName, label: `${hhmm(start)}–${hhmm(end + 60_000)} · ${p.seriesName}` });
            }}
          />
        </Panel>
        <Panel title="Top IPs (eventos sospechosos)">
          <EChart option={charts.ips} height={250} onClick={(p) => pick({ ip: p.name, label: `IP ${p.name}` })} />
        </Panel>
        <Panel title="Top cuentas (eventos sospechosos)">
          <EChart option={charts.users} height={250} onClick={(p) => pick({ user: p.name, label: `Cuenta ${p.name}` })} />
        </Panel>
        <Panel title="Top equipos (eventos sospechosos)">
          <EChart option={charts.hosts} height={250} onClick={(p) => pick({ host: p.name, label: `Equipo ${p.name}` })} />
        </Panel>
        <Panel title="Mapa de calor equipo × hora" hint="Eventos sospechosos" wide>
          <EChart
            option={charts.heat}
            height={320}
            onClick={(p) => {
              const host = charts.heat.yAxis.data[p.value[1]];
              const hour = charts.heat.xAxis.data[p.value[0]].slice(0, 2);
              pick({ host, from: `${hour}:00`, to: `${hour}:59`, level: 'sospechoso', label: `${host} entre ${hour}:00 y ${hour}:59` });
            }}
          />
        </Panel>
        <Panel title="Distribución por Event_ID">
          <EChart option={charts.eventIds} height={320} onClick={(p) => pick({ eventId: p.name, label: `Event_ID ${p.name}` })} />
        </Panel>
        <Panel title="Severity del SIEM frente a criticidad del analista" hint="Escala logarítmica" wide>
          <EChart option={charts.siem} height={280} />
          <p className="muted small">
            Muchos eventos que el SIEM marcó como <b>Informational</b> forman parte de incidentes críticos: la severidad del
            SIEM no sustituye la correlación.
          </p>
        </Panel>
      </div>

      <div className="legend-row">
        {LEVELS.slice().reverse().map((l) => (
          <span key={l}>
            <i style={{ background: LEVEL_COLORS[l] }} /> {l}
          </span>
        ))}
      </div>

      <div id="dash-table">
        <h3 className="section-title">Eventos seleccionados</h3>
        <EventsTable dataset={dataset} analysis={analysis} filter={filter} onClearFilter={() => setFilter({})} onOpenFinding={nav.openFinding} />
      </div>
    </div>
  );
}

function Panel({ title, hint, wide, children }) {
  return (
    <motion.section className={`card panel${wide ? ' wide' : ''}`} initial={{ opacity: 0, y: 16 }} whileInView={{ opacity: 1, y: 0 }} viewport={{ once: true }}>
      <div className="row-between">
        <h4>{title}</h4>
        {hint && <small className="muted">{hint}</small>}
      </div>
      {children}
    </motion.section>
  );
}
