import { useEffect, useMemo, useState } from 'react';
import { motion } from 'framer-motion';
import EChart from '../components/EChart.jsx';
import LevelBadge from '../components/LevelBadge.jsx';
import { LEVEL_COLORS, palette } from '../lib/charts.js';
import { useTheme } from '../theme.jsx';

const STEP_MS = 2 * 60_000;
const hhmm = (t) => new Date(t).toISOString().slice(11, 16);
const hhmmss = (ts) => ts.slice(11, 19);

export default function Timeline({ dataset, analysis, nav }) {
  const { theme } = useTheme();
  const c = palette(theme);
  const min = dataset.events[0]._t - 5 * 60_000;
  const max = dataset.events[dataset.events.length - 1]._t + 5 * 60_000;
  const [cursor, setCursor] = useState(max);
  const [playing, setPlaying] = useState(false);

  useEffect(() => {
    if (!playing) return;
    const id = setInterval(() => {
      setCursor((t) => {
        if (t + STEP_MS >= max) {
          setPlaying(false);
          return max;
        }
        return t + STEP_MS;
      });
    }, 90);
    return () => clearInterval(id);
  }, [playing, max]);

  function play() {
    if (cursor >= max) setCursor(min);
    setPlaying(true);
  }

  const lanes = useMemo(() => ['Actividad normal', ...[...analysis.incidents].reverse().map((i) => i.id)], [analysis]);
  const points = useMemo(() => {
    const normal = dataset.events
      .filter((e) => !analysis.eventLevel.has(e.Log_ID))
      .map((e) => ({ value: [e._t, 0], e, lvl: null }));
    const flagged = analysis.incidents.flatMap((inc) =>
      inc.evidence.map((e) => ({ value: [e._t, lanes.indexOf(inc.id)], e, lvl: analysis.eventLevel.get(e.Log_ID) }))
    );
    return [...normal, ...flagged];
  }, [dataset, analysis, lanes]);

  const option = useMemo(
    () => ({
      backgroundColor: 'transparent',
      textStyle: { fontFamily: "'Manrope Variable', Manrope, sans-serif", color: c.text },
      animationDurationUpdate: 120,
      grid: { left: 70, right: 24, top: 20, bottom: 60 },
      tooltip: {
        backgroundColor: c.panel,
        borderColor: c.grid,
        textStyle: { color: c.text },
        formatter: (p) => {
          const e = p.data.e;
          return `<b>${e.Log_ID}</b> · ${e.Timestamp.slice(11)}<br/>${e.Hostname} · ${e.Event_ID} · ${e.User}<br/>${e.Process_CommandLine || e.Event_Description}`;
        },
      },
      xAxis: {
        type: 'value',
        min,
        max,
        axisLabel: { formatter: (v) => hhmm(v), color: c.muted },
        axisLine: { lineStyle: { color: c.grid } },
        splitLine: { lineStyle: { color: c.grid, type: 'dashed' } },
      },
      yAxis: {
        type: 'category',
        data: lanes,
        axisLabel: { color: c.text, fontWeight: 600 },
        axisLine: { lineStyle: { color: c.grid } },
        splitLine: { show: true, lineStyle: { color: c.grid } },
      },
      dataZoom: [
        { type: 'inside', xAxisIndex: 0 },
        { type: 'slider', xAxisIndex: 0, height: 18, bottom: 12, labelFormatter: (v) => hhmm(v), textStyle: { color: c.muted } },
      ],
      series: [
        {
          type: 'scatter',
          data: points
            .filter((p) => p.value[0] <= cursor)
            .map((p) => ({
              ...p,
              symbolSize: p.lvl ? 11 : 5,
              itemStyle: { color: p.lvl ? LEVEL_COLORS[p.lvl] : '#64748b', opacity: p.lvl ? 0.9 : 0.35, borderColor: c.panel, borderWidth: p.lvl ? 1 : 0 },
            })),
          markLine: {
            silent: true,
            symbol: 'none',
            animation: false,
            lineStyle: { color: c.accent, width: 2 },
            label: { formatter: () => hhmm(cursor), color: c.accent, fontWeight: 700 },
            data: cursor < max ? [{ xAxis: cursor }] : [],
          },
        },
      ],
    }),
    [points, lanes, cursor, min, max, c]
  );

  return (
    <div className="page">
      <div className="card">
        <div className="row-between">
          <p className="lead no-margin">
            Cada carril es un incidente; los puntos grises son actividad normal. Pulse <b>Reproducir</b> para ver cómo se
            desarrolló el día.
          </p>
          <div className="player">
            <span className="mono clock">{hhmm(Math.min(cursor, max))}</span>
            {playing ? (
              <button className="btn btn-primary" onClick={() => setPlaying(false)}>
                ❚❚ Pausa
              </button>
            ) : (
              <button className="btn btn-primary" onClick={play}>
                ▶ Reproducir
              </button>
            )}
            <button
              className="btn btn-ghost"
              onClick={() => {
                setPlaying(false);
                setCursor(max);
              }}
            >
              Ver todo
            </button>
          </div>
        </div>
        <EChart option={option} height={360} notMerge={false} onClick={(p) => p.data?.e && nav.showEvents({ ids: [p.data.e.Log_ID], label: p.data.e.Log_ID })} />
      </div>

      <h3 className="section-title">Cadena de ataque por incidente</h3>
      <div className="stack">
        {analysis.incidents.map((inc) => (
          <div key={inc.id} className="card chain-card">
            <div className="chain-head">
              <b className="mono">{inc.id}</b>
              <LevelBadge level={inc.level} small />
              <span className="muted small">
                {hhmmss(inc.start)}–{hhmmss(inc.end)}
              </span>
            </div>
            <div className="chain-steps">
              {inc.findings.map((f, i) => {
                const reached = cursor >= f._start;
                return (
                  <div key={f.id} className="chain-item">
                    <motion.button
                      className={`chain-node lvl-${f.level}${reached ? ' reached' : ''}`}
                      animate={{ opacity: reached ? 1 : 0.3, scale: reached ? 1 : 0.94 }}
                      transition={{ duration: 0.3 }}
                      onClick={() => nav.openFinding(f.id)}
                      title={f.title}
                    >
                      <small className="mono">
                        {hhmmss(f.start)} · {f.id}
                      </small>
                      <span>{f.short}</span>
                    </motion.button>
                    {i < inc.findings.length - 1 && (
                      <motion.span className="chain-arrow" animate={{ opacity: cursor >= inc.findings[i + 1]._start ? 1 : 0.25 }}>
                        →
                      </motion.span>
                    )}
                  </div>
                );
              })}
            </div>
          </div>
        ))}
      </div>

      <h3 className="section-title">Línea de tiempo consolidada</h3>
      <div className="table-wrap card">
        <table className="data">
          <thead>
            <tr>
              <th>Inicio</th>
              <th>Fin</th>
              <th>Incidente</th>
              <th>Hallazgo</th>
              <th>Criticidad</th>
            </tr>
          </thead>
          <tbody>
            {[...analysis.findings]
              .sort((a, b) => a._start - b._start)
              .map((f) => (
                <tr key={f.id} onClick={() => nav.openFinding(f.id)}>
                  <td className="mono">{hhmmss(f.start)}</td>
                  <td className="mono">{hhmmss(f.end)}</td>
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
      </div>
    </div>
  );
}
