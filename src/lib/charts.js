// Opciones de ECharts compartidas por el dashboard, la línea de tiempo y el PDF
import { LEVELS } from './engine.js';

export const LEVEL_COLORS = { Crítico: '#dc2626', Alto: '#ea580c', Medio: '#ca8a04', Bajo: '#2563eb' };
const NORMAL_COLOR = '#64748b';
const FONT = "'Manrope Variable', Manrope, 'Segoe UI', sans-serif";

const LIGHT = { text: '#0f172a', muted: '#5b6b85', grid: '#e2e8f0', panel: '#ffffff', accent: '#0284c7' };
const DARK = { text: '#e2e8f0', muted: '#8a9bb8', grid: '#22304d', panel: '#111a2e', accent: '#38bdf8' };

export const palette = (theme) => (theme === 'light' ? LIGHT : DARK);

const hhmm = (t) => new Date(t).toISOString().slice(11, 16);

function base(c) {
  return {
    backgroundColor: 'transparent',
    textStyle: { fontFamily: FONT, color: c.text },
    tooltip: { backgroundColor: c.panel, borderColor: c.grid, textStyle: { color: c.text, fontFamily: FONT } },
    animationDuration: 900,
    animationEasing: 'cubicOut',
  };
}

const axis = (c) => ({
  axisLine: { lineStyle: { color: c.grid } },
  axisLabel: { color: c.muted, fontFamily: FONT },
  splitLine: { lineStyle: { color: c.grid, type: 'dashed' } },
});

export function levelDonut(analysis, c) {
  const data = [...LEVELS].reverse().map((l) => ({ name: l, value: analysis.stats.byLevel[l], itemStyle: { color: LEVEL_COLORS[l] } }));
  return {
    ...base(c),
    tooltip: { ...base(c).tooltip, trigger: 'item', formatter: '{b}: {c} hallazgos ({d}%)' },
    legend: { bottom: 0, textStyle: { color: c.muted, fontFamily: FONT } },
    title: {
      text: String(analysis.stats.findings),
      subtext: 'hallazgos',
      left: 'center',
      top: '36%',
      textStyle: { color: c.text, fontSize: 28, fontWeight: 700, fontFamily: FONT },
      subtextStyle: { color: c.muted, fontFamily: FONT },
    },
    series: [
      {
        type: 'pie',
        radius: ['52%', '76%'],
        center: ['50%', '45%'],
        itemStyle: { borderColor: c.panel, borderWidth: 3, borderRadius: 6 },
        label: { show: false },
        data: data.filter((d) => d.value > 0),
      },
    ],
  };
}

export function eventsOverTime(dataset, analysis, c, bucketMin = 10) {
  const size = bucketMin * 60_000;
  const first = Math.floor(dataset.events[0]._t / size) * size;
  const last = dataset.events[dataset.events.length - 1]._t;
  const buckets = [];
  for (let t = first; t <= last; t += size) buckets.push(t);
  const series = ['Normal', ...LEVELS].map((name) => ({ name, data: buckets.map(() => 0) }));
  for (const e of dataset.events) {
    const i = Math.floor((e._t - first) / size);
    const lvl = analysis.eventLevel.get(e.Log_ID);
    series[lvl ? LEVELS.indexOf(lvl) + 1 : 0].data[i]++;
  }
  return {
    ...base(c),
    tooltip: { ...base(c).tooltip, trigger: 'axis', axisPointer: { type: 'shadow' } },
    legend: { top: 0, textStyle: { color: c.muted, fontFamily: FONT } },
    grid: { left: 40, right: 16, top: 36, bottom: 30 },
    xAxis: { type: 'category', data: buckets.map(hhmm), ...axis(c), splitLine: { show: false } },
    yAxis: { type: 'value', ...axis(c) },
    series: series.map((s) => ({
      ...s,
      type: 'bar',
      stack: 'total',
      barCategoryGap: '20%',
      itemStyle: { color: s.name === 'Normal' ? NORMAL_COLOR : LEVEL_COLORS[s.name], opacity: s.name === 'Normal' ? 0.45 : 1 },
    })),
    _buckets: buckets,
    _bucketSize: size,
  };
}

export function topBar(entries, c, color) {
  const data = [...entries].reverse();
  return {
    ...base(c),
    tooltip: { ...base(c).tooltip, trigger: 'axis', axisPointer: { type: 'shadow' } },
    grid: { left: 8, right: 30, top: 8, bottom: 8, containLabel: true },
    xAxis: { type: 'value', ...axis(c) },
    yAxis: { type: 'category', data: data.map((d) => d[0]), ...axis(c), splitLine: { show: false } },
    series: [
      {
        type: 'bar',
        data: data.map((d) => d[1]),
        itemStyle: { color: color || c.accent, borderRadius: [0, 4, 4, 0] },
        label: { show: true, position: 'right', color: c.muted, fontFamily: FONT },
      },
    ],
  };
}

export function hostHourHeatmap(dataset, analysis, c) {
  const hosts = [...new Set(dataset.events.map((e) => e.Hostname))].sort();
  const hours = [...new Set(dataset.events.map((e) => e.Timestamp.slice(11, 13)))].sort();
  const counts = new Map();
  for (const e of dataset.events) {
    if (!analysis.eventLevel.has(e.Log_ID)) continue;
    const k = `${hours.indexOf(e.Timestamp.slice(11, 13))}|${hosts.indexOf(e.Hostname)}`;
    counts.set(k, (counts.get(k) || 0) + 1);
  }
  const data = [...counts].map(([k, v]) => [...k.split('|').map(Number), v]);
  return {
    ...base(c),
    tooltip: { ...base(c).tooltip, formatter: (p) => `${hosts[p.value[1]]} · ${hours[p.value[0]]}:00<br/>${p.value[2]} eventos sospechosos` },
    grid: { left: 8, right: 8, top: 8, bottom: 50, containLabel: true },
    xAxis: { type: 'category', data: hours.map((h) => `${h}:00`), ...axis(c), splitArea: { show: true, areaStyle: { color: ['transparent'] } } },
    yAxis: { type: 'category', data: hosts, ...axis(c) },
    visualMap: {
      min: 0,
      max: Math.max(1, ...data.map((d) => d[2])),
      calculable: true,
      orient: 'horizontal',
      left: 'center',
      bottom: 0,
      itemHeight: 120,
      textStyle: { color: c.muted },
      inRange: { color: ['#fde68a', '#f97316', '#b91c1c'] },
    },
    series: [{ type: 'heatmap', data, label: { show: true, color: '#111', fontFamily: FONT }, itemStyle: { borderColor: c.panel, borderWidth: 2 } }],
  };
}

export function siemVsAnalyst(dataset, analysis, c) {
  const order = ['Informational', 'Warning', 'Medium', 'High', 'Critical'];
  const sev = order.filter((s) => dataset.events.some((e) => e.Severity === s));
  const extra = [...new Set(dataset.events.map((e) => e.Severity))].filter((s) => !order.includes(s));
  const cats = [...sev, ...extra];
  const names = ['Sin hallazgo', ...LEVELS];
  const series = names.map((name) => ({ name, data: cats.map(() => 0) }));
  for (const e of dataset.events) {
    const lvl = analysis.eventLevel.get(e.Log_ID);
    series[lvl ? LEVELS.indexOf(lvl) + 1 : 0].data[cats.indexOf(e.Severity)]++;
  }
  return {
    ...base(c),
    tooltip: { ...base(c).tooltip, trigger: 'axis', axisPointer: { type: 'shadow' } },
    legend: { top: 0, textStyle: { color: c.muted, fontFamily: FONT } },
    grid: { left: 8, right: 16, top: 36, bottom: 8, containLabel: true },
    xAxis: { type: 'category', data: cats, name: 'Severity SIEM', nameLocation: 'middle', nameGap: 26, ...axis(c), splitLine: { show: false } },
    yAxis: { type: 'log', min: 1, ...axis(c) },
    series: series.map((s) => ({
      ...s,
      type: 'bar',
      data: s.data.map((v) => (v ? v : null)),
      itemStyle: { color: s.name === 'Sin hallazgo' ? NORMAL_COLOR : LEVEL_COLORS[s.name] },
    })),
  };
}
