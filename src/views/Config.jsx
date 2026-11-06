import { DEFAULT_CONFIG } from '../lib/engine.js';
import { ThemeToggle } from '../theme.jsx';

const NUMBERS = [
  ['sprayMinAccounts', 'Password spraying: cuentas distintas mínimas', 'R-01'],
  ['sprayWindowMin', 'Password spraying: ventana (min)', 'R-01'],
  ['bruteMinFailures', 'Fuerza bruta: fallos mínimos usuario+IP', 'R-02'],
  ['bruteWindowMin', 'Fuerza bruta: ventana (min)', 'R-02'],
  ['successLookaheadMin', 'Éxito posterior: búsqueda (min)', 'R-01/R-02'],
  ['webMinRequests', 'Web: peticiones mínimas de una IP', 'R-05'],
  ['webWindowMin', 'Web: ventana (min)', 'R-05'],
  ['massAccessMin', 'Acceso masivo: archivos mínimos', 'R-09'],
  ['massAccessWindowMin', 'Acceso masivo: ventana (min)', 'R-09'],
  ['exfilMinMB', 'Exfiltración: volumen mínimo (MB)', 'R-10'],
  ['commandGapMin', 'Agrupar comandos del mismo usuario (min)', 'R-07'],
  ['correlationGapMin', 'Correlación de hallazgos en incidentes (min)', 'Correlación'],
  ['workStart', 'Horario laboral: inicio (h)', 'R-03'],
  ['workEnd', 'Horario laboral: fin (h)', 'R-03'],
];
const LISTS = [
  ['criticalAssets', 'Activos críticos (DC, servidores de archivos, BD)'],
  ['privilegedAccounts', 'Cuentas privilegiadas autorizadas'],
  ['serviceAccounts', 'Cuentas de servicio'],
];

export default function Config({ config, setConfig, analysis }) {
  const setNum = (k) => (e) => setConfig({ ...config, [k]: Math.max(0, Number(e.target.value) || 0) });
  const setList = (k) => (e) => setConfig({ ...config, [k]: e.target.value.split('\n').map((s) => s.trim()).filter(Boolean) });
  const changed = JSON.stringify(config) !== JSON.stringify(DEFAULT_CONFIG);

  return (
    <div className="page config">
      <div className="card row-between">
        <div>
          <h4 className="plain">Apariencia</h4>
          <p className="muted small no-margin">Toda la aplicación en modo negro (oscuro) o blanco (claro). Se recuerda en este navegador.</p>
        </div>
        <ThemeToggle />
      </div>

      <div className="card">
        <div className="row-between">
          <h4 className="plain">Umbrales de detección</h4>
          <button className="btn btn-ghost sm" onClick={() => setConfig(DEFAULT_CONFIG)} disabled={!changed}>
            Restablecer valores por defecto
          </button>
        </div>
        <p className="muted small">
          {analysis
            ? `Con la configuración actual: ${analysis.stats.incidents} incidentes, ${analysis.stats.anomalies} anomalías y ${analysis.stats.findings} hallazgos.`
            : 'Cargue un archivo para ver el efecto de los cambios.'}{' '}
          El análisis se recalcula al instante y es reproducible: el mismo archivo con los mismos umbrales da siempre el mismo resultado.
        </p>
        <div className="config-grid">
          {NUMBERS.map(([k, label, rule]) => (
            <label key={k} className="field compact">
              <span>
                {label} <em className="muted">({rule})</em>
              </span>
              <input className="input" type="number" min="0" value={config[k]} onChange={setNum(k)} />
            </label>
          ))}
        </div>
      </div>

      <div className="config-lists">
        {LISTS.map(([k, label]) => (
          <label key={k} className="card field">
            <span>{label} — una por línea</span>
            <textarea className="input" rows={5} value={config[k].join('\n')} onChange={setList(k)} />
          </label>
        ))}
      </div>
    </div>
  );
}
