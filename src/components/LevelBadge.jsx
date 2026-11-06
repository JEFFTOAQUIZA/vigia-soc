const CLASS = { Crítico: 'critical', Alto: 'high', Medio: 'medium', Bajo: 'low' };

export default function LevelBadge({ level, small = false }) {
  if (!level) return <span className="level-badge none">—</span>;
  return <span className={`level-badge ${CLASS[level]}${small ? ' small' : ''}`}>{level}</span>;
}

export const levelClass = (level) => CLASS[level] || 'none';
