import { useEffect, useRef } from 'react';
import * as echarts from 'echarts';

export default function EChart({ option, height = 300, onClick, notMerge = true }) {
  const ref = useRef(null);
  const chart = useRef(null);

  useEffect(() => {
    chart.current = echarts.init(ref.current, null, { renderer: 'canvas' });
    const observer = new ResizeObserver(() => chart.current?.resize());
    observer.observe(ref.current);
    return () => {
      observer.disconnect();
      chart.current.dispose();
      chart.current = null;
    };
  }, []);

  useEffect(() => {
    chart.current?.setOption(option, notMerge);
  }, [option, notMerge]);

  useEffect(() => {
    const c = chart.current;
    if (!c) return;
    c.off('click');
    if (onClick) c.on('click', onClick);
  }, [onClick]);

  return <div ref={ref} style={{ height, width: '100%', cursor: onClick ? 'pointer' : 'default' }} />;
}
