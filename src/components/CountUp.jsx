import { useEffect, useRef } from 'react';
import { animate } from 'framer-motion';

export default function CountUp({ value, duration = 1.1 }) {
  const ref = useRef(null);

  useEffect(() => {
    const controls = animate(0, value, {
      duration,
      ease: 'easeOut',
      onUpdate: (v) => {
        if (ref.current) ref.current.textContent = Math.round(v).toLocaleString('es');
      },
    });
    return () => controls.stop();
  }, [value, duration]);

  return <span ref={ref}>0</span>;
}
