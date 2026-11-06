export default function Logo({ size = 40 }) {
  return (
    <svg width={size} height={size} viewBox="0 0 48 48" fill="none" aria-hidden="true">
      <path
        d="M24 3 6 10v12c0 11.5 7.7 20.6 18 23 10.3-2.4 18-11.5 18-23V10L24 3Z"
        stroke="var(--accent)"
        strokeWidth="2.5"
        fill="rgba(56,189,248,.08)"
      />
      <path d="M12 24s4.5-7 12-7 12 7 12 7-4.5 7-12 7-12-7-12-7Z" stroke="var(--text)" strokeWidth="2" />
      <circle cx="24" cy="24" r="3.5" fill="var(--accent)" />
    </svg>
  );
}
