export default function StatCard({ label, value, color, onClick, active }) {
  return (
    <button
      type="button"
      onClick={onClick}
      aria-pressed={active}
      style={{
        background: active ? `${color}1a` : '#1a2332',
        border: `1px solid ${active ? color : '#354150'}`,
        borderRadius: 6,
        padding: '10px 14px',
        cursor: 'pointer',
        textAlign: 'left',
        minWidth: 100,
        transition: 'background 0.15s, border-color 0.15s',
      }}
    >
      <span style={{
        display: 'block',
        fontSize: 22,
        fontWeight: 700,
        fontFamily: "'JetBrains Mono', monospace",
        color,
      }}>
        {value}
      </span>
      <span style={{
        display: 'block',
        fontSize: 10,
        color: '#8d99a8',
        textTransform: 'uppercase',
        letterSpacing: '0.08em',
        fontWeight: 600,
        marginTop: 2,
      }}>
        {label}
      </span>
    </button>
  )
}
