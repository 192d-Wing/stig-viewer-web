import s from './StatCard.module.css'

export default function StatCard({ label, value, colorVar, onClick, active }) {
  return (
    <button
      type="button"
      onClick={onClick}
      className={`${s.card} ${active ? s.active : ''}`}
      style={{ '--card-color': colorVar }}
      aria-pressed={active}
    >
      <span className={s.value}>{value}</span>
      <span className={s.label}>{label}</span>
    </button>
  )
}
