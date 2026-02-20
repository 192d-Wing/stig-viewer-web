import s from './SeverityBadge.module.css'

export default function SeverityBadge({ severity }) {
  const cls = severity === 'CAT I' ? s.cat1 : severity === 'CAT II' ? s.cat2 : s.cat3
  return (
    <span className={`${s.badge} ${cls}`} aria-label={`Severity: ${severity}`}>
      {severity}
    </span>
  )
}
