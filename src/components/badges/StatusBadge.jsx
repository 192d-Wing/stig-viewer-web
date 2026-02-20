import { STATUS_OPTIONS } from '../../constants/status.js'
import s from './StatusBadge.module.css'

export default function StatusBadge({ status, small = false }) {
  const opt = STATUS_OPTIONS.find((o) => o.value === status) ?? STATUS_OPTIONS[0]
  return (
    <span
      className={`${s.badge} ${s[status]} ${small ? s.small : ''}`}
      aria-label={`Status: ${opt.label}`}
    >
      <span className={s.dot} aria-hidden="true" />
      {opt.label}
    </span>
  )
}
