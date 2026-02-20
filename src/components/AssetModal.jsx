import s from './AssetModal.module.css'

const FIELDS = [
  { key: 'hostname', label: 'Hostname' },
  { key: 'ip', label: 'IP Address' },
  { key: 'mac', label: 'MAC Address' },
  { key: 'fqdn', label: 'FQDN' },
]

export default function AssetModal({ show, onClose, assetInfo, onUpdate }) {
  if (!show) return null

  return (
    <div
      className={s.backdrop}
      onClick={onClose}
      role="dialog"
      aria-modal="true"
      aria-label="Asset Information"
    >
      <div className={s.modal} onClick={(e) => e.stopPropagation()}>
        <h2 className={s.title}>Asset Information</h2>
        {FIELDS.map(({ key, label }) => (
          <div key={key} className={s.field}>
            <label htmlFor={`asset-${key}`} className={s.fieldLabel}>
              {label}
            </label>
            <input
              id={`asset-${key}`}
              type="text"
              value={assetInfo[key]}
              onChange={(e) => onUpdate({ ...assetInfo, [key]: e.target.value })}
              className={s.input}
              autoComplete="off"
            />
          </div>
        ))}
        <div className={s.actions}>
          <button type="button" onClick={onClose} className={s.doneBtn}>
            Done
          </button>
        </div>
      </div>
    </div>
  )
}
