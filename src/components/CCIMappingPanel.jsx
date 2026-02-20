import { CCI_MAP } from '../constants/cciMap.js'
import s from './CCIMappingPanel.module.css'

export default function CCIMappingPanel({ cciIds }) {
  if (!cciIds || cciIds.length === 0) return null

  return (
    <div className={s.panel}>
      {cciIds.map((id) => {
        const mapping = CCI_MAP[id]
        return (
          <span
            key={id}
            className={`${s.pill} ${mapping ? s.mapped : s.unknown}`}
            title={mapping ? `${id}: ${mapping.title}` : id}
            aria-label={mapping ? `${id} maps to ${mapping.control}: ${mapping.title}` : id}
          >
            {mapping ? (
              <>
                <span className={s.control}>{mapping.control}</span>
                <span className={s.cciId}>{id}</span>
              </>
            ) : (
              <span className={s.cciId}>{id}</span>
            )}
          </span>
        )
      })}
    </div>
  )
}
