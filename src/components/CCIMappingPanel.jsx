import Badge from '@cloudscape-design/components/badge'
import { CCI_MAP } from '../constants/cciMap.js'

export default function CCIMappingPanel({ cciIds }) {
  if (!cciIds || cciIds.length === 0) return null

  return (
    <div style={{ display: 'flex', flexWrap: 'wrap', gap: 6, marginTop: 6 }}>
      {cciIds.map((id) => {
        const mapping = CCI_MAP[id]
        return (
          <span
            key={id}
            title={mapping ? `${id}: ${mapping.title}` : id}
            aria-label={mapping ? `${id} maps to ${mapping.control}: ${mapping.title}` : id}
          >
            <Badge color={mapping ? 'blue' : 'grey'}>
              {mapping ? `${mapping.control} \u00b7 ${id}` : id}
            </Badge>
          </span>
        )
      })}
    </div>
  )
}
