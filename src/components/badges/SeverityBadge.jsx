import Badge from '@cloudscape-design/components/badge'
import { SEVERITY_BADGE_COLOR } from '../../constants/cloudscapeHelpers.js'

export default function SeverityBadge({ severity }) {
  return <Badge color={SEVERITY_BADGE_COLOR[severity] || 'grey'}>{severity}</Badge>
}
