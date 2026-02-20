import StatusIndicator from '@cloudscape-design/components/status-indicator'
import { STATUS_INDICATOR_TYPE, STATUS_LABEL } from '../../constants/cloudscapeHelpers.js'

export default function StatusBadge({ status }) {
  return (
    <StatusIndicator type={STATUS_INDICATOR_TYPE[status] || 'pending'}>
      {STATUS_LABEL[status] || status}
    </StatusIndicator>
  )
}
