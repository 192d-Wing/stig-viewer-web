import { useState, useCallback } from 'react'
import { exportPOAMCSV, exportPOAMJSON } from '../utils/exportPOAM.js'
import Modal from '@cloudscape-design/components/modal'
import Button from '@cloudscape-design/components/button'
import RadioGroup from '@cloudscape-design/components/radio-group'
import SpaceBetween from '@cloudscape-design/components/space-between'
import StatusIndicator from '@cloudscape-design/components/status-indicator'
import Box from '@cloudscape-design/components/box'

function downloadBlob(content, filename, mime) {
  const blob = new Blob([content], { type: mime })
  const url = URL.createObjectURL(blob)
  const anchor = document.createElement('a')
  anchor.href = url
  anchor.download = filename
  anchor.click()
  URL.revokeObjectURL(url)
}

export default function POAMExportModal({ show, onClose, stig, assetInfo }) {
  const [includeNonReviewed, setIncludeNonReviewed] = useState(false)

  const baseName = stig.title.replace(/[^a-zA-Z0-9]/g, '_')

  const handleCSV = useCallback(() => {
    const csv = exportPOAMCSV(stig, assetInfo, includeNonReviewed)
    downloadBlob(csv, `${baseName}_POAM.csv`, 'text/csv;charset=utf-8;')
  }, [stig, assetInfo, includeNonReviewed, baseName])

  const handleJSON = useCallback(() => {
    const rows = exportPOAMJSON(stig, assetInfo, includeNonReviewed)
    const json = JSON.stringify(rows, null, 2)
    downloadBlob(json, `${baseName}_POAM.json`, 'application/json')
  }, [stig, assetInfo, includeNonReviewed, baseName])

  const openCount = stig.rules.filter((r) => r.status === 'open').length
  const pendingCount = stig.rules.filter((r) => r.status === 'not_reviewed').length

  return (
    <Modal
      visible={show}
      onDismiss={onClose}
      header="Export POA&M"
      footer={
        <SpaceBetween direction="horizontal" size="xs">
          <div style={{ flex: 1 }} />
          <Button variant="link" onClick={onClose}>Cancel</Button>
          <Button onClick={handleJSON}>Download JSON</Button>
          <Button variant="primary" onClick={handleCSV}>Download CSV</Button>
        </SpaceBetween>
      }
    >
      <SpaceBetween size="l">
        {/* Counts */}
        <SpaceBetween direction="horizontal" size="l">
          <StatusIndicator type="error">{openCount} Open findings</StatusIndicator>
          <StatusIndicator type="pending">{pendingCount} Not Reviewed</StatusIndicator>
        </SpaceBetween>

        {/* Scope */}
        <Box>
          <Box margin={{ bottom: 'xs' }} fontSize="body-s" fontWeight="bold" color="text-label">
            Scope
          </Box>
          <RadioGroup
            value={includeNonReviewed ? 'all' : 'open'}
            onChange={({ detail }) => setIncludeNonReviewed(detail.value === 'all')}
            items={[
              { value: 'open', label: `Open findings only (${openCount} items)` },
              { value: 'all', label: `Open + Not Reviewed (${openCount + pendingCount} items)` },
            ]}
          />
        </Box>
      </SpaceBetween>
    </Modal>
  )
}
