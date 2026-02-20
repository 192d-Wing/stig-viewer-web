import Modal from '@cloudscape-design/components/modal'
import Button from '@cloudscape-design/components/button'
import FormField from '@cloudscape-design/components/form-field'
import Input from '@cloudscape-design/components/input'
import SpaceBetween from '@cloudscape-design/components/space-between'

const FIELDS = [
  { key: 'hostname', label: 'Hostname' },
  { key: 'ip', label: 'IP Address' },
  { key: 'mac', label: 'MAC Address' },
  { key: 'fqdn', label: 'FQDN' },
]

export default function AssetModal({ show, onClose, assetInfo, onUpdate }) {
  return (
    <Modal
      visible={show}
      onDismiss={onClose}
      header="Asset Information"
      footer={
        <div style={{ display: 'flex', justifyContent: 'flex-end' }}>
          <Button variant="primary" onClick={onClose}>Done</Button>
        </div>
      }
    >
      <SpaceBetween size="m">
        {FIELDS.map(({ key, label }) => (
          <FormField key={key} label={label}>
            <Input
              value={assetInfo[key]}
              onChange={({ detail }) => onUpdate({ ...assetInfo, [key]: detail.value })}
              autoComplete={false}
            />
          </FormField>
        ))}
      </SpaceBetween>
    </Modal>
  )
}
