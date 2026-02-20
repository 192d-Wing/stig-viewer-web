import { useState, useCallback } from 'react'
import Header from '@cloudscape-design/components/header'
import Button from '@cloudscape-design/components/button'
import FileUpload from '@cloudscape-design/components/file-upload'
import SpaceBetween from '@cloudscape-design/components/space-between'
import Box from '@cloudscape-design/components/box'

export default function DropZone({ onFilesLoad, onLoadSample }) {
  const [files, setFiles] = useState([])
  const [dragOver, setDragOver] = useState(false)

  const handleFiles = useCallback(
    (fileList) => {
      if (fileList && fileList.length > 0) onFilesLoad(fileList)
    },
    [onFilesLoad],
  )

  const handleDrop = useCallback(
    (e) => {
      e.preventDefault()
      setDragOver(false)
      handleFiles(e.dataTransfer?.files)
    },
    [handleFiles],
  )

  return (
    <div
      onDragOver={(e) => { e.preventDefault(); setDragOver(true) }}
      onDragLeave={() => setDragOver(false)}
      onDrop={handleDrop}
      style={{ textAlign: 'center', maxWidth: 560, width: '100%', margin: '0 auto' }}
    >
      <SpaceBetween size="l">
        {/* Brand */}
        <div style={{ display: 'inline-flex', alignItems: 'center', gap: 12, marginBottom: 8 }}>
          <svg width="40" height="40" viewBox="0 0 40 40" fill="none" aria-hidden="true">
            <rect width="40" height="40" rx="8" fill="#539fe5" />
            <path d="M12 10h16v4H12zM12 17h16v2H12zM12 22h16v2H12zM12 27h10v2H12z" fill="#0f1b2e" />
            <path d="M28 22l4 4-4 4" stroke="#0f1b2e" strokeWidth="2.5" strokeLinecap="round" strokeLinejoin="round" />
          </svg>
          <Header variant="h1" description="Web Edition v3.0">
            STIG Viewer
          </Header>
        </div>

        {/* File upload area */}
        <div style={{
          border: `2px dashed ${dragOver ? '#539fe5' : '#354150'}`,
          borderRadius: 12,
          padding: '48px 32px',
          background: dragOver ? '#539fe510' : 'transparent',
          transition: 'border-color 0.2s, background 0.2s',
        }}>
          <Box textAlign="center">
            <SpaceBetween size="m">
              <svg
                width="48"
                height="48"
                viewBox="0 0 48 48"
                fill="none"
                style={{ margin: '0 auto', display: 'block', opacity: 0.5 }}
                aria-hidden="true"
              >
                <path
                  d="M24 32V16m0 0l-8 8m8-8l8 8M8 36h32"
                  stroke="#8d99a8"
                  strokeWidth="2"
                  strokeLinecap="round"
                  strokeLinejoin="round"
                />
              </svg>
              <FileUpload
                value={files}
                onChange={({ detail }) => {
                  setFiles(detail.value)
                  if (detail.value.length > 0) handleFiles(detail.value)
                }}
                accept=".xml,.ckl"
                multiple
                constraintText="Supports XCCDF (.xml) and Checklist (.ckl)"
                i18nStrings={{
                  uploadButtonText: (e) => e ? 'Choose files' : 'Choose file',
                  dropzoneText: (e) => e ? 'Drop files to upload' : 'Drop file to upload',
                  removeFileAriaLabel: (e) => `Remove file ${e + 1}`,
                  limitShowFewer: 'Show fewer files',
                  limitShowMore: 'Show more files',
                  errorIconAriaLabel: 'Error',
                }}
              />
            </SpaceBetween>
          </Box>
        </div>

        {/* Demo button */}
        <Button variant="link" onClick={onLoadSample}>
          Load Demo STIG
        </Button>
      </SpaceBetween>
    </div>
  )
}
