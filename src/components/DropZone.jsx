import { useState, useRef, useCallback } from 'react'
import s from './DropZone.module.css'

export default function DropZone({ onFilesLoad, onLoadSample }) {
  const [dragOver, setDragOver] = useState(false)
  const fileInputRef = useRef(null)

  const handleFiles = useCallback(
    (files) => {
      if (files && files.length > 0) onFilesLoad(files)
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

  const handleDragOver = useCallback((e) => {
    e.preventDefault()
    setDragOver(true)
  }, [])

  const handleDragLeave = useCallback(() => setDragOver(false), [])

  return (
    <div
      className={s.page}
      onDragOver={handleDragOver}
      onDragLeave={handleDragLeave}
      onDrop={handleDrop}
    >
      <div className={s.center}>
        {/* Brand */}
        <div className={s.brand}>
          <svg width="40" height="40" viewBox="0 0 40 40" fill="none" aria-hidden="true">
            <rect width="40" height="40" rx="8" fill="#c9a227" />
            <path d="M12 10h16v4H12zM12 17h16v2H12zM12 22h16v2H12zM12 27h10v2H12z" fill="#0f1115" />
            <path d="M28 22l4 4-4 4" stroke="#0f1115" strokeWidth="2.5" strokeLinecap="round" strokeLinejoin="round" />
          </svg>
          <div>
            <h1 className={s.appName}>STIG Viewer</h1>
            <p className={s.appVersion}>WEB EDITION v3.0</p>
          </div>
        </div>

        {/* Drop target */}
        <button
          type="button"
          className={`${s.dropZone} ${dragOver ? s.dragOver : ''}`}
          onClick={() => fileInputRef.current?.click()}
          aria-label="Click to select STIG files, or drag and drop files here"
        >
          <svg
            width="48"
            height="48"
            viewBox="0 0 48 48"
            fill="none"
            className={s.uploadIcon}
            aria-hidden="true"
          >
            <path
              d="M24 32V16m0 0l-8 8m8-8l8 8M8 36h32"
              stroke="currentColor"
              strokeWidth="2"
              strokeLinecap="round"
              strokeLinejoin="round"
            />
          </svg>
          <p className={s.dropTitle}>Drop STIG files or click to browse</p>
          <p className={s.dropSub}>
            Supports XCCDF (.xml) and Checklist (.ckl) · Multiple files supported
          </p>
          <input
            ref={fileInputRef}
            type="file"
            accept=".xml,.ckl"
            multiple
            className={s.hiddenInput}
            aria-hidden="true"
            tabIndex={-1}
            onChange={(e) => handleFiles(e.target.files)}
          />
        </button>

        {/* Demo */}
        <button type="button" onClick={onLoadSample} className={s.demoBtn}>
          Load Demo STIG
        </button>
      </div>
    </div>
  )
}
