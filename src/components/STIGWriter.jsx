import { useState, useEffect, useRef, useMemo, useCallback } from 'react'
import { parseXCCDF } from '../utils/parseXCCDF.js'
import { parseCKL } from '../utils/parseCKL.js'
import { exportXCCDF } from '../utils/exportXCCDF.js'
import { apiGet, apiJson } from '../utils/api.js'
import Header from '@cloudscape-design/components/header'
import Button from '@cloudscape-design/components/button'
import SpaceBetween from '@cloudscape-design/components/space-between'
import Container from '@cloudscape-design/components/container'
import ColumnLayout from '@cloudscape-design/components/column-layout'
import Tabs from '@cloudscape-design/components/tabs'
import Table from '@cloudscape-design/components/table'
import Box from '@cloudscape-design/components/box'
import FormField from '@cloudscape-design/components/form-field'
import Input from '@cloudscape-design/components/input'
import Textarea from '@cloudscape-design/components/textarea'
import Select from '@cloudscape-design/components/select'
import Modal from '@cloudscape-design/components/modal'
import Alert from '@cloudscape-design/components/alert'
import Badge from '@cloudscape-design/components/badge'
import StatusIndicator from '@cloudscape-design/components/status-indicator'

const SEVERITY_OPTIONS = [
  { label: 'CAT I (High)', value: 'CAT I' },
  { label: 'CAT II (Medium)', value: 'CAT II' },
  { label: 'CAT III (Low)', value: 'CAT III' },
]

const SEVERITY_BADGE_COLOR = {
  'CAT I': 'red',
  'CAT II': 'blue',
  'CAT III': 'grey',
}

const STATUS_BADGE = {
  draft: { color: 'grey', label: 'Draft' },
  submitted: { color: 'blue', label: 'Submitted' },
  in_review: { color: 'blue', label: 'In Review' },
  approved: { color: 'green', label: 'Approved' },
  rejected: { color: 'red', label: 'Rejected' },
}

// ── Drafts Table (landing page) ──────────────────────────────────────────────

function DraftsTable({ onOpenDraft, onRefresh }) {
  const [drafts, setDrafts] = useState([])
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState(null)
  const [creating, setCreating] = useState(false)

  const fetchDrafts = useCallback(async () => {
    setLoading(true)
    setError(null)
    try {
      const data = await apiGet('/api/drafts')
      setDrafts(data)
    } catch (err) {
      setError(err.message)
    } finally {
      setLoading(false)
    }
  }, [])

  useEffect(() => { fetchDrafts() }, [fetchDrafts])

  // Allow parent to trigger refresh
  useEffect(() => {
    if (onRefresh) onRefresh.current = fetchDrafts
  }, [onRefresh, fetchDrafts])

  const handleCreate = useCallback(async () => {
    setCreating(true)
    try {
      const draft = await apiJson('/api/drafts', 'POST')
      onOpenDraft(draft.id)
    } catch (err) {
      setError(err.message)
    } finally {
      setCreating(false)
    }
  }, [onOpenDraft])

  const handleDelete = useCallback(async (id) => {
    try {
      await apiJson(`/api/drafts/${encodeURIComponent(id)}`, 'DELETE')
      fetchDrafts()
    } catch (err) {
      setError(err.message)
    }
  }, [fetchDrafts])

  const columnDefinitions = [
    {
      id: 'title',
      header: 'Title',
      cell: (item) => item.title || '(untitled)',
      sortingComparator: (a, b) => a.title.localeCompare(b.title),
    },
    {
      id: 'status',
      header: 'Status',
      cell: (item) => {
        const s = STATUS_BADGE[item.status] || STATUS_BADGE.draft
        return <Badge color={s.color}>{s.label}</Badge>
      },
      width: 130,
    },
    {
      id: 'author',
      header: 'Author',
      cell: (item) => item.authorName,
      width: 160,
    },
    {
      id: 'assignedReviewer',
      header: 'Reviewer',
      cell: (item) =>
        item.assignedReviewerId ? (
          <Badge color="blue">Assigned to {item.assignedReviewerName || 'reviewer'}</Badge>
        ) : (
          <Badge color="grey">Open for review</Badge>
        ),
      width: 220,
    },
    {
      id: 'version',
      header: 'Version',
      cell: (item) => item.version || '—',
      width: 100,
    },
    {
      id: 'updatedAt',
      header: 'Last Updated',
      cell: (item) => new Date(item.updatedAt).toLocaleDateString(),
      sortingComparator: (a, b) => new Date(a.updatedAt) - new Date(b.updatedAt),
      width: 150,
    },
    {
      id: 'actions',
      header: 'Actions',
      cell: (item) => (
        <SpaceBetween direction="horizontal" size="xs">
          <Button variant="inline-link" onClick={() => onOpenDraft(item.id)}>
            Open
          </Button>
          {(item.status === 'draft' || item.status === 'rejected') && (
            <Button variant="inline-link" onClick={() => handleDelete(item.id)}>
              Delete
            </Button>
          )}
        </SpaceBetween>
      ),
      width: 160,
    },
  ]

  return (
    <Table
      variant="full-page"
      stickyHeader
      stripedRows
      loading={loading}
      loadingText="Loading drafts"
      items={drafts}
      columnDefinitions={columnDefinitions}
      header={
        <Header
          variant="awsui-h1-sticky"
          counter={`(${drafts.length})`}
          actions={
            <Button variant="primary" loading={creating} onClick={handleCreate}>
              New Draft
            </Button>
          }
          description="Author new STIGs or modify existing ones for submission to DISA"
        >
          STIG Writer
        </Header>
      }
      empty={
        <Box textAlign="center" padding={{ vertical: 'l' }}>
          <SpaceBetween size="xs">
            <b>No drafts yet</b>
            <Button onClick={handleCreate} loading={creating}>
              Create your first draft
            </Button>
          </SpaceBetween>
        </Box>
      }
    />
  )

  // Error display handled by wrapping in alert if needed
}

// ── Draft Editor ─────────────────────────────────────────────────────────────

function DraftEditor({ draftId, onBack }) {
  const [draft, setDraft] = useState(null)
  const [rules, setRules] = useState([])
  const [loading, setLoading] = useState(true)
  const [saving, setSaving] = useState(false)
  const [error, setError] = useState(null)
  const [success, setSuccess] = useState(null)
  const [selectedRules, setSelectedRules] = useState([])
  const [editingRule, setEditingRule] = useState(null)
  const [activeTabId, setActiveTabId] = useState('metadata')
  const [comments, setComments] = useState([])
  const [newComment, setNewComment] = useState('')
  const [importError, setImportError] = useState(null)
  const fileInputRef = useRef(null)
  const saveTimerRef = useRef(null)
  const pendingSaveRef = useRef(null)

  // Load draft data
  const fetchDraft = useCallback(async () => {
    setLoading(true)
    setError(null)
    try {
      const data = await apiGet(`/api/drafts/${encodeURIComponent(draftId)}`)
      setDraft({
        id: data.id,
        title: data.title,
        authorId: data.authorId,
        basedOnStig: data.basedOnStig,
        status: data.status,
        version: data.version,
        releaseInfo: data.releaseInfo,
        description: data.description,
        nextVulnId: data.nextVulnId,
      })
      setRules(data.rules || [])
    } catch (err) {
      setError(err.message)
    } finally {
      setLoading(false)
    }
  }, [draftId])

  useEffect(() => { fetchDraft() }, [fetchDraft])

  // Load comments
  const fetchComments = useCallback(async () => {
    try {
      const data = await apiGet(`/api/drafts/${encodeURIComponent(draftId)}/comments`)
      setComments(data)
    } catch {
      // Silently fail for comments
    }
  }, [draftId])

  useEffect(() => { fetchComments() }, [fetchComments])

  // Save draft (debounced)
  const saveDraft = useCallback(async (draftData, rulesData) => {
    if (!draftData || draftData.status === 'approved' || draftData.status === 'submitted' || draftData.status === 'in_review') return
    setSaving(true)
    try {
      await apiJson(`/api/drafts/${encodeURIComponent(draftId)}`, 'PUT', {
        title: draftData.title,
        description: draftData.description,
        version: draftData.version,
        releaseInfo: draftData.releaseInfo,
        rules: rulesData,
      })
    } catch {
      // Silent save failure — user can retry manually
    } finally {
      setSaving(false)
    }
  }, [draftId])

  const debouncedSave = useCallback((draftData, rulesData) => {
    if (saveTimerRef.current) clearTimeout(saveTimerRef.current)
    pendingSaveRef.current = { draftData, rulesData }
    saveTimerRef.current = setTimeout(() => {
      pendingSaveRef.current = null
      saveDraft(draftData, rulesData)
    }, 1500)
  }, [saveDraft])

  // Flush pending save immediately
  const flushSave = useCallback(() => {
    if (saveTimerRef.current) {
      clearTimeout(saveTimerRef.current)
      saveTimerRef.current = null
    }
    if (pendingSaveRef.current) {
      const { draftData, rulesData } = pendingSaveRef.current
      pendingSaveRef.current = null
      saveDraft(draftData, rulesData)
    }
  }, [saveDraft])

  // Flush on unmount
  useEffect(() => {
    return () => flushSave()
  }, [flushSave])

  const handleBack = useCallback(() => {
    flushSave()
    onBack()
  }, [flushSave, onBack])

  const isEditable = draft?.status === 'draft' || draft?.status === 'rejected'

  const updateDraft = useCallback((updates) => {
    setDraft((prev) => {
      const next = { ...prev, ...updates }
      setRules((currentRules) => {
        debouncedSave(next, currentRules)
        return currentRules
      })
      return next
    })
  }, [debouncedSave])

  const updateRule = useCallback((ruleId, updates) => {
    setRules((prev) => {
      const next = prev.map((r) => (r.id === ruleId ? { ...r, ...updates } : r))
      setDraft((currentDraft) => {
        debouncedSave(currentDraft, next)
        return currentDraft
      })
      return next
    })
    setEditingRule((prev) => (prev && prev.id === ruleId ? { ...prev, ...updates } : prev))
  }, [debouncedSave])

  const addRule = useCallback(async () => {
    try {
      const data = await apiJson(`/api/drafts/${encodeURIComponent(draftId)}/next-vuln-id`, 'POST')
      const rule = {
        id: data.ruleId,
        stigId: data.vulnId,
        groupId: data.groupId,
        title: '',
        severity: 'CAT II',
        description: '',
        fixText: '',
        checkText: '',
        cciIds: [],
        status: 'not_reviewed',
        findingDetails: '',
        comments: '',
      }
      setRules((prev) => {
        const next = [...prev, rule]
        setDraft((currentDraft) => {
          debouncedSave(currentDraft, next)
          return currentDraft
        })
        return next
      })
    } catch (err) {
      setError(`Failed to add rule: ${err.message}`)
    }
  }, [draftId, debouncedSave])

  const deleteSelectedRules = useCallback(() => {
    const ids = new Set(selectedRules.map((r) => r.id))
    setRules((prev) => {
      const next = prev.filter((r) => !ids.has(r.id))
      setDraft((currentDraft) => {
        debouncedSave(currentDraft, next)
        return currentDraft
      })
      return next
    })
    setSelectedRules([])
    setEditingRule((prev) => (prev && ids.has(prev.id) ? null : prev))
  }, [selectedRules, debouncedSave])

  const handleImport = useCallback(async (e) => {
    const file = e.target.files?.[0]
    if (!file) return
    setImportError(null)
    try {
      const text = await file.text()
      const parsed = file.name.endsWith('.ckl') ? parseCKL(text) : parseXCCDF(text)
      updateDraft({
        title: parsed.title,
        description: parsed.description,
        version: parsed.version,
        releaseInfo: parsed.releaseInfo,
      })
      setRules(parsed.rules || [])
      setSelectedRules([])
      setEditingRule(null)
      setActiveTabId('metadata')
      // Force immediate save
      saveDraft({ ...draft, ...parsed }, parsed.rules || [])
    } catch (err) {
      setImportError(err.message)
    }
    e.target.value = ''
  }, [draft, updateDraft, saveDraft])

  const handleExport = useCallback(() => {
    const stig = { ...draft, rules }
    const xml = exportXCCDF(stig)
    const blob = new Blob([xml], { type: 'application/xml' })
    const url = URL.createObjectURL(blob)
    const a = document.createElement('a')
    a.href = url
    a.download = `${(draft?.title || 'draft_stig').replace(/[^a-zA-Z0-9]/g, '_')}.xml`
    a.click()
    URL.revokeObjectURL(url)
  }, [draft, rules])

  // Workflow actions
  const doTransition = useCallback(async (action, body) => {
    setError(null)
    setSuccess(null)
    try {
      const result = await apiJson(
        `/api/drafts/${encodeURIComponent(draftId)}/${action}`,
        'POST',
        body,
      )
      setDraft((prev) => ({ ...prev, status: result.status }))
      setSuccess(`Draft ${result.status.replace('_', ' ')}`)
      fetchComments()
    } catch (err) {
      setError(err.message)
    }
  }, [draftId, fetchComments])

  const handleWithdraw = useCallback(() => doTransition('revise'), [doTransition])
  const handleReview = useCallback(() => doTransition('review'), [doTransition])
  const handleRevise = useCallback(() => doTransition('revise'), [doTransition])

  // Submit-with-reviewer modal state. Reviewer options are fetched lazily
  // the first time the modal opens to avoid an extra API call on every
  // draft view.
  const [showSubmitModal, setShowSubmitModal] = useState(false)
  const [reviewerOptions, setReviewerOptions] = useState([])
  const [selectedReviewer, setSelectedReviewer] = useState(null)

  const openSubmitModal = useCallback(async () => {
    setShowSubmitModal(true)
    setSelectedReviewer(null)
    try {
      const users = await apiGet('/api/users')
      const eligible = (users || []).filter(
        (u) => u.role === 'reviewer' || u.role === 'admin',
      )
      setReviewerOptions([
        { label: 'Any reviewer', value: '' },
        ...eligible.map((u) => ({ label: u.displayName, value: u.id })),
      ])
    } catch {
      setReviewerOptions([{ label: 'Any reviewer', value: '' }])
    }
  }, [])

  const handleSubmit = useCallback(async () => {
    const body = selectedReviewer && selectedReviewer.value
      ? { assignedReviewerId: selectedReviewer.value }
      : undefined
    await doTransition('submit', body)
    setShowSubmitModal(false)
    setSelectedReviewer(null)
  }, [doTransition, selectedReviewer])

  const [showApproveModal, setShowApproveModal] = useState(false)
  const [showRejectModal, setShowRejectModal] = useState(false)
  const [actionComment, setActionComment] = useState('')

  const handleApprove = useCallback(() => {
    doTransition('approve', { comment: actionComment || undefined })
    setShowApproveModal(false)
    setActionComment('')
  }, [doTransition, actionComment])

  const handleReject = useCallback(() => {
    doTransition('reject', { comment: actionComment || 'Rejected' })
    setShowRejectModal(false)
    setActionComment('')
  }, [doTransition, actionComment])

  const handleAddComment = useCallback(async () => {
    if (!newComment.trim()) return
    try {
      await apiJson(`/api/drafts/${encodeURIComponent(draftId)}/comments`, 'POST', {
        body: newComment.trim(),
      })
      setNewComment('')
      fetchComments()
    } catch (err) {
      setError(err.message)
    }
  }, [draftId, newComment, fetchComments])

  const xccdfPreview = useMemo(() => {
    if (!draft) return ''
    return exportXCCDF({ ...draft, rules })
  }, [draft, rules])

  const handleCopyPreview = useCallback(() => {
    navigator.clipboard.writeText(xccdfPreview)
  }, [xccdfPreview])

  if (loading) {
    return (
      <SpaceBetween size="m">
        <Button variant="link" iconName="arrow-left" onClick={handleBack}>
          Back to Drafts
        </Button>
        <StatusIndicator type="loading">Loading draft</StatusIndicator>
      </SpaceBetween>
    )
  }

  if (!draft) {
    return (
      <SpaceBetween size="m">
        <Button variant="link" iconName="arrow-left" onClick={handleBack}>
          Back to Drafts
        </Button>
        <Alert type="error">Draft not found</Alert>
      </SpaceBetween>
    )
  }

  // Release info parsing
  const releaseMatch = draft.releaseInfo?.match(/Release:\s*(\d+)/i)
  const dateMatch = draft.releaseInfo?.match(/Benchmark Date:\s*(.+)/i)
  const releaseNum = releaseMatch?.[1] || '1'
  const benchmarkDate = dateMatch?.[1] || ''

  const updateReleaseInfo = (release, date) => {
    const parts = []
    if (release) parts.push(`Release: ${release}`)
    if (date) parts.push(`Benchmark Date: ${date}`)
    updateDraft({ releaseInfo: parts.join(' ') })
  }

  // Workflow action buttons
  const workflowActions = []
  const status = draft.status

  if (isEditable) {
    workflowActions.push(
      <Button key="import" onClick={() => fileInputRef.current?.click()}>
        Import File
      </Button>,
    )
  }

  if (status === 'draft') {
    workflowActions.push(
      <Button key="submit" variant="primary" onClick={openSubmitModal}>
        Submit for Review
      </Button>,
    )
  } else if (status === 'submitted') {
    workflowActions.push(
      <Button key="withdraw" onClick={handleWithdraw}>
        Withdraw
      </Button>,
      <Button key="review" variant="primary" onClick={handleReview}>
        Pick Up Review
      </Button>,
    )
  } else if (status === 'in_review') {
    workflowActions.push(
      <Button key="approve" variant="primary" onClick={() => setShowApproveModal(true)}>
        Approve
      </Button>,
      <Button key="reject" onClick={() => setShowRejectModal(true)}>
        Reject
      </Button>,
    )
  } else if (status === 'rejected') {
    workflowActions.push(
      <Button key="revise" variant="primary" onClick={handleRevise}>
        Revise
      </Button>,
    )
  }

  if (draft.title) {
    workflowActions.push(
      <Button key="export" onClick={handleExport}>
        Export XCCDF
      </Button>,
    )
  }

  const statusBadge = STATUS_BADGE[status] || STATUS_BADGE.draft

  const ruleColumnDefinitions = [
    {
      id: 'stigId',
      header: 'Vuln ID',
      cell: (item) => item.stigId,
      width: 120,
      sortingComparator: (a, b) => a.stigId.localeCompare(b.stigId),
    },
    {
      id: 'severity',
      header: 'Severity',
      cell: (item) => (
        <Badge color={SEVERITY_BADGE_COLOR[item.severity] || 'grey'}>
          {item.severity}
        </Badge>
      ),
      width: 120,
      sortingComparator: (a, b) => a.severity.localeCompare(b.severity),
    },
    {
      id: 'title',
      header: 'Title',
      cell: (item) => item.title || '(untitled)',
      sortingComparator: (a, b) => a.title.localeCompare(b.title),
    },
    {
      id: 'cciIds',
      header: 'CCI',
      cell: (item) => (item.cciIds || []).join(', ') || '—',
      width: 150,
    },
  ]

  return (
    <SpaceBetween size="m">
      {/* Back + header */}
      <Button variant="link" iconName="arrow-left" onClick={onBack}>
        Back to Drafts
      </Button>

      <Header
        variant="h2"
        description={
          <SpaceBetween direction="horizontal" size="xs" alignItems="center">
            <Badge color={statusBadge.color}>{statusBadge.label}</Badge>
            {saving && <StatusIndicator type="loading">Saving</StatusIndicator>}
          </SpaceBetween>
        }
        actions={
          <SpaceBetween direction="horizontal" size="xs">
            {workflowActions}
          </SpaceBetween>
        }
      >
        {draft.title || '(untitled draft)'}
      </Header>

      <input
        ref={fileInputRef}
        type="file"
        accept=".xml,.ckl"
        style={{ display: 'none' }}
        aria-hidden="true"
        tabIndex={-1}
        onChange={handleImport}
      />

      {error && (
        <Alert type="error" dismissible onDismiss={() => setError(null)}>
          {error}
        </Alert>
      )}
      {success && (
        <Alert type="success" dismissible onDismiss={() => setSuccess(null)}>
          {success}
        </Alert>
      )}
      {importError && (
        <Alert type="error" dismissible onDismiss={() => setImportError(null)}>
          Failed to import: {importError}
        </Alert>
      )}

      {/* Tabs */}
      <Tabs
        activeTabId={activeTabId}
        onChange={({ detail }) => setActiveTabId(detail.activeTabId)}
        ariaLabel="Draft editor sections"
        tabs={[
          {
            label: 'Metadata',
            id: 'metadata',
            content: (
              <Container header={<Header variant="h2">STIG Metadata</Header>}>
                <SpaceBetween size="l">
                  <FormField label="Title" description="Name of the STIG">
                    <Input
                      value={draft.title}
                      onChange={({ detail }) => updateDraft({ title: detail.value })}
                      placeholder="e.g. My Application Security"
                      disabled={!isEditable}
                    />
                  </FormField>
                  <FormField label="Description">
                    <Textarea
                      value={draft.description}
                      onChange={({ detail }) => updateDraft({ description: detail.value })}
                      placeholder="Overview of what this STIG covers"
                      rows={4}
                      disabled={!isEditable}
                    />
                  </FormField>
                  <ColumnLayout columns={3}>
                    <FormField label="Version">
                      <Input
                        value={draft.version}
                        onChange={({ detail }) => updateDraft({ version: detail.value })}
                        placeholder="1"
                        disabled={!isEditable}
                      />
                    </FormField>
                    <FormField label="Release Number">
                      <Input
                        value={releaseNum}
                        onChange={({ detail }) => updateReleaseInfo(detail.value, benchmarkDate)}
                        placeholder="1"
                        disabled={!isEditable}
                      />
                    </FormField>
                    <FormField label="Benchmark Date">
                      <Input
                        value={benchmarkDate}
                        onChange={({ detail }) => updateReleaseInfo(releaseNum, detail.value)}
                        placeholder="e.g. 20 Feb 2026"
                        disabled={!isEditable}
                      />
                    </FormField>
                  </ColumnLayout>
                </SpaceBetween>
              </Container>
            ),
          },
          {
            label: `Rules (${rules.length})`,
            id: 'rules',
            content: (
              <SpaceBetween size="m">
                <Table
                  items={rules}
                  columnDefinitions={ruleColumnDefinitions}
                  selectionType={isEditable ? 'multi' : undefined}
                  selectedItems={selectedRules}
                  onSelectionChange={({ detail }) => setSelectedRules(detail.selectedItems)}
                  onRowClick={({ detail }) => setEditingRule(detail.item)}
                  sortingDisabled={false}
                  stripedRows
                  header={
                    <Header
                      counter={`(${rules.length})`}
                      actions={
                        isEditable ? (
                          <SpaceBetween direction="horizontal" size="xs">
                            <Button
                              disabled={selectedRules.length === 0}
                              onClick={deleteSelectedRules}
                            >
                              Delete Selected
                            </Button>
                            <Button variant="primary" onClick={addRule}>
                              Add Rule
                            </Button>
                          </SpaceBetween>
                        ) : undefined
                      }
                    >
                      Rules
                    </Header>
                  }
                  empty={
                    <Box textAlign="center" padding={{ vertical: 'l' }}>
                      <SpaceBetween size="xs">
                        <b>No rules yet</b>
                        {isEditable && (
                          <Button onClick={addRule}>Add your first rule</Button>
                        )}
                      </SpaceBetween>
                    </Box>
                  }
                />

                {/* Rule editor modal */}
                <Modal
                  visible={editingRule !== null}
                  onDismiss={() => setEditingRule(null)}
                  header={editingRule ? `Edit ${editingRule.stigId}` : 'Edit Rule'}
                  size="large"
                  footer={
                    <Box float="right">
                      <Button variant="primary" onClick={() => setEditingRule(null)}>
                        Done
                      </Button>
                    </Box>
                  }
                >
                  {editingRule && (
                    <SpaceBetween size="l">
                      <ColumnLayout columns={3}>
                        <FormField label="Vuln ID (stigId)">
                          <Input
                            value={editingRule.stigId}
                            onChange={({ detail }) => updateRule(editingRule.id, { stigId: detail.value })}
                            disabled={!isEditable}
                          />
                        </FormField>
                        <FormField label="Rule ID">
                          <Input
                            value={editingRule.id}
                            onChange={({ detail }) => {
                              if (!isEditable) return
                              const oldId = editingRule.id
                              setRules((prev) => {
                                const next = prev.map((r) => (r.id === oldId ? { ...r, id: detail.value } : r))
                                setDraft((currentDraft) => {
                                  debouncedSave(currentDraft, next)
                                  return currentDraft
                                })
                                return next
                              })
                              setEditingRule((prev) => ({ ...prev, id: detail.value }))
                            }}
                            disabled={!isEditable}
                          />
                        </FormField>
                        <FormField label="Group ID">
                          <Input
                            value={editingRule.groupId}
                            onChange={({ detail }) => updateRule(editingRule.id, { groupId: detail.value })}
                            disabled={!isEditable}
                          />
                        </FormField>
                      </ColumnLayout>
                      <ColumnLayout columns={2}>
                        <FormField label="Severity">
                          <Select
                            selectedOption={
                              SEVERITY_OPTIONS.find((o) => o.value === editingRule.severity) ||
                              SEVERITY_OPTIONS[1]
                            }
                            onChange={({ detail }) =>
                              updateRule(editingRule.id, { severity: detail.selectedOption.value })
                            }
                            options={SEVERITY_OPTIONS}
                            disabled={!isEditable}
                          />
                        </FormField>
                        <FormField label="CCI IDs" description="Comma-separated">
                          <Input
                            value={(editingRule.cciIds || []).join(', ')}
                            onChange={({ detail }) =>
                              updateRule(editingRule.id, {
                                cciIds: detail.value
                                  .split(',')
                                  .map((s) => s.trim())
                                  .filter(Boolean),
                              })
                            }
                            placeholder="CCI-000213, CCI-000366"
                            disabled={!isEditable}
                          />
                        </FormField>
                      </ColumnLayout>
                      <FormField label="Title">
                        <Input
                          value={editingRule.title}
                          onChange={({ detail }) => updateRule(editingRule.id, { title: detail.value })}
                          disabled={!isEditable}
                        />
                      </FormField>
                      <FormField label="Vulnerability Discussion">
                        <Textarea
                          value={editingRule.description}
                          onChange={({ detail }) =>
                            updateRule(editingRule.id, { description: detail.value })
                          }
                          rows={4}
                          disabled={!isEditable}
                        />
                      </FormField>
                      <FormField label="Check Text">
                        <Textarea
                          value={editingRule.checkText}
                          onChange={({ detail }) =>
                            updateRule(editingRule.id, { checkText: detail.value })
                          }
                          rows={4}
                          disabled={!isEditable}
                        />
                      </FormField>
                      <FormField label="Fix Text">
                        <Textarea
                          value={editingRule.fixText}
                          onChange={({ detail }) =>
                            updateRule(editingRule.id, { fixText: detail.value })
                          }
                          rows={4}
                          disabled={!isEditable}
                        />
                      </FormField>
                    </SpaceBetween>
                  )}
                </Modal>
              </SpaceBetween>
            ),
          },
          {
            label: `Comments (${comments.length})`,
            id: 'comments',
            content: (
              <Container header={<Header variant="h2">Review Comments</Header>}>
                <SpaceBetween size="m">
                  {comments.length === 0 && (
                    <Box color="text-body-secondary">No comments yet.</Box>
                  )}
                  {comments.map((c) => (
                    <Container
                      key={c.id}
                      header={
                        <SpaceBetween direction="horizontal" size="xs" alignItems="center">
                          <Box fontWeight="bold">{c.userName}</Box>
                          <Badge color="grey">{c.userRole}</Badge>
                          {c.action && (
                            <Badge color={c.action === 'approve' ? 'green' : 'red'}>
                              {c.action}
                            </Badge>
                          )}
                          <Box color="text-body-secondary">
                            {new Date(c.createdAt).toLocaleString()}
                          </Box>
                        </SpaceBetween>
                      }
                    >
                      {c.body}
                    </Container>
                  ))}
                  <FormField label="Add a comment">
                    <SpaceBetween size="xs">
                      <Textarea
                        value={newComment}
                        onChange={({ detail }) => setNewComment(detail.value)}
                        placeholder="Write a comment..."
                        rows={3}
                      />
                      <Box>
                        <Button
                          onClick={handleAddComment}
                          disabled={!newComment.trim()}
                        >
                          Post Comment
                        </Button>
                      </Box>
                    </SpaceBetween>
                  </FormField>
                </SpaceBetween>
              </Container>
            ),
          },
          {
            label: 'Preview',
            id: 'preview',
            content: (
              <Container
                header={
                  <Header
                    variant="h2"
                    actions={
                      <SpaceBetween direction="horizontal" size="xs">
                        <Button iconName="copy" onClick={handleCopyPreview}>
                          Copy to Clipboard
                        </Button>
                        <Button
                          variant="primary"
                          disabled={!draft.title}
                          onClick={handleExport}
                        >
                          Export XCCDF
                        </Button>
                      </SpaceBetween>
                    }
                  >
                    XCCDF Preview
                  </Header>
                }
              >
                <pre
                  style={{
                    fontSize: 12,
                    lineHeight: 1.6,
                    color: '#8d99a8',
                    background: '#0f1b2e80',
                    border: '1px solid #354150',
                    borderRadius: 6,
                    padding: '16px',
                    whiteSpace: 'pre-wrap',
                    wordBreak: 'break-word',
                    fontFamily: "'JetBrains Mono', monospace",
                    margin: 0,
                    maxHeight: '70vh',
                    overflow: 'auto',
                  }}
                >
                  {xccdfPreview}
                </pre>
              </Container>
            ),
          },
        ]}
      />

      {/* Submit modal — optional reviewer selection */}
      <Modal
        visible={showSubmitModal}
        onDismiss={() => setShowSubmitModal(false)}
        header="Submit Draft for Review"
        footer={
          <Box float="right">
            <SpaceBetween direction="horizontal" size="xs">
              <Button onClick={() => setShowSubmitModal(false)}>Cancel</Button>
              <Button variant="primary" onClick={handleSubmit} data-testid="confirm-submit">
                Submit
              </Button>
            </SpaceBetween>
          </Box>
        }
      >
        <FormField
          label="Send to reviewer"
          description="Leave on 'Any reviewer' to let any reviewer claim this draft."
        >
          <Select
            data-testid="reviewer-select"
            selectedOption={selectedReviewer || { label: 'Any reviewer', value: '' }}
            onChange={({ detail }) => setSelectedReviewer(detail.selectedOption)}
            options={reviewerOptions}
            placeholder="Any reviewer"
          />
        </FormField>
      </Modal>

      {/* Approve modal */}
      <Modal
        visible={showApproveModal}
        onDismiss={() => setShowApproveModal(false)}
        header="Approve Draft"
        footer={
          <Box float="right">
            <SpaceBetween direction="horizontal" size="xs">
              <Button onClick={() => setShowApproveModal(false)}>Cancel</Button>
              <Button variant="primary" onClick={handleApprove}>
                Approve
              </Button>
            </SpaceBetween>
          </Box>
        }
      >
        <FormField label="Comment (optional)">
          <Textarea
            value={actionComment}
            onChange={({ detail }) => setActionComment(detail.value)}
            placeholder="Add a comment..."
            rows={3}
          />
        </FormField>
      </Modal>

      {/* Reject modal */}
      <Modal
        visible={showRejectModal}
        onDismiss={() => setShowRejectModal(false)}
        header="Reject Draft"
        footer={
          <Box float="right">
            <SpaceBetween direction="horizontal" size="xs">
              <Button onClick={() => setShowRejectModal(false)}>Cancel</Button>
              <Button variant="primary" onClick={handleReject}>
                Reject
              </Button>
            </SpaceBetween>
          </Box>
        }
      >
        <FormField label="Reason for rejection">
          <Textarea
            value={actionComment}
            onChange={({ detail }) => setActionComment(detail.value)}
            placeholder="Explain why this draft is being rejected..."
            rows={3}
          />
        </FormField>
      </Modal>
    </SpaceBetween>
  )
}

// ── Main STIGWriter component ────────────────────────────────────────────────

export default function STIGWriter({ initialDraftId, onClearDraftId }) {
  const [activeDraftId, setActiveDraftId] = useState(initialDraftId || null)
  const refreshRef = useRef(null)

  // Open a draft from the table or external trigger
  useEffect(() => {
    if (initialDraftId) setActiveDraftId(initialDraftId)
  }, [initialDraftId])

  const handleBack = useCallback(() => {
    setActiveDraftId(null)
    if (onClearDraftId) onClearDraftId()
    // Refresh drafts table when returning
    if (refreshRef.current) refreshRef.current()
  }, [onClearDraftId])

  if (activeDraftId) {
    return <DraftEditor draftId={activeDraftId} onBack={handleBack} />
  }

  return <DraftsTable onOpenDraft={setActiveDraftId} onRefresh={refreshRef} />
}
