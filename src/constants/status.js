export const STATUS_OPTIONS = [
  { value: 'not_reviewed', label: 'Not Reviewed', color: 'var(--status-nr)' },
  { value: 'not_a_finding', label: 'Not a Finding', color: 'var(--status-naf)' },
  { value: 'open', label: 'Open', color: 'var(--status-open)' },
  { value: 'not_applicable', label: 'Not Applicable', color: 'var(--status-na)' },
]

export const STATUS_CKL_MAP = {
  not_reviewed: 'Not_Reviewed',
  not_a_finding: 'NotAFinding',
  open: 'Open',
  not_applicable: 'Not_Applicable',
}

export const FINDING_DETAILS_FIELDS = [
  { key: 'findingDetails', label: 'Finding Details' },
  { key: 'comments', label: 'Comments' },
]
