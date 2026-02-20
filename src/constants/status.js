export const STATUS_OPTIONS = [
  { value: 'not_reviewed', label: 'Not Reviewed', color: '#8d99a8' },
  { value: 'not_a_finding', label: 'Not a Finding', color: '#22c55e' },
  { value: 'open', label: 'Open', color: '#ff4444' },
  { value: 'not_applicable', label: 'Not Applicable', color: '#8b5cf6' },
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
