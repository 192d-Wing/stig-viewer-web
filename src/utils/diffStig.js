const DIFF_FIELDS = ['title', 'severity', 'description', 'checkText', 'fixText']

/**
 * Compares two STIG objects by stigId.
 *
 * @param {object} stigA - baseline (older) STIG
 * @param {object} stigB - comparison (newer) STIG
 * @returns {{ added: Rule[], removed: Rule[], changed: ChangedEntry[] }}
 */
export function diffSTIGs(stigA, stigB) {
  const mapA = new Map(stigA.rules.map((r) => [r.stigId, r]))
  const mapB = new Map(stigB.rules.map((r) => [r.stigId, r]))

  const added = []
  const removed = []
  const changed = []

  // Rules in B not in A (added)
  for (const [id, ruleB] of mapB) {
    if (!mapA.has(id)) {
      added.push(ruleB)
    }
  }

  // Rules in A — either removed or potentially changed
  for (const [id, ruleA] of mapA) {
    if (!mapB.has(id)) {
      removed.push(ruleA)
      continue
    }
    const ruleB = mapB.get(id)
    // DIFF_FIELDS is a const string array — bracket access is safe here.
    // eslint-disable-next-line security/detect-object-injection
    const diffFields = DIFF_FIELDS.filter((f) => ruleA[f] !== ruleB[f])
    if (diffFields.length > 0) {
      changed.push({
        stigId: id,
        ruleId: ruleA.id,
        // eslint-disable-next-line security/detect-object-injection
        a: Object.fromEntries(diffFields.map((f) => [f, ruleA[f]])),
        // eslint-disable-next-line security/detect-object-injection
        b: Object.fromEntries(diffFields.map((f) => [f, ruleB[f]])),
        fields: diffFields,
      })
    }
  }

  return { added, removed, changed }
}
