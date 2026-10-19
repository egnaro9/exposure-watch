export const meta = {
  name: 'exposure-watch-blind-key-audit',
  description: 'Three blind labelers re-derive all 22 answer-key labels from the documents; disputed pairs get a neutral adjudication',
  phases: [
    { title: 'Label', detail: 'three independent blind labelers, all 22 pairs each' },
    { title: 'Adjudicate', detail: 'one neutral adjudicator per disputed pair' },
  ],
}

const PACKET = args.packet
const KEY = args.key

const DEFS = `Verdict definitions (these are the specification; apply them exactly):
- affected: the installed version is in an affected range or list.
- not_affected: it is not.
- conditional: the version is affected but exposure depends on a feature or configuration the inventory does not record.
- unknown: the documents do not settle it.
The inventory records ONLY vendor, product, version as written by the administrator, and a hostname. It records nothing about enabled features, configuration, or edition.`

const LABEL_SCHEMA = {
  type: 'object',
  properties: {
    labels: {
      type: 'array',
      items: {
        type: 'object',
        properties: {
          pair_id: { type: 'string' },
          label: { type: 'string', enum: ['affected', 'not_affected', 'conditional', 'unknown'] },
          source: { type: 'string', enum: ['kev', 'nvd_description', 'nvd_config'] },
          deciding_quote: { type: 'string' },
          reasoning: { type: 'string' },
          outside_knowledge_note: { type: 'string' },
          confidence: { type: 'string', enum: ['high', 'medium', 'low'] },
        },
        required: ['pair_id', 'label', 'source', 'deciding_quote', 'reasoning', 'outside_knowledge_note', 'confidence'],
      },
    },
  },
  required: ['labels'],
}

const ORDERS = ['in file order, P01 first', 'in reverse order, P22 first', 'starting at P12, wrapping around']

function labelPrompt(i) {
  return `You are labeling an evaluation dataset for software vulnerability exposure triage. Work alone.

Read exactly one file: ${PACKET}
Do not open, list, or search any other file or directory. Do not use the web.

The file holds 22 pairs. Each pair is one installed software item and one CVE, plus three source documents (kev, nvd_description, nvd_config). For each pair decide the verdict from the three documents only.

${DEFS}

Version comparison: compare token by token, numbers numerically. Read each nvd_config row's bounds literally (Including means inclusive, Excluding means exclusive). Where a row lists an exact version and update instead of a range, match both.

For every pair return: the label; the single source and an exact quote (copied character for character) that decides it; your reasoning in two or three sentences; and, separately, outside_knowledge_note: anything you know from outside the documents (for example a vendor advisory) that would change the answer in the real world, or "none". The label itself must follow the documents and the definitions, not outside knowledge.

Work through the pairs ${ORDERS[i]}. Return all 22.`
}

phase('Label')
const runs = await parallel([0, 1, 2].map(i => () =>
  agent(labelPrompt(i), { label: `labeler ${'ABC'[i]}`, phase: 'Label', schema: LABEL_SCHEMA, effort: 'high' })))
const ok = runs.filter(Boolean)
log(`${ok.length} of 3 labelers returned`)

const byPair = {}
ok.forEach((r, li) => r.labels.forEach(l => {
  (byPair[l.pair_id] = byPair[l.pair_id] || []).push({ labeler: 'ABC'[li], ...l })
}))

const ids = Object.keys(KEY).sort()
const table = ids.map(id => {
  const ls = byPair[id] || []
  const counts = {}
  ls.forEach(l => { counts[l.label] = (counts[l.label] || 0) + 1 })
  const top = Object.entries(counts).sort((a, b) => b[1] - a[1])[0]
  const unanimous = ls.length === ok.length && Object.keys(counts).length === 1
  return { id, key: KEY[id], labels: ls.map(l => l.label), majority: top ? top[0] : null,
           unanimous, disputed: !unanimous || (top && top[0] !== KEY[id]) }
})
const disputed = table.filter(t => t.disputed)
log(`disputed pairs: ${disputed.map(d => d.id).join(', ') || 'none'}`)

const ADJ_SCHEMA = {
  type: 'object',
  properties: {
    pair_id: { type: 'string' },
    final_label: { type: 'string', enum: ['affected', 'not_affected', 'conditional', 'unknown'] },
    deciding_quote: { type: 'string' },
    source: { type: 'string', enum: ['kev', 'nvd_description', 'nvd_config'] },
    case_for_each_candidate: { type: 'string' },
    disagreements: { type: 'string', description: 'Where any candidate reasoning below is wrong, and why. Must be non-empty.' },
    real_world_note: { type: 'string' },
  },
  required: ['pair_id', 'final_label', 'deciding_quote', 'source', 'case_for_each_candidate', 'disagreements', 'real_world_note'],
}

phase('Adjudicate')
const adjudicated = await parallel(disputed.map(d => () => {
  const cands = []
  const seen = new Set()
  const push = (label, why) => { if (!seen.has(label)) { seen.add(label); cands.push({ label, why: [] }) }
                                  cands.find(c => c.label === label).why.push(why) }
  push(d.key, 'proposed when the dataset was first built (no written reasoning beyond the definitions)')
  ;(byPair[d.id] || []).forEach(l => push(l.label, `${l.reasoning} [quotes ${l.source}: "${l.deciding_quote.slice(0, 300)}"]`))
  const candText = cands.map((c, n) => `Candidate ${n + 1}: ${c.label}\n` + c.why.map(w => `  - ${w}`).join('\n')).join('\n\n')
  return agent(`You are adjudicating one disputed label in a vulnerability-exposure evaluation dataset.

Read exactly one file: ${PACKET}, and use only pair ${d.id} in it. Do not open any other file. Do not use the web.

${DEFS}

The candidate labels below come from different people. They are listed in no particular order of authority, and none of them is presumed correct.

${candText}

Decide the label the documents and the definitions require. Make the strongest case for each candidate first, then decide. In disagreements, name every place a candidate's reasoning is wrong; it must not be empty. In real_world_note, say whether outside knowledge (a vendor advisory, for example) would change the real-world answer; it does not change the label.`,
    { label: `adjudicate ${d.id}`, phase: 'Adjudicate', schema: ADJ_SCHEMA, effort: 'high' })
}))

return {
  labelers_returned: ok.length,
  table,
  adjudicated: adjudicated.filter(Boolean),
  outside_notes: ids.flatMap(id => (byPair[id] || []).filter(l => l.outside_knowledge_note && !/^none\.?$/i.test(l.outside_knowledge_note.trim()))
    .map(l => ({ id, labeler: l.labeler, note: l.outside_knowledge_note }))),
  low_confidence: ids.flatMap(id => (byPair[id] || []).filter(l => l.confidence !== 'high').map(l => ({ id, labeler: l.labeler, label: l.label, confidence: l.confidence }))),
}
