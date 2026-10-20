export const meta = {
  name: 'exposure-watch-heldout-blind-key',
  description: 'Three blind labelers label every held-out pair from the documents; any pair they do not all agree on gets one neutral adjudication',
  phases: [
    { title: 'Label', detail: 'three independent blind labelers, every pair, in chunks' },
    { title: 'Adjudicate', detail: 'one neutral adjudicator per pair the labelers did not all agree on' },
  ],
}

// args: { packet: absolute path of eval/heldout/key_audit/packet.json, ids: ["P01", ...], chunk: 20 }
// The labelers see only the packet: the item, the CVE and the three documents the agents see.
// They never see how an item was built, what the code says, or any agent answer.
const PACKET = args.packet
const IDS = args.ids
const CHUNK = args.chunk || 20

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

const chunks = []
for (let i = 0; i < IDS.length; i += CHUNK) chunks.push(IDS.slice(i, i + CHUNK))

function labelPrompt(ids, order) {
  const list = order === 'reverse' ? [...ids].reverse() : ids
  return `You are labeling an evaluation dataset for software vulnerability exposure triage. Work alone.

Read exactly one file: ${PACKET}
Do not open, list, or search any other file or directory. Do not use the web.

The file holds many pairs. Label ONLY these pairs, in this order: ${list.join(', ')}.
Each pair is one installed software item and one CVE, plus three source documents (kev, nvd_description, nvd_config). For each pair decide the verdict from the three documents only.

${DEFS}

Version comparison: compare token by token, numbers numerically. Read each nvd_config row's bounds literally (Including means inclusive, Excluding means exclusive). Where a row lists an exact version and update instead of a range, match both. If the nvd_config document is empty or no row describes the item's product, say what that means for the verdict under the definitions.

For every pair return: the label; the single source and an exact quote (copied character for character) that decides it; your reasoning in two or three sentences; and, separately, outside_knowledge_note: anything you know from outside the documents (for example a vendor advisory, or that you recognise this CVE at all) that would change the answer in the real world, or "none". The label itself must follow the documents and the definitions, not outside knowledge.

Return exactly ${ids.length} labels.`
}

phase('Label')
const LABELERS = ['A', 'B', 'C']
const ORDERS = { A: 'forward', B: 'reverse', C: 'forward' }
const jobs = []
LABELERS.forEach(L => chunks.forEach((ids, ci) => jobs.push({ L, ci, ids })))
const results = await parallel(jobs.map(j => () =>
  agent(labelPrompt(j.ids, ORDERS[j.L]), { label: `labeler ${j.L} chunk ${j.ci + 1}`, phase: 'Label',
                                           schema: LABEL_SCHEMA, effort: 'high' })
    .then(r => ({ ...j, r }))))

const byPair = {}
const missing = []
results.forEach((x, n) => {
  if (!x || !x.r) { missing.push(`${jobs[n].L} chunk ${jobs[n].ci + 1}`); return }
  const got = new Set()
  x.r.labels.forEach(l => {
    if (!x.ids.includes(l.pair_id) || got.has(l.pair_id)) return
    got.add(l.pair_id)
    ;(byPair[l.pair_id] = byPair[l.pair_id] || []).push({ labeler: x.L, ...l })
  })
  x.ids.filter(id => !got.has(id)).forEach(id => missing.push(`${x.L} ${id}`))
})
if (missing.length) log(`MISSING labels (pair not labeled by all three): ${missing.join(', ')}`)

const table = IDS.map(id => {
  const ls = byPair[id] || []
  const labels = Object.fromEntries(ls.map(l => [l.labeler, l.label]))
  const unanimous = ls.length === 3 && new Set(ls.map(l => l.label)).size === 1
  return { id, labels, unanimous }
})
const disputed = table.filter(t => !t.unanimous)
log(`${table.length - disputed.length} unanimous, ${disputed.length} to adjudicate: ${disputed.map(d => d.id).join(', ') || 'none'}`)

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
  ;(byPair[d.id] || []).forEach(l => {
    let c = cands.find(x => x.label === l.label)
    if (!c) { c = { label: l.label, why: [] }; cands.push(c) }
    c.why.push(`${l.reasoning} [quotes ${l.source}: "${l.deciding_quote.slice(0, 300)}"]`)
  })
  const candText = cands.map((c, n) => `Candidate ${n + 1}: ${c.label}\n` + c.why.map(w => `  - ${w}`).join('\n')).join('\n\n')
  return agent(`You are adjudicating one disputed label in a vulnerability-exposure evaluation dataset.

Read exactly one file: ${PACKET}, and use only pair ${d.id} in it. Do not open any other file. Do not use the web.

${DEFS}

The candidate labels below come from independent labelers. They are listed in no particular order of authority, and none of them is presumed correct. Any label may be right, including one no candidate proposed.

${candText}

Decide the label the documents and the definitions require. Make the strongest case for each candidate first, then decide. In disagreements, name every place a candidate's reasoning is wrong; it must not be empty. In real_world_note, say whether outside knowledge would change the real-world answer; it does not change the label.`,
    { label: `adjudicate ${d.id}`, phase: 'Adjudicate', schema: ADJ_SCHEMA, effort: 'high' })
}))

return {
  labelers: LABELERS,
  missing,
  table,
  labels: byPair,
  adjudicated: adjudicated.filter(Boolean),
  outside_notes: IDS.flatMap(id => (byPair[id] || []).filter(l => l.outside_knowledge_note && !/^none\.?$/i.test(l.outside_knowledge_note.trim()))
    .map(l => ({ id, labeler: l.labeler, note: l.outside_knowledge_note }))),
}
