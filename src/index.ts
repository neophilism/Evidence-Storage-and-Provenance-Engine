import { digest, hashBytes, invariant, nonempty, requireScope, validTime, type Context, type Ref, type Scope } from './contracts.ts';

export type ScanStatus = 'quarantined' | 'scanning' | 'clean' | 'infected' | 'failed';
export type EvidenceRef = Ref & { readonly kind: 'evidence' };
type Stamp = Readonly<{ actorId: string; at: string; requestId: string; purpose: string }>;
export type SourceFamily = Readonly<{ id: string; label: string; parentIds: readonly string[]; reason: string }>;
export type FamilyIndependence = Stamp & Readonly<{ id: string; familyIds: readonly [string, string]; graphDigest: string; rationale: string }>;
export type EvidenceVersion = Readonly<{
  ref: EvidenceRef; acquisitionId: string; sha256: string; byteLength: number; mediaType: string;
  storageVersionRef: string; sourceFamilyId: string | null; capturedAt: string; originalLanguage: string;
  allowedPurposes: readonly string[]; supersedes: EvidenceRef | null;
  lineage: Readonly<{ parent: EvidenceRef; redactionPlanId: string }> | null;
  acquired: Stamp; metadataHash: string;
}>;
export type ScanRecord = Stamp & Readonly<{
  id: string; evidence: EvidenceRef; status: ScanStatus; attemptId: string | null;
  engineVersion: string | null; sha256: string; reason: string;
}>;
export type Representation = Stamp & Readonly<{
  id: string; evidence: EvidenceRef; sourceSha256: string; text: string | null;
  pages: readonly string[] | null; durationMs: number | null; toolVersion: string; digest: string;
}>;
export type IntegrityRecord = Stamp & Readonly<{
  id: string; evidence: EvidenceRef; expectedSha256: string; observedSha256: string;
  status: 'matched' | 'mismatch';
}>;
export type HandlingRecord = Stamp & Readonly<{
  id: string; sequence: number; evidence: EvidenceRef; action: string; detail: string;
  contentSha256: string; previousHash: string; hash: string;
}>;
export type RedactionRange = Readonly<{ start: number; end: number; reason: string }>;
export type RedactionPlan = Stamp & Readonly<{
  id: string; source: EvidenceRef; representationId: string; representationDigest: string;
  ranges: readonly RedactionRange[]; targetPurpose: string; policyVersion: string;
  expiresAt: string; reviewerId: string; digest: string;
}>;
export type EvidenceState = Scope & Readonly<{
  schemaVersion: 1; versions: readonly EvidenceVersion[]; families: readonly SourceFamily[];
  independence: readonly FamilyIndependence[]; scans: readonly ScanRecord[];
  representations: readonly Representation[]; integrity: readonly IntegrityRecord[];
  handling: readonly HandlingRecord[]; redactionPlans: readonly RedactionPlan[];
}>;
type SelectorBase = Readonly<{ evidence: EvidenceRef; sha256: string }>;
type RepresentationAnchor = Readonly<{ representationId: string; representationDigest: string }>;
export type EvidenceSelector =
  | (SelectorBase & Readonly<{ kind: 'whole' }>)
  | (SelectorBase & RepresentationAnchor & Readonly<{ kind: 'text'; page: number | null; start: number; end: number; quote: string }>)
  | (SelectorBase & RepresentationAnchor & Readonly<{ kind: 'page'; fromPage: number; toPage: number }>)
  | (SelectorBase & RepresentationAnchor & Readonly<{ kind: 'time'; startMs: number; endMs: number }>);
export type FamilySnapshot = Readonly<{ familyId: string | null; roots: readonly string[]; basisDigest: string }>;
export type SourceAnalysis = Readonly<{
  groups: readonly (readonly EvidenceRef[])[]; sourceGroupCount: number; uniqueByteCount: number;
  unknownFamilyRefs: readonly EvidenceRef[]; allGroupsIndependentlyAssessed: boolean;
  independentFamilyCount: number | null; basisDigest: string;
}>;

const HEX = /^[0-9a-f]{64}$/;
const STATUSES: readonly ScanStatus[] = ['quarantined', 'scanning', 'clean', 'infected', 'failed'];
function object(value: unknown, label: string): asserts value is Record<string, unknown> {
  invariant(value !== null && typeof value === 'object' && !Array.isArray(value), 'invalid_input', `${label} must be an object`);
}
function integer(value: unknown, min: number, label: string): asserts value is number {
  invariant(Number.isSafeInteger(value) && (value as number) >= min, 'invalid_input', `${label} is out of range`);
}
function hash(value: unknown): asserts value is string { invariant(typeof value === 'string' && HEX.test(value), 'invalid_hash', 'Expected a SHA-256 digest'); }
function strings(value: unknown, label: string, allowEmpty = false): asserts value is readonly string[] {
  invariant(Array.isArray(value) && (allowEmpty || value.length > 0), 'invalid_input', `${label} must be an array`);
  value.forEach(v => nonempty(v, label));
  invariant(new Set(value).size === value.length, 'duplicate', `${label} must be unique`);
}
function scope(value: Scope): void { object(value, 'scope'); nonempty(value.tenantId, 'tenantId'); nonempty(value.projectId, 'projectId'); }
function context(ctx: Context): void {
  scope(ctx); object(ctx.actor, 'actor'); nonempty(ctx.actor.id, 'actor.id');
  invariant(['human', 'agent', 'service'].includes(ctx.actor.kind), 'invalid_input', 'Unknown actor kind');
  strings(ctx.actor.roles, 'roles', true); nonempty(ctx.purpose, 'purpose'); nonempty(ctx.requestId, 'requestId'); validTime(ctx.now);
}
function stamp(ctx: Context): Stamp { return { actorId: ctx.actor.id, at: ctx.now, requestId: ctx.requestId, purpose: ctx.purpose }; }
function validStamp(value: Stamp): void { object(value, 'stamp'); nonempty(value.actorId, 'actorId'); nonempty(value.requestId, 'requestId'); nonempty(value.purpose, 'purpose'); validTime(value.at); }
function key(ref: Ref): string { return JSON.stringify([ref.tenantId, ref.projectId, ref.kind, ref.id, ref.revision]); }
function exact(a: Ref, b: Ref): boolean { return key(a) === key(b); }
function reference(ref: Ref, expectedScope: Scope): asserts ref is EvidenceRef {
  object(ref, 'reference'); scope(ref); requireScope(expectedScope, ref); nonempty(ref.id, 'reference.id');
  invariant(ref.kind === 'evidence', 'invalid_reference', 'Expected an evidence reference'); integer(ref.revision, 1, 'revision');
}
function freeze<T>(value: T): T {
  const copy = structuredClone(value);
  function visit(v: unknown): void { if (v && typeof v === 'object') { Object.values(v).forEach(visit); Object.freeze(v); } }
  visit(copy); return copy;
}
function uniqueIds(items: readonly { readonly id: string }[], label: string): void {
  const seen = new Set<string>();
  for (const item of items) { object(item, label); nonempty(item.id, `${label}.id`); invariant(!seen.has(item.id), 'duplicate', `Duplicate ${label} ID`); seen.add(item.id); }
}
function version(state: EvidenceState, ref: Ref): EvidenceVersion {
  reference(ref, state); const found = state.versions.find(v => exact(v.ref, ref));
  invariant(found, 'not_found', 'Evidence revision does not exist'); return found;
}
function current(state: EvidenceState, ref: Ref): EvidenceVersion {
  const found = version(state, ref);
  invariant(!state.versions.some(v => v.ref.id === ref.id && v.ref.revision > ref.revision), 'stale_revision', 'A newer evidence revision exists');
  return found;
}
function familyGraphDigest(state: EvidenceState): string { return digest(state.families.map(f => ({ id: f.id, parents: [...f.parentIds].sort() })).sort((a, b) => a.id.localeCompare(b.id))); }
function roots(state: EvidenceState, id: string, path = new Set<string>()): string[] {
  invariant(!path.has(id), 'family_cycle', 'Source-family lineage is circular');
  const family = state.families.find(f => f.id === id); invariant(family, 'unknown_family', 'Source family does not exist');
  const next = new Set(path).add(id);
  return family.parentIds.length === 0 ? [id] : [...new Set(family.parentIds.flatMap(parent => roots(state, parent, next)))].sort();
}
function lineageAncestors(state: EvidenceState, ref: EvidenceRef, path = new Set<string>()): string[] {
  const k = key(ref); invariant(!path.has(k), 'lineage_cycle', 'Evidence derivative lineage is circular');
  const v = version(state, ref); return v.lineage === null ? [k] : [k, ...lineageAncestors(state, v.lineage.parent, new Set(path).add(k))];
}
function scanStatus(state: EvidenceState, ref: EvidenceRef): ScanStatus { return state.scans.findLast(s => exact(s.evidence, ref))?.status ?? 'quarantined'; }
function representation(state: EvidenceState, ref: EvidenceRef, id: string): Representation {
  nonempty(id, 'representationId'); const r = state.representations.find(r => r.id === id);
  invariant(r && exact(r.evidence, ref), 'invalid_selector', 'Representation does not belong to the exact evidence revision'); return r;
}
function before(ctx: Context, at: string): void { invariant(validTime(ctx.now) >= validTime(at), 'invalid_time', 'Operation predates its prerequisite'); }
function guard(state: EvidenceState, ctx: Context): void { context(ctx); object(state, 'evidence state'); requireScope(ctx, state); assertEvidenceState(state); }
function usable(state: EvidenceState, ctx: Context, ref: EvidenceRef, requireCurrent: boolean): EvidenceVersion {
  const v = requireCurrent ? current(state, ref) : version(state, ref);
  invariant(scanStatus(state, ref) === 'clean', 'evidence_quarantined', 'A current clean scan is required');
  invariant(state.integrity.findLast(i => exact(i.evidence, ref))?.status !== 'mismatch', 'integrity_failure', 'Unresolved evidence integrity mismatch');
  invariant(v.allowedPurposes.includes(ctx.purpose), 'purpose_denied', 'This evidence version is not authorized for the requested purpose');
  for (const ancestorKey of lineageAncestors(state, ref).slice(1)) {
    const ancestor = state.versions.find(item => key(item.ref) === ancestorKey)!;
    if (requireCurrent) current(state, ancestor.ref);
    invariant(scanStatus(state, ancestor.ref) === 'clean' && state.integrity.findLast(i => exact(i.evidence, ancestor.ref))?.status !== 'mismatch', 'evidence_quarantined', 'A derivative ancestor is quarantined or has failed integrity');
  }
  if (v.lineage !== null) {
    const plan = state.redactionPlans.find(p => p.id === v.lineage?.redactionPlanId)!;
    invariant(validTime(ctx.now) < validTime(plan.expiresAt), 'expired', 'Derivative purpose approval has expired');
  }
  before(ctx, v.acquired.at); return v;
}
function handled(state: EvidenceState, ctx: Context, evidence: EvidenceRef, action: string, detail: string): EvidenceState {
  const contentSha256 = version(state, evidence).sha256;
  const base = { ...stamp(ctx), id: `${ctx.requestId}:${state.handling.length + 1}`, sequence: state.handling.length + 1,
    evidence, action, detail, contentSha256, previousHash: state.handling.at(-1)?.hash ?? '0'.repeat(64) };
  return { ...state, handling: [...state.handling, { ...base, hash: digest(base) }] };
}
function finish(state: EvidenceState): EvidenceState { assertEvidenceState(state); return freeze(state); }

/** Validate a deserialized snapshot before using it. Digests detect corruption, not a malicious storage administrator. */
export function assertEvidenceState(state: EvidenceState): void {
  object(state, 'evidence state'); scope(state); invariant(state.schemaVersion === 1, 'invalid_state', 'Unknown evidence state schema');
  for (const field of ['versions', 'families', 'independence', 'scans', 'representations', 'integrity', 'handling', 'redactionPlans'] as const) {
    invariant(Array.isArray(state[field]), 'invalid_state', `Missing evidence ${field}`);
  }
  uniqueIds(state.families, 'family'); uniqueIds(state.independence, 'independence'); uniqueIds(state.scans, 'scan');
  uniqueIds(state.representations, 'representation'); uniqueIds(state.integrity, 'integrity'); uniqueIds(state.handling, 'handling'); uniqueIds(state.redactionPlans, 'redaction plan');
  for (const f of state.families) { nonempty(f.label, 'family.label'); nonempty(f.reason, 'family.reason'); strings(f.parentIds, 'parentIds', true); roots(state, f.id); }
  const keys = new Set<string>(); const acquisitions = new Set<string>(); const storage = new Map<string, string>();
  for (const v of state.versions) {
    object(v, 'version'); reference(v.ref, state); invariant(!keys.has(key(v.ref)), 'duplicate', 'Duplicate evidence revision'); keys.add(key(v.ref));
    nonempty(v.acquisitionId, 'acquisitionId'); invariant(!acquisitions.has(v.acquisitionId), 'duplicate', 'Duplicate acquisition'); acquisitions.add(v.acquisitionId);
    hash(v.sha256); integer(v.byteLength, 0, 'byteLength'); nonempty(v.storageVersionRef, 'storageVersionRef');
    invariant(!storage.has(v.storageVersionRef) || storage.get(v.storageVersionRef) === v.sha256, 'storage_conflict', 'Storage version refers to different bytes'); storage.set(v.storageVersionRef, v.sha256);
    invariant(typeof v.mediaType === 'string' && /^[a-z0-9!#$&^_.+-]+\/[a-z0-9!#$&^_.+-]+$/i.test(v.mediaType), 'invalid_input', 'Invalid media type');
    strings(v.allowedPurposes, 'allowedPurposes'); validTime(v.capturedAt); validStamp(v.acquired); nonempty(v.originalLanguage, 'originalLanguage', 100);
    invariant(validTime(v.capturedAt) <= validTime(v.acquired.at), 'invalid_time', 'Capture cannot follow acquisition');
    if (v.sourceFamilyId !== null) { nonempty(v.sourceFamilyId, 'sourceFamilyId'); roots(state, v.sourceFamilyId); }
    if (v.supersedes === null) invariant(v.ref.revision === 1, 'invalid_revision', 'First evidence revision must be one');
    else { const previous = version(state, v.supersedes); invariant(previous.ref.id === v.ref.id && previous.ref.revision + 1 === v.ref.revision, 'invalid_revision', 'Evidence revisions must be consecutive'); invariant(validTime(v.acquired.at) >= validTime(previous.acquired.at), 'invalid_time', 'Acquisition predates its predecessor'); }
    const { metadataHash, ...metadata } = v; hash(metadataHash); invariant(digest(metadata) === metadataHash, 'integrity_failure', 'Evidence metadata digest mismatch');
    if (v.lineage !== null) {
      object(v.lineage, 'lineage'); const parent = version(state, v.lineage.parent); lineageAncestors(state, v.ref);
      const plan = state.redactionPlans.find(p => p.id === v.lineage?.redactionPlanId);
      invariant(plan && exact(plan.source, parent.ref), 'invalid_lineage', 'Derivative must retain its exact approved source');
      invariant(v.sourceFamilyId === parent.sourceFamilyId && v.allowedPurposes.length === 1 && v.allowedPurposes[0] === plan.targetPurpose, 'invalid_lineage', 'Derivative family or purpose differs from its plan');
      invariant(validTime(v.acquired.at) < validTime(plan.expiresAt), 'expired', 'Derivative was made after its plan expired');
      const r = representation(state, parent.ref, plan.representationId);
      invariant(r.text !== null && typeof r.text === 'string', 'invalid_selector', 'Redaction source has no text');
      const output = redactText(r.text, plan.ranges);
      invariant(v.sha256 === hashBytes(Buffer.from(output, 'utf8')) && v.byteLength === Buffer.byteLength(output), 'integrity_failure', 'Derivative bytes do not match the approved redaction');
    }
  }
  for (const i of state.independence) { validStamp(i); nonempty(i.rationale, 'rationale'); strings(i.familyIds, 'familyIds'); invariant(i.familyIds.length === 2, 'invalid_input', 'An independence assessment requires two families'); i.familyIds.forEach(id => roots(state, id)); hash(i.graphDigest); }
  const scanStates = new Map<string, ScanRecord>();
  for (const s of state.scans) {
    validStamp(s); const v = version(state, s.evidence); nonempty(s.reason, 'scan reason');
    invariant(STATUSES.includes(s.status), 'invalid_status', 'Unknown scan status'); invariant(s.sha256 === v.sha256, 'integrity_failure', 'Scan is bound to different bytes');
    const previous = scanStates.get(key(s.evidence));
    if (s.status === 'scanning') {
      invariant(!previous || ['quarantined', 'failed', 'clean'].includes(previous.status), 'invalid_transition', 'Scan cannot begin in this state'); nonempty(s.attemptId, 'attemptId'); nonempty(s.engineVersion, 'engineVersion');
    } else if (s.status !== 'quarantined') {
      invariant(previous?.status === 'scanning' && previous.attemptId === s.attemptId && previous.engineVersion === s.engineVersion, 'stale_scan', 'Scan result has no matching active attempt');
    } else invariant(s.attemptId === null && s.engineVersion === null, 'invalid_state', 'Quarantine cannot retain an active scan');
    invariant(validTime(s.at) >= validTime(previous?.at ?? v.acquired.at), 'invalid_time', 'Scan history is not chronological'); scanStates.set(key(s.evidence), s);
  }
  for (const r of state.representations) {
    validStamp(r); const v = version(state, r.evidence); invariant(r.sourceSha256 === v.sha256, 'integrity_failure', 'Representation source digest differs'); nonempty(r.toolVersion, 'toolVersion');
    invariant(r.text === null || typeof r.text === 'string', 'invalid_input', 'Representation text must be a string or null');
    invariant(r.pages === null || (Array.isArray(r.pages) && r.pages.length > 0 && r.pages.every(p => typeof p === 'string')), 'invalid_input', 'Representation pages must be text');
    if (r.durationMs !== null) integer(r.durationMs, 1, 'durationMs');
    invariant(r.text !== null || r.pages !== null || r.durationMs !== null, 'invalid_input', 'An empty representation is not useful');
    const { digest: contentDigest, ...body } = r; invariant(digest(body) === contentDigest, 'integrity_failure', 'Representation digest mismatch');
  }
  for (const i of state.integrity) { validStamp(i); const v = version(state, i.evidence); hash(i.observedSha256); invariant(i.expectedSha256 === v.sha256, 'integrity_failure', 'Integrity record has the wrong expected hash'); invariant(i.status === (i.observedSha256 === v.sha256 ? 'matched' : 'mismatch'), 'invalid_status', 'Invalid integrity result'); }
  for (const p of state.redactionPlans) {
    validStamp(p); version(state, p.source); const r = representation(state, p.source, p.representationId);
    invariant(r.text !== null && r.digest === p.representationDigest, 'invalid_selector', 'Redaction requires exact full-text representation'); validateRanges(p.ranges, r.text.length);
    nonempty(p.targetPurpose, 'targetPurpose'); nonempty(p.policyVersion, 'policyVersion'); nonempty(p.reviewerId, 'reviewerId');
    invariant(validTime(p.expiresAt) > validTime(p.at), 'invalid_time', 'Redaction approval must have a future expiry');
    const { digest: planDigest, ...body } = p; invariant(digest(body) === planDigest, 'integrity_failure', 'Redaction plan digest mismatch');
  }
  let previousHash = '0'.repeat(64); let sequence = 0; let lastAt = -Infinity;
  for (const h of state.handling) {
    validStamp(h); const v = version(state, h.evidence); nonempty(h.action, 'handling action'); nonempty(h.detail, 'handling detail');
    invariant(h.sequence === ++sequence && h.previousHash === previousHash && h.contentSha256 === v.sha256, 'integrity_failure', 'Handling chain is discontinuous');
    invariant(validTime(h.at) >= lastAt && validTime(h.at) >= validTime(v.acquired.at), 'invalid_time', 'Handling record predates its prerequisite'); lastAt = validTime(h.at);
    const { hash: eventHash, ...body } = h; invariant(digest(body) === eventHash, 'integrity_failure', 'Handling chain digest mismatch'); previousHash = eventHash;
  }
}

export function createEvidenceState(input: Scope): EvidenceState {
  scope(input); return finish({ tenantId: input.tenantId, projectId: input.projectId, schemaVersion: 1, versions: [], families: [], independence: [], scans: [], representations: [], integrity: [], handling: [], redactionPlans: [] });
}
export function addSourceFamily(state: EvidenceState, ctx: Context, input: SourceFamily): EvidenceState {
  guard(state, ctx); object(input, 'family'); invariant(!state.families.some(f => f.id === input.id), 'duplicate', 'Source family already exists');
  strings(input.parentIds, 'parentIds', true);
  return finish({ ...state, families: [...state.families, { id: input.id, label: input.label, parentIds: [...input.parentIds], reason: input.reason }] });
}
/** A directed derivation edge, never a declaration of independent corroboration. */
export function linkSourceFamilies(state: EvidenceState, ctx: Context, input: { childId: string; parentId: string; reason: string }): EvidenceState {
  guard(state, ctx); object(input, 'family link'); nonempty(input.reason, 'reason'); roots(state, input.childId); roots(state, input.parentId);
  const child = state.families.find(f => f.id === input.childId)!;
  invariant(!child.parentIds.includes(input.parentId), 'duplicate', 'Source-family edge already exists');
  return finish({ ...state, families: state.families.map(f => f.id === input.childId ? { ...f, parentIds: [...f.parentIds, input.parentId], reason: input.reason } : f) });
}
export function recordFamilyIndependence(state: EvidenceState, ctx: Context, input: { id: string; familyIds: readonly [string, string]; rationale: string }): EvidenceState {
  guard(state, ctx); object(input, 'independence'); invariant(ctx.actor.kind === 'human', 'human_review_required', 'Source independence needs an attributable human assessment'); strings(input.familyIds, 'familyIds');
  invariant(input.familyIds.length === 2 && input.familyIds.every(id => { const r = roots(state, id); return r.length === 1 && r[0] === id; }), 'invalid_family', 'Assess independent root families');
  return finish({ ...state, independence: [...state.independence, { id: input.id, familyIds: [...input.familyIds] as [string, string], rationale: input.rationale, graphDigest: familyGraphDigest(state), ...stamp(ctx) }] });
}
export type AcquisitionInput = Readonly<{
  id: string; acquisitionId: string; bytes: Uint8Array; mediaType: string; storageVersionRef: string;
  sourceFamilyId: string | null; capturedAt: string; originalLanguage: string;
  allowedPurposes: readonly string[]; supersedes: EvidenceRef | null;
}>;
function acquired(state: EvidenceState, ctx: Context, input: AcquisitionInput, lineage: EvidenceVersion['lineage']): EvidenceState {
  object(input, 'acquisition'); nonempty(input.id, 'id'); invariant(input.bytes instanceof Uint8Array, 'invalid_input', 'Acquisition requires exact bytes');
  strings(input.allowedPurposes, 'allowedPurposes');
  const existing = state.versions.filter(v => v.ref.id === input.id);
  if (existing.length) {
    invariant(input.supersedes !== null, 'stale_revision', 'A replacement must name the exact current revision'); current(state, input.supersedes);
    invariant(input.supersedes.id === input.id && existing.every(v => v.lineage === null), 'invalid_lineage', 'Original acquisitions cannot rewrite derivative lineage');
  } else invariant(input.supersedes === null, 'invalid_revision', 'New evidence cannot supersede another object');
  const ref: EvidenceRef = { tenantId: state.tenantId, projectId: state.projectId, kind: 'evidence', id: input.id, revision: (input.supersedes?.revision ?? 0) + 1 };
  const metadata = { ref, acquisitionId: input.acquisitionId, sha256: hashBytes(input.bytes), byteLength: input.bytes.byteLength, mediaType: input.mediaType,
    storageVersionRef: input.storageVersionRef, sourceFamilyId: input.sourceFamilyId, capturedAt: input.capturedAt, originalLanguage: input.originalLanguage,
    allowedPurposes: [...input.allowedPurposes], supersedes: input.supersedes, lineage, acquired: stamp(ctx) };
  const next = { ...state, versions: [...state.versions, { ...metadata, metadataHash: digest(metadata) }] };
  return handled(next, ctx, ref, lineage ? 'redacted_derivative_acquired' : 'acquired', 'Exact bytes acquired into quarantine');
}
export function acquireEvidence(state: EvidenceState, ctx: Context, input: AcquisitionInput): EvidenceState { guard(state, ctx); return finish(acquired(state, ctx, input, null)); }
export function getEvidenceVersion(state: EvidenceState, ctx: Context, ref: EvidenceRef): EvidenceVersion { guard(state, ctx); return freeze(version(state, ref)); }
export function getScanStatus(state: EvidenceState, ctx: Context, ref: EvidenceRef): ScanStatus { guard(state, ctx); version(state, ref); return scanStatus(state, ref); }
export function requireEvidenceUsable(state: EvidenceState, ctx: Context, ref: EvidenceRef, options: { requireCurrent?: boolean } = {}): EvidenceVersion { guard(state, ctx); return freeze(usable(state, ctx, ref, options.requireCurrent !== false)); }
export function beginScan(state: EvidenceState, ctx: Context, input: { id: string; evidence: EvidenceRef; attemptId: string; engineVersion: string }): EvidenceState {
  guard(state, ctx); object(input, 'scan'); const v = version(state, input.evidence); nonempty(input.attemptId, 'attemptId'); nonempty(input.engineVersion, 'engineVersion');
  invariant(!state.scans.some(s => s.attemptId === input.attemptId), 'duplicate', 'Scan attempt IDs cannot be reused');
  const s: ScanRecord = { ...stamp(ctx), id: input.id, evidence: v.ref, attemptId: input.attemptId, engineVersion: input.engineVersion, status: 'scanning', sha256: v.sha256, reason: 'Scan started' };
  return finish(handled({ ...state, scans: [...state.scans, s] }, ctx, v.ref, 'scan_started', input.engineVersion));
}
export function completeScan(state: EvidenceState, ctx: Context, input: { id: string; evidence: EvidenceRef; attemptId: string; sha256: string; status: 'clean' | 'infected' | 'failed'; reason: string }): EvidenceState {
  guard(state, ctx); object(input, 'scan result'); version(state, input.evidence); invariant(['clean', 'infected', 'failed'].includes(input.status), 'invalid_status', 'Unknown scan result');
  const active = state.scans.findLast(s => exact(s.evidence, input.evidence));
  invariant(active?.status === 'scanning' && active.attemptId === input.attemptId, 'stale_scan', 'Scan attempt is no longer active');
  if (input.status === 'clean') invariant(state.integrity.findLast(i => exact(i.evidence, input.evidence))?.status !== 'mismatch', 'integrity_failure', 'Resolve the byte mismatch before marking evidence clean');
  return finish(handled({ ...state, scans: [...state.scans, { ...stamp(ctx), id: input.id, evidence: input.evidence, attemptId: input.attemptId, sha256: input.sha256, status: input.status, reason: input.reason, engineVersion: active.engineVersion }] }, ctx, input.evidence, 'scan_completed', input.status));
}
export function quarantineEvidence(state: EvidenceState, ctx: Context, input: { id: string; evidence: EvidenceRef; reason: string }): EvidenceState {
  guard(state, ctx); object(input, 'quarantine'); const v = version(state, input.evidence);
  return finish(handled({ ...state, scans: [...state.scans, { ...stamp(ctx), id: input.id, evidence: input.evidence, reason: input.reason, status: 'quarantined', attemptId: null, engineVersion: null, sha256: v.sha256 }] }, ctx, v.ref, 'quarantined', input.reason));
}
export function recordIntegrityCheck(state: EvidenceState, ctx: Context, input: { id: string; evidence: EvidenceRef; bytes: Uint8Array }): EvidenceState {
  guard(state, ctx); object(input, 'integrity check'); const v = version(state, input.evidence); invariant(input.bytes instanceof Uint8Array, 'invalid_input', 'Integrity check requires bytes');
  const observedSha256 = hashBytes(input.bytes); const status = observedSha256 === v.sha256 ? 'matched' : 'mismatch';
  let next: EvidenceState = { ...state, integrity: [...state.integrity, { ...stamp(ctx), id: input.id, evidence: v.ref, observedSha256, expectedSha256: v.sha256, status }] };
  next = handled(next, ctx, v.ref, 'integrity_checked', status);
  if (status === 'mismatch') next = { ...next, scans: [...next.scans, { ...stamp(ctx), id: `integrity:${input.id}`, evidence: v.ref, status: 'quarantined', attemptId: null, engineVersion: null, sha256: v.sha256, reason: 'Byte integrity mismatch' }] };
  return finish(next);
}
export function recordHandling(state: EvidenceState, ctx: Context, input: { evidence: EvidenceRef; action: 'inspected' | 'transferred' | 'storage_verified'; detail: string; expectedSha256: string }): EvidenceState {
  guard(state, ctx); object(input, 'handling'); invariant(['inspected', 'transferred', 'storage_verified'].includes(input.action), 'invalid_status', 'Unknown handling action');
  const v = usable(state, ctx, input.evidence, false); invariant(v.sha256 === input.expectedSha256, 'integrity_failure', 'Handling references different bytes'); nonempty(input.detail, 'detail');
  return finish(handled(state, ctx, v.ref, input.action, input.detail));
}
export function addRepresentation(state: EvidenceState, ctx: Context, input: { id: string; evidence: EvidenceRef; sourceSha256: string; text: string | null; pages: readonly string[] | null; durationMs: number | null; toolVersion: string }): EvidenceState {
  guard(state, ctx); object(input, 'representation'); const v = usable(state, ctx, input.evidence, true);
  const body = { id: input.id, evidence: input.evidence, sourceSha256: input.sourceSha256, text: input.text, pages: input.pages, durationMs: input.durationMs, toolVersion: input.toolVersion, ...stamp(ctx) };
  return finish(handled({ ...state, representations: [...state.representations, { ...body, digest: digest(body) }] }, ctx, v.ref, 'representation_added', input.toolVersion));
}
export function validateEvidenceSelector(state: EvidenceState, ctx: Context, selector: EvidenceSelector, options: { requireCurrent?: boolean } = {}): EvidenceVersion {
  guard(state, ctx); object(selector, 'selector'); const v = usable(state, ctx, selector.evidence, options.requireCurrent !== false);
  invariant(selector.sha256 === v.sha256, 'invalid_selector', 'Selector is bound to different bytes');
  invariant(['whole', 'text', 'page', 'time'].includes(selector.kind), 'invalid_selector', 'Unknown selector kind');
  if (selector.kind === 'whole') return freeze(v);
  const r = representation(state, v.ref, selector.representationId); invariant(selector.representationDigest === r.digest, 'invalid_selector', 'Representation revision digest mismatch');
  if (selector.kind === 'text') {
    let text = r.text;
    if (selector.page !== null) { integer(selector.page, 1, 'page'); invariant(r.pages !== null && selector.page <= r.pages.length, 'invalid_selector', 'Page is outside the representation'); text = r.pages[selector.page - 1] ?? null; }
    invariant(text !== null, 'invalid_selector', 'Text is not available at this anchor'); integer(selector.start, 0, 'text start'); integer(selector.end, 1, 'text end');
    invariant(selector.start < selector.end && selector.end <= text.length, 'invalid_selector', 'Text range is empty or outside the representation');
    invariant(typeof selector.quote === 'string' && text.slice(selector.start, selector.end) === selector.quote, 'invalid_selector', 'Quote does not match the exact selected text');
    invariant(codePointBoundary(text, selector.start) && codePointBoundary(text, selector.end), 'invalid_selector', 'Text range splits a Unicode surrogate pair');
  } else if (selector.kind === 'page') {
    integer(selector.fromPage, 1, 'fromPage'); integer(selector.toPage, 1, 'toPage');
    invariant(r.pages !== null && selector.fromPage <= selector.toPage && selector.toPage <= r.pages.length, 'invalid_selector', 'Page range is outside the representation');
  } else {
    integer(selector.startMs, 0, 'startMs'); integer(selector.endMs, 1, 'endMs');
    invariant(r.durationMs !== null && selector.startMs < selector.endMs && selector.endMs <= r.durationMs, 'invalid_selector', 'Time range is outside the representation');
  }
  return freeze(v);
}
function codePointBoundary(text: string, at: number): boolean { return !(at > 0 && at < text.length && /[\uD800-\uDBFF]/.test(text[at - 1]!) && /[\uDC00-\uDFFF]/.test(text[at]!)); }
export function getFamilySnapshot(state: EvidenceState, ctx: Context, ref: EvidenceRef): FamilySnapshot {
  guard(state, ctx); const v = version(state, ref); const familyRoots = v.sourceFamilyId === null ? [] : roots(state, v.sourceFamilyId);
  return freeze({ familyId: v.sourceFamilyId, roots: familyRoots, basisDigest: digest({ graph: familyGraphDigest(state), familyId: v.sourceFamilyId, roots: familyRoots, sha256: v.sha256, ancestors: lineageAncestors(state, ref) }) });
}
export function evidenceDependencyFingerprint(state: EvidenceState, ctx: Context, selector: EvidenceSelector): string {
  validateEvidenceSelector(state, ctx, selector);
  return digest({ selector, metadataHash: version(state, selector.evidence).metadataHash, family: getFamilySnapshot(state, ctx, selector.evidence), scan: state.scans.findLast(s => exact(s.evidence, selector.evidence)) ?? null,
    integrity: state.integrity.findLast(i => exact(i.evidence, selector.evidence)) ?? null });
}
/** Distinct files/families are not automatically independent; all cross-group root pairs need current human assessments. */
export function analyzeSources(state: EvidenceState, ctx: Context, refs: readonly EvidenceRef[]): SourceAnalysis {
  guard(state, ctx); invariant(Array.isArray(refs), 'invalid_input', 'Evidence refs must be an array');
  const unique = [...new Map(refs.map(r => [key(version(state, r).ref), r])).values()];
  const records = unique.map(r => ({ ref: r, v: version(state, r), roots: getFamilySnapshot(state, ctx, r).roots, ancestors: lineageAncestors(state, r) }));
  const groups: typeof records[] = [];
  const related = (a: typeof records[number], b: typeof records[number]): boolean => a.v.sha256 === b.v.sha256 || a.roots.some(r => b.roots.includes(r)) || a.ancestors.some(r => b.ancestors.includes(r));
  for (const record of records) {
    const matching = groups.filter(g => g.some(other => related(record, other)));
    const merged = [record, ...matching.flat()];
    for (const match of matching) groups.splice(groups.indexOf(match), 1);
    groups.push(merged);
  }
  const unknownFamilyRefs = records.filter(r => r.roots.length === 0).map(r => r.ref);
  const graphDigest = familyGraphDigest(state);
  const assessed = (a: string, b: string): boolean => state.independence.some(i => i.graphDigest === graphDigest && i.familyIds.includes(a) && i.familyIds.includes(b));
  let allGroupsIndependentlyAssessed = records.length > 0 && unknownFamilyRefs.length === 0;
  for (let i = 0; i < groups.length; i++) for (let j = i + 1; j < groups.length; j++) {
    for (const a of groups[i]!) for (const b of groups[j]!) for (const ar of a.roots) for (const br of b.roots) if (!assessed(ar, br)) allGroupsIndependentlyAssessed = false;
  }
  return freeze({ groups: groups.map(g => g.map(r => r.ref)), sourceGroupCount: groups.length, uniqueByteCount: new Set(records.map(r => r.v.sha256)).size, unknownFamilyRefs,
    allGroupsIndependentlyAssessed, independentFamilyCount: allGroupsIndependentlyAssessed ? groups.length : null,
    basisDigest: digest({ graphDigest, refs: unique.map(r => key(r)).sort(), assessments: state.independence }) });
}
function validateRanges(ranges: readonly RedactionRange[], length: number): void {
  invariant(Array.isArray(ranges) && ranges.length > 0, 'invalid_input', 'At least one redaction range is required'); let previousEnd = 0;
  for (const r of ranges) { object(r, 'redaction range'); integer(r.start, 0, 'start'); integer(r.end, 1, 'end'); nonempty(r.reason, 'redaction reason'); invariant(r.start >= previousEnd && r.end > r.start && r.end <= length, 'invalid_selector', 'Redactions must be sorted, disjoint and in bounds'); previousEnd = r.end; }
}
function redactText(text: string, ranges: readonly RedactionRange[]): string {
  validateRanges(ranges, text.length); let result = ''; let cursor = 0;
  for (const r of ranges) { invariant(codePointBoundary(text, r.start) && codePointBoundary(text, r.end), 'invalid_selector', 'Redaction splits a Unicode surrogate pair'); result += text.slice(cursor, r.start) + '[REDACTED]'; cursor = r.end; }
  return result + text.slice(cursor);
}
export function approveTextRedaction(state: EvidenceState, ctx: Context, input: { id: string; source: EvidenceRef; representationId: string; ranges: readonly RedactionRange[]; targetPurpose: string; policyVersion: string; expiresAt: string }): EvidenceState {
  guard(state, ctx); object(input, 'redaction approval'); invariant(ctx.actor.kind === 'human', 'human_review_required', 'Redaction purpose requires a human decision'); usable(state, ctx, input.source, true);
  const r = representation(state, input.source, input.representationId); invariant(r.text !== null, 'invalid_selector', 'Redaction requires a full-text representation'); redactText(r.text, input.ranges);
  const body = { id: input.id, source: input.source, representationId: input.representationId, ranges: input.ranges, targetPurpose: input.targetPurpose, policyVersion: input.policyVersion, expiresAt: input.expiresAt,
    representationDigest: r.digest, reviewerId: ctx.actor.id, ...stamp(ctx) };
  return finish(handled({ ...state, redactionPlans: [...state.redactionPlans, { ...body, digest: digest(body) }] }, ctx, input.source, 'redaction_approved', input.targetPurpose));
}
/** Returns output bytes separately; caller must atomically persist these bytes and the returned metadata. */
export function createRedactedDerivative(state: EvidenceState, ctx: Context, input: { planId: string; id: string; acquisitionId: string; storageVersionRef: string }): { state: EvidenceState; bytes: Uint8Array; ref: EvidenceRef } {
  guard(state, ctx); object(input, 'redaction'); const plan = state.redactionPlans.find(p => p.id === input.planId); invariant(plan, 'not_found', 'Redaction plan does not exist');
  before(ctx, plan.at); invariant(validTime(ctx.now) < validTime(plan.expiresAt), 'expired', 'Redaction plan expired'); const source = usable(state, ctx, plan.source, true);
  invariant(!state.versions.some(v => v.ref.id === input.id), 'invalid_lineage', 'Derivative must be a new evidence object');
  const r = representation(state, source.ref, plan.representationId); const bytes = new Uint8Array(Buffer.from(redactText(r.text!, plan.ranges), 'utf8'));
  const next = finish(acquired(state, ctx, { id: input.id, acquisitionId: input.acquisitionId, bytes, storageVersionRef: input.storageVersionRef, mediaType: 'text/plain', sourceFamilyId: source.sourceFamilyId,
    capturedAt: ctx.now, originalLanguage: source.originalLanguage, allowedPurposes: [plan.targetPurpose], supersedes: null }, { parent: source.ref, redactionPlanId: plan.id }));
  return { state: next, bytes, ref: next.versions.at(-1)!.ref };
}
