import { sourceFilePath } from '../app/paths';

export const PROPOSAL_REVIEW_LIMITS = {
  documentBytes: 1024 * 1024,
  filesInDocument: 200,
  filesRendered: 40,
  linesPerFileInDocument: 2000,
  linesPerFileRendered: 400,
  lineCharacters: 4096,
  hunksPerFile: 40,
  findings: 200,
  historyEntries: 40,
} as const;

export type ReviewState = 'unvalidated' | 'validating' | 'validated-pass' | 'validated-fail' | 'rejected' | 'superseded' | 'accepted';
export type FileKind = 'added' | 'modified' | 'deleted' | 'binary';
export type DiffLineKind = 'context' | 'addition' | 'deletion';

export interface RevisionPin {
  revisionId: string;
  sourceSha256: string;
  metadataVersion: string;
}

export interface ProposalReviewIdentity {
  proposalId: string;
  taskId: string;
  jobId: string;
  runId: string;
  base: RevisionPin;
  candidate: RevisionPin & { parentRevisionId: string };
  currentBase: RevisionPin | null;
}

export interface ValidationBinding {
  proposalId: string;
  taskId: string;
  baseRevisionId: string;
  candidateRevisionId: string;
  baseSourceSha256: string;
  candidateSourceSha256: string;
}

export interface ValidationFinding {
  code: string;
  severity: 'error' | 'warning' | 'info';
  summary: string;
  fileId: string | null;
}

export interface ValidationEvidence {
  source: 'fixture-record';
  binding: ValidationBinding;
  validatorId: string;
  checkpointSha256: string;
  outcome: 'passed' | 'failed';
  recordedAt: string;
  findings: ValidationFinding[];
}

export interface DiffLine {
  kind: DiffLineKind;
  text: string;
}

export interface DiffHunk {
  header: string;
  lines: DiffLine[];
}

export interface ProposalFileChange {
  fileId: string;
  path: string;
  kind: FileKind;
  baseFileId: string | null;
  candidateFileId: string | null;
  baseOwner: string | null;
  candidateOwner: string | null;
  ownershipViolation: { expectedOwner: string; actualOwner: string } | null;
  sizeBytes: number | null;
  shownLines: number;
  totalLines: number | null;
  omittedBytes: number | null;
  truncated: boolean;
  hunks: DiffHunk[];
}

export interface ProposalHistoryEntry {
  state: ReviewState;
  recordedAt: string;
  actor: string;
}

export interface ProposalReviewDocument {
  schema: 'proposal-review-fixture/v1';
  source: 'fixture';
  identity: ProposalReviewIdentity;
  state: ReviewState;
  supersededBy: string | null;
  validation: ValidationEvidence | null;
  files: ProposalFileChange[];
  totalFiles: number;
  omittedFiles: number;
  history: ProposalHistoryEntry[];
  regressionDelta: { added: number; removed: number; unchanged: number } | null;
}

export class ProposalReviewDecodeError extends Error {
  constructor() {
    super();
    this.name = 'ProposalReviewDecodeError';
  }
}

type RecordValue = Record<string, unknown>;

function record(value: unknown): value is RecordValue {
  return typeof value === 'object' && value !== null && !Array.isArray(value);
}

function text(value: unknown, max = 512): value is string {
  return typeof value === 'string' && value.length > 0 && value.length <= max && !hasUnsupportedControl(value);
}

function hasUnsupportedControl(value: string): boolean {
  return [...value].some(character => {
    const code = character.charCodeAt(0);
    return code <= 8 || code === 11 || code === 12 || (code >= 14 && code <= 31);
  });
}

function nullableText(value: unknown, max = 512): value is string | null {
  return value === null || text(value, max);
}

function id(value: unknown): value is string {
  return typeof value === 'string' && /^[A-Za-z0-9][A-Za-z0-9_-]{0,127}$/.test(value);
}

function hash(value: unknown): value is string {
  return typeof value === 'string' && /^[a-f0-9]{64}$/.test(value);
}

function count(value: unknown, max = Number.MAX_SAFE_INTEGER): value is number {
  return typeof value === 'number' && Number.isSafeInteger(value) && value >= 0 && value <= max;
}

function timestamp(value: unknown): value is string {
  return typeof value === 'string' && value.length <= 40 && Number.isFinite(Date.parse(value));
}

function isState(value: unknown): value is ReviewState {
  return value === 'unvalidated' || value === 'validating' || value === 'validated-pass' || value === 'validated-fail' ||
    value === 'rejected' || value === 'superseded' || value === 'accepted';
}

function isRevisionPin(value: unknown): value is RevisionPin {
  return record(value) && id(value.revisionId) && hash(value.sourceSha256) && hash(value.metadataVersion);
}

function isCandidatePin(value: unknown): value is RevisionPin & { parentRevisionId: string } {
  return isRevisionPin(value) && record(value) && id(value.parentRevisionId);
}

function sameValidationBinding(value: ValidationBinding, identity: ProposalReviewIdentity): boolean {
  return value.proposalId === identity.proposalId && value.taskId === identity.taskId &&
    value.baseRevisionId === identity.base.revisionId && value.candidateRevisionId === identity.candidate.revisionId &&
    value.baseSourceSha256 === identity.base.sourceSha256 && value.candidateSourceSha256 === identity.candidate.sourceSha256;
}

function decodeIdentity(value: unknown): ProposalReviewIdentity | null {
  if (!record(value) || !id(value.proposalId) || !id(value.taskId) || !/^[0-9a-f]{32}$/.test(String(value.jobId)) || !id(value.runId) ||
    !isRevisionPin(value.base) || !isCandidatePin(value.candidate) ||
    !(value.currentBase === null || isRevisionPin(value.currentBase))) return null;
  return value as unknown as ProposalReviewIdentity;
}

function decodeValidation(value: unknown, identity: ProposalReviewIdentity): ValidationEvidence | null | undefined {
  if (value === null) return null;
  if (!record(value) || value.source !== 'fixture-record' || !record(value.binding) || !id(value.binding.proposalId) ||
    !id(value.binding.taskId) || !id(value.binding.baseRevisionId) || !id(value.binding.candidateRevisionId) ||
    !hash(value.binding.baseSourceSha256) || !hash(value.binding.candidateSourceSha256) ||
    !id(value.validatorId) || !hash(value.checkpointSha256) || (value.outcome !== 'passed' && value.outcome !== 'failed') ||
    !timestamp(value.recordedAt) || !Array.isArray(value.findings) || value.findings.length > PROPOSAL_REVIEW_LIMITS.findings) return undefined;
  const findings: ValidationFinding[] = [];
  for (const item of value.findings) {
    if (!record(item) || !id(item.code) || (item.severity !== 'error' && item.severity !== 'warning' && item.severity !== 'info') ||
      !text(item.summary, 1000) || !nullableText(item.fileId, 128)) return undefined;
    findings.push(item as unknown as ValidationFinding);
  }
  const binding = value.binding as unknown as ValidationBinding;
  if (!sameValidationBinding(binding, identity)) return undefined;
  return { ...value, binding, findings } as unknown as ValidationEvidence;
}

function decodeFiles(value: unknown): ProposalFileChange[] | undefined {
  if (!Array.isArray(value) || value.length > PROPOSAL_REVIEW_LIMITS.filesInDocument) return undefined;
  const files: ProposalFileChange[] = [];
  const seen = new Set<string>();
  for (const item of value) {
    if (!record(item) || !id(item.fileId) || seen.has(item.fileId) || !text(item.path, 512) ||
      (item.kind !== 'added' && item.kind !== 'modified' && item.kind !== 'deleted' && item.kind !== 'binary') ||
      !(item.baseFileId === null || id(item.baseFileId)) || !(item.candidateFileId === null || id(item.candidateFileId)) ||
      !nullableText(item.baseOwner, 128) || !nullableText(item.candidateOwner, 128) || !count(item.shownLines, PROPOSAL_REVIEW_LIMITS.linesPerFileInDocument) ||
      !(item.totalLines === null || count(item.totalLines, 1_000_000)) || !(item.omittedBytes === null || count(item.omittedBytes, 1_000_000_000)) ||
      typeof item.truncated !== 'boolean' || !(item.sizeBytes === null || count(item.sizeBytes, 1_000_000_000_000)) ||
      !Array.isArray(item.hunks) || item.hunks.length > PROPOSAL_REVIEW_LIMITS.hunksPerFile) return undefined;
    if ((item.kind === 'added' && (item.baseFileId !== null || item.candidateFileId === null)) ||
      (item.kind === 'deleted' && (item.candidateFileId !== null || item.baseFileId === null)) ||
      (item.kind === 'modified' && (item.baseFileId === null || item.candidateFileId === null)) ||
      (item.baseFileId === null && item.candidateFileId === null) || (item.kind === 'binary' && item.hunks.length !== 0)) return undefined;
    const hunks: DiffHunk[] = [];
    let lineCount = 0;
    for (const hunk of item.hunks) {
      if (!record(hunk) || !text(hunk.header, 256) || !Array.isArray(hunk.lines) || hunk.lines.length > PROPOSAL_REVIEW_LIMITS.linesPerFileInDocument) return undefined;
      const lines: DiffLine[] = [];
      for (const line of hunk.lines) {
        if (!record(line) || (line.kind !== 'context' && line.kind !== 'addition' && line.kind !== 'deletion') ||
          typeof line.text !== 'string' || line.text.length > PROPOSAL_REVIEW_LIMITS.lineCharacters || hasUnsupportedControl(line.text)) return undefined;
        lines.push(line as unknown as DiffLine);
      }
      lineCount += lines.length;
      if (lineCount > PROPOSAL_REVIEW_LIMITS.linesPerFileInDocument) return undefined;
      hunks.push({ header: hunk.header, lines });
    }
    if (lineCount !== item.shownLines || (item.totalLines !== null && item.totalLines < item.shownLines) ||
      (!item.truncated && (item.omittedBytes !== 0 || item.totalLines !== item.shownLines)) ||
      (item.truncated && item.omittedBytes === 0 && item.totalLines === item.shownLines)) return undefined;
    if (item.kind === 'binary' && item.sizeBytes === null) return undefined;
    seen.add(item.fileId);
    files.push(item as unknown as ProposalFileChange);
  }
  return files;
}

function decodeHistory(value: unknown): ProposalHistoryEntry[] | undefined {
  if (!Array.isArray(value) || value.length > PROPOSAL_REVIEW_LIMITS.historyEntries) return undefined;
  const result: ProposalHistoryEntry[] = [];
  for (const item of value) {
    if (!record(item) || !isState(item.state) || !timestamp(item.recordedAt) || !text(item.actor, 128)) return undefined;
    result.push(item as unknown as ProposalHistoryEntry);
  }
  return result;
}

/** Canonical, collision-safe identity for the exact review and both revision pins. */
export function proposalReviewBinding(identity: ProposalReviewIdentity): string {
  return JSON.stringify([
    identity.proposalId, identity.taskId, identity.jobId, identity.runId,
    identity.base.revisionId, identity.base.sourceSha256, identity.base.metadataVersion,
    identity.candidate.revisionId, identity.candidate.sourceSha256, identity.candidate.metadataVersion,
    identity.candidate.parentRevisionId,
    identity.currentBase?.revisionId ?? null, identity.currentBase?.sourceSha256 ?? null, identity.currentBase?.metadataVersion ?? null,
  ]);
}

/** Refuse malformed, contradictory or over-limit fixture documents before rendering any part of them. */
export function decodeProposalReview(value: unknown): ProposalReviewDocument {
  let bytes: number;
  try {
    bytes = new TextEncoder().encode(JSON.stringify(value)).byteLength;
  } catch {
    throw new ProposalReviewDecodeError();
  }
  if (bytes > PROPOSAL_REVIEW_LIMITS.documentBytes || !record(value) || value.schema !== 'proposal-review-fixture/v1' || value.source !== 'fixture')
    throw new ProposalReviewDecodeError();
  const identity = decodeIdentity(value.identity);
  if (!identity || !isState(value.state) || !nullableText(value.supersededBy, 128) ||
    !count(value.totalFiles, 100_000) || !count(value.omittedFiles, 100_000) || !Array.isArray(value.files) ||
    !count(value.regressionDelta === null ? 0 : (record(value.regressionDelta) ? value.regressionDelta.added : -1), 1_000_000) ||
    !count(value.regressionDelta === null ? 0 : (record(value.regressionDelta) ? value.regressionDelta.removed : -1), 1_000_000) ||
    !count(value.regressionDelta === null ? 0 : (record(value.regressionDelta) ? value.regressionDelta.unchanged : -1), 1_000_000))
    throw new ProposalReviewDecodeError();
  const files = decodeFiles(value.files);
  const history = decodeHistory(value.history);
  const validation = decodeValidation(value.validation, identity);
  if (!files || !history || validation === undefined || value.totalFiles < files.length || value.omittedFiles !== value.totalFiles - files.length ||
    identity.candidate.parentRevisionId !== identity.base.revisionId ||
    (value.state === 'superseded' && !id(value.supersededBy)) || (value.state !== 'superseded' && value.supersededBy !== null) ||
    (value.state === 'unvalidated' && validation !== null) ||
    ((value.state === 'validated-pass' || value.state === 'accepted') && validation?.outcome !== 'passed') ||
    (value.state === 'validated-fail' && validation?.outcome !== 'failed') ||
    (value.state === 'accepted' && !validation) ||
    (value.regressionDelta !== null && (!record(value.regressionDelta) || !count(value.regressionDelta.added, 1_000_000) ||
      !count(value.regressionDelta.removed, 1_000_000) || !count(value.regressionDelta.unchanged, 1_000_000))))
    throw new ProposalReviewDecodeError();
  return value as unknown as ProposalReviewDocument;
}

/** Exact pinned source links only; missing file identity never falls back to a mutable route. */
export function proposalSnapshotHref(basePath: string, identity: ProposalReviewIdentity, side: 'base' | 'candidate', fileId: string | null): string | null {
  if (!fileId) return null;
  const pin = identity[side];
  return sourceFilePath(basePath, { jobId: identity.jobId, runId: identity.runId, revisionId: pin.revisionId }, fileId,
    { sourceSha256: pin.sourceSha256, metadataVersion: pin.metadataVersion });
}
