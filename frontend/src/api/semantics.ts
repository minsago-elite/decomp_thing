import type { Artifact, ContractDocument, Page, RevisionDirectory, Run, SourceChunk, SourceSearch, ValidationBytePreview, ValidationCases, ValidationFailure, ValidationHistory, ValidationSummary } from './generated';
import { ApiClientError } from './errors';
import { normalizeBasePath, validateResourceHref } from '../app/paths';
import type { ApiResource } from '../app/paths';

const requireValue = (condition: boolean): void => {
  if (!condition) throw new ApiClientError('invalid_response');
};

function checkValidationHistory(value: ValidationHistory): void {
  if (value.state !== 'recorded') {
    requireValue([value.graphSha256, value.corpusSha256, value.page, value.totalPages,
      value.previousPage, value.nextPage].every(field => field === null) && value.items.length === 0);
    return;
  }
  if (value.page === null || value.totalPages === null) throw new ApiClientError('invalid_response');
  requireValue(value.page <= value.totalPages && value.graphSha256 !== null && value.corpusSha256 !== null);
  requireValue(value.previousPage === (value.page > 1 ? value.page - 1 : null));
  requireValue(value.nextPage === (value.page < value.totalPages ? value.page + 1 : null));
  requireValue(new Set(value.items.map(item => `${item.ownerKind}:${item.ownerId}`)).size === value.items.length);
  value.items.forEach(item => {
    requireValue(item.canInspect === (item.hasReceipt && !item.identityWithheld));
    if (item.ownerKind === 'run-failure') requireValue(item.hasReceipt && item.normalOutcome === null && item.failureKind != null);
    else requireValue(item.failureKind == null && item.hasReceipt === (item.normalOutcome !== null));
    const refs = [item.candidateId, item.sourceSha256, item.corpusSha256];
    requireValue(refs.every(field => item.canInspect ? field !== null : field === null));
    // The selected receipt may precede growth of the current retained corpus.
  });
}

function checkValidationFailure(value: ValidationFailure): void {
  const total = BigInt(value.inputCount), completed = BigInt(value.reportedCompletedPairs);
  requireValue(completed <= total && value.reportedCleanupVerified === (value.classification !== 'cleanup-unverified'));
  requireValue(value.classification === (value.reason === 'timeout' ? 'resource-exhausted' : value.reason));
  const casePhase = ['before-case', 'original-operation', 'rebuilt-operation'].includes(value.phase);
  requireValue(casePhase === (value.inputOrdinal !== null));
  if (value.inputOrdinal !== null) {
    const ordinal = BigInt(value.inputOrdinal);
    requireValue(ordinal >= 1n && ordinal <= total && completed + 1n === ordinal);
  }
  if (['source-preparation', 'build', 'build-finalization', 'capture-rebuilt'].includes(value.phase)) requireValue(completed === 0n);
}

function checkValidationPreview(value: ValidationBytePreview | null, bytes: string | null): void {
  if (value === null || bytes === null) throw new ApiClientError('invalid_response');
  const total = BigInt(bytes), prefix = total > 128n ? 128 : Number(total);
  requireValue(value.totalBytes === bytes && value.prefixBytes === prefix && value.truncated === (total > BigInt(prefix)));
  const tokens = value.hex === '' ? [] : value.hex.split(/[ \n]/u);
  requireValue(tokens.length === prefix && tokens.every(token => /^[0-9a-f]{2}$/u.test(token)));
  requireValue(value.hex === tokens.map((token, index) => `${index === 0 ? '' : index % 16 === 0 ? '\n' : ' '}${token}`).join(''));
  requireValue((value.text === null) === (value.textBytes === null));
  if (value.textBytes !== null) requireValue(value.textBytes <= prefix &&
    (value.truncated ? prefix - value.textBytes <= 3 : value.textBytes === prefix));
  let expectedText: string | null = null, expectedBytes: number | null = null;
  try {
    // Streaming leaves only an incomplete suffix undecoded; malformed UTF-8 still throws.
    const decoded = new TextDecoder('utf-8', { fatal: true, ignoreBOM: true })
      .decode(Uint8Array.from(tokens, token => Number.parseInt(token, 16)), { stream: value.truncated });
    expectedBytes = new TextEncoder().encode(decoded).length;
    expectedText = Array.from(decoded, character => {
      if (character === '\\') return '\\\\';
      if (character === '\r') return '\\r';
      if (character === '\n') return '\\n\n';
      if (character === '\t') return '\\t';
      const code = character.codePointAt(0)!;
      return code <= 31 || (code >= 127 && code <= 159) || /[\p{Cf}\p{Zl}\p{Zp}]/u.test(character)
        ? `${code > 65535 ? '\\U' : '\\u'}${code.toString(16).padStart(code > 65535 ? 8 : 4, '0')}` : character;
    }).join('');
  } catch { /* Malformed bytes have no text representation. */ }
  requireValue(value.text === expectedText && value.textBytes === expectedBytes);
}

function checkValidationCases(value: ValidationCases, summary: ValidationSummary): void {
  const total = BigInt(value.totalInputs), start = BigInt(value.page - 1) * 20n;
  const pages = total === 0n ? 1n : (total + 19n) / 20n;
  requireValue(BigInt(value.totalPages) === pages && value.page <= value.totalPages);
  const remaining = total > start ? total - start : 0n;
  requireValue(value.items.length === Number(remaining > 20n ? 20n : remaining));
  requireValue(value.previousPage === (value.page > 1 ? value.page - 1 : null));
  requireValue(value.nextPage === (value.page < value.totalPages ? value.page + 1 : null));
  requireValue(new Set(value.items.map(item => item.caseId)).size === value.items.length);
  requireValue(value.sourceSha256 === summary.sourceSha256);
  const behavior = value.normalOutcome === 'behavior-checked';
  let matched: bigint | null = null;
  if (behavior) {
    if (value.matchedInputs === null) throw new ApiClientError('invalid_response');
    matched = BigInt(value.matchedInputs);
    requireValue(total > 0n && matched <= total && summary.casesCompared === value.totalInputs);
    requireValue(summary.result === (matched === total ? 'passed' : 'failed'));
  } else requireValue(value.matchedInputs === null && summary.casesCompared === '0' &&
    summary.result === (value.normalOutcome === 'compile-failed' ? 'failed' : 'unknown'));
  let pageMatches = 0n;
  value.items.forEach((item, index) => {
    requireValue(BigInt(item.ordinal) === start + BigInt(index) + 1n);
    const flags = [item.exitCodeMatches, item.stdoutMatches, item.stderrMatches];
    const bytes = [item.originalStdoutBytes, item.rebuiltStdoutBytes, item.originalStderrBytes, item.rebuiltStderrBytes];
    const previews = [item.originalStdoutPreview, item.rebuiltStdoutPreview, item.originalStderrPreview, item.rebuiltStderrPreview];
    if (!behavior) {
      requireValue(item.outcome === (value.normalOutcome === 'compile-failed' ? 'compile-failed' : 'compile-only') &&
        [...flags, ...bytes, ...previews].every(field => field === null));
      return;
    }
    requireValue(flags.every(flag => flag !== null));
    previews.forEach((preview, position) => { checkValidationPreview(preview, bytes[position] ?? null); });
    for (const [flag, first, second] of [[item.stdoutMatches, item.originalStdoutPreview, item.rebuiltStdoutPreview],
      [item.stderrMatches, item.originalStderrPreview, item.rebuiltStderrPreview]] as const) {
      if (first === null || second === null) throw new ApiClientError('invalid_response');
      const samePrefix = first.totalBytes === second.totalBytes && first.hex === second.hex;
      if (flag) requireValue(samePrefix && first.text === second.text && first.textBytes === second.textBytes);
      if (!first.truncated && !second.truncated) requireValue(flag === samePrefix);
    }
    const same = flags.every(flag => flag === true);
    requireValue(item.outcome === (same ? 'matched' : 'mismatch'));
    if (same) pageMatches++;
  });
  if (matched !== null) requireValue(pageMatches <= matched && matched <= pageMatches + total - BigInt(value.items.length));
  let indexedMismatchPages: number[] | null = null;
  if (value.comparisonIndex != null) {
    requireValue(behavior && total <= 10000n);
    const size = Number(total), hex = value.comparisonIndex.mismatchBitmapHex;
    requireValue(hex.length === 2 * Math.ceil(size / 8));
    const mismatch = (ordinal: number) => (parseInt(hex.slice((ordinal >>> 3) * 2, (ordinal >>> 3) * 2 + 2), 16)
      & (1 << (ordinal & 7))) !== 0;
    let differences = 0;
    const pages = new Set<number>();
    for (let ordinal = 0; ordinal < size; ordinal++) if (mismatch(ordinal)) {
      differences++; pages.add(Math.floor(ordinal / 20) + 1);
    }
    for (let ordinal = size; ordinal < Math.ceil(size / 8) * 8; ordinal++) requireValue(!mismatch(ordinal));
    requireValue(BigInt(differences) === total - (matched ?? total));
    value.items.forEach(item => requireValue(mismatch(Number(item.ordinal) - 1) === (item.outcome === 'mismatch')));
    indexedMismatchPages = [...pages];
  }
  const navigation = [value.firstMismatchPage, value.previousMismatchPage, value.nextMismatchPage];
  if (navigation.every(page => page === undefined)) return; // Older v1 producers did not report mismatch navigation.
  requireValue(navigation.every(page => page !== undefined));
  if (indexedMismatchPages !== null) {
    const expected = [indexedMismatchPages[0] ?? null,
      indexedMismatchPages.filter(page => page < value.page).at(-1) ?? null,
      indexedMismatchPages.find(page => page > value.page) ?? null];
    requireValue(navigation.every((page, index) => page === expected[index]));
  }
  if (matched === null || matched === total) {
    requireValue(navigation.every(page => page === null));
    return;
  }
  const first = value.firstMismatchPage, previous = value.previousMismatchPage, next = value.nextMismatchPage;
  if (first == null) throw new ApiClientError('invalid_response');
  const knownPages = new Set(navigation.filter((page): page is number => page != null));
  requireValue([...knownPages].every(page => page >= 1 && page <= value.totalPages && page >= first));
  requireValue(previous == null ? first >= value.page : previous < value.page && first < value.page);
  requireValue(next == null || next > value.page);
  if (first > value.page) requireValue(next === first);
  const pageMismatches = BigInt(value.items.length) - pageMatches;
  if (pageMismatches > 0n) requireValue(first <= value.page);
  if (first === value.page) requireValue(pageMismatches > 0n);
  const outside = total - matched - pageMismatches;
  requireValue(BigInt([...knownPages].filter(page => page !== value.page).length) <= outside);
  if (outside > 0n) requireValue(previous != null || next != null);
}

function checkRun(run: Run): void {
  // Match the durable store, including terminal attempts cancelled before start.
  const reasons: Record<Run['state'], readonly Run['terminalReason'][]> = {
    queued: [null], running: [null], cancelling: [null],
    completed: ['COMPLETED', 'NO_CHANGES'],
    failed: ['FAILED', 'REFUSED', 'LIMIT_EXHAUSTED'],
    cancelled: ['CANCELLED'], interrupted: ['PROCESS_INTERRUPTED'],
  };
  requireValue(reasons[run.state].includes(run.terminalReason));
  if (run.state === 'queued') requireValue(run.startedAt === null);
  if (run.state === 'running' || run.state === 'completed') requireValue(run.startedAt !== null);
}

function checkSourcePage(items: ReadonlyArray<{ fileId: string; displayName: string }>, totalFiles: number, page: Page, version: string): void {
  requireValue(page.snapshotVersion === version && items.length <= page.limit && items.length <= totalFiles);
  requireValue(new Set(items.map(item => item.fileId)).size === items.length);
  requireValue(page.nextCursor === null || (items.length > 0 && items.length < totalFiles));
  requireValue(items.every(item => item.displayName.split('/').every(part =>
    part.trim().length > 0 && part !== '.' && part !== '..' && part.length <= 255)));
}

function isDirectoryLabel(label: string | null): boolean {
  // Match the host's Kotlin Char.isWhitespace set; JS trim also removes U+FEFF.
  return label !== null && /[^\u0020\u00a0\u1680\u2000-\u200a\u2028\u2029\u202f\u205f\u3000]/u.test(label)
    && label !== '.' && label !== '..';
}

function checkDirectory(directory: RevisionDirectory): void {
  const { items, page, metadataVersion, sourceFileCount, totalChildren, breadcrumbs, depth, directoryId } = directory;
  requireValue(page.snapshotVersion === metadataVersion && items.length <= page.limit
    && items.length <= totalChildren && totalChildren <= sourceFileCount);
  requireValue(page.nextCursor === null || items.length < totalChildren);
  const identities = items.map(item => item.kind === 'file' ? item.fileId : item.directoryId);
  requireValue(new Set(identities).size === items.length
    && new Set(items.map(item => item.displayName)).size === items.length);
  let count = 0;
  for (const [index, item] of items.entries()) {
    requireValue(isDirectoryLabel(item.displayName));
    count += item.kind === 'file' ? 1 : item.sourceFileCount;
    if (item.kind === 'directory') requireValue(!breadcrumbs.some(crumb => crumb.directoryId === item.directoryId));
    const previous = items[index - 1];
    if (previous) requireValue((previous.kind === 'directory' && item.kind === 'file')
      || (previous.kind === item.kind && previous.displayName < item.displayName));
  }
  requireValue(count <= sourceFileCount && (items.length !== totalChildren || count === sourceFileCount));
  requireValue(breadcrumbs.length === 1 + Math.min(depth, 31) && directory.omittedAncestors === Math.max(0, depth - 31));
  requireValue(breadcrumbs[0]?.directoryId === 'root' && breadcrumbs[0]?.displayName === null);
  requireValue(new Set(breadcrumbs.map(crumb => crumb.directoryId)).size === breadcrumbs.length);
  requireValue(breadcrumbs.at(-1)?.directoryId === directoryId && breadcrumbs.at(-1)?.displayName === directory.displayName);
  requireValue(breadcrumbs.slice(1).every(crumb => isDirectoryLabel(crumb.displayName)));
  if (depth === 0) requireValue(directoryId === 'root' && directory.parentDirectoryId === null && directory.displayName === null);
  else requireValue(directoryId !== 'root' && directory.displayName !== null
    && directory.parentDirectoryId === breadcrumbs.at(-2)?.directoryId);
}

export function checkSourceChunk(data: SourceChunk): void {
  const size = BigInt(data.sizeBytes), offset = BigInt(data.offsetBytes), length = BigInt(data.lengthBytes);
  const end = offset + length;
  requireValue(size <= 8388608n && length <= 131072n && end <= size
    && (size === 0n ? offset === 0n && length === 0n : offset < size && length > 0n));
  requireValue(data.completeFile === (offset === 0n && end === size));
  requireValue(end < size ? data.nextOffsetBytes !== null && BigInt(data.nextOffsetBytes) === end : data.nextOffsetBytes === null);
  if (data.representation === 'hex') {
    requireValue(data.fallbackReason !== null && data.firstLine === null && data.startsMidLine === null && data.endsMidLine === null);
    requireValue(/^[0-9a-f]*$/u.test(data.text) && BigInt(data.text.length) === 2n * length);
  } else {
    const encoded = new TextEncoder().encode(data.text);
    requireValue(BigInt(encoded.length) === length
      && new TextDecoder('utf-8', { fatal: true, ignoreBOM: true }).decode(encoded) === data.text);
    requireValue(data.fallbackReason === null && data.firstLine !== null && data.startsMidLine !== null && data.endsMidLine !== null);
    if (data.firstLine !== null) requireValue(BigInt(data.firstLine) >= 1n && BigInt(data.firstLine) <= offset + 1n
      && (offset !== 0n || data.firstLine === '1') && (offset === 0n || data.firstLine !== '1' || data.startsMidLine === true));
    if (offset === 0n) requireValue(data.startsMidLine === false);
    requireValue(data.endsMidLine === (end < size && !data.text.endsWith('\n')));
  }
}

const codePoints = (value: string): number => Array.from(value).length;
const ARTIFACT_CODES = { 'exploration-report': 'exploration', 'progress-journal': 'progress', 'source-manifest': 'manifest',
  'build-contract': 'contract', 'source-archive': 'archive' } as const;

export function checkSourceSearch(data: SourceSearch): void {
  const { page, limits, scope, progress, query, items } = data;
  requireValue(page.snapshotVersion === data.metadataVersion && page.limit === limits.maxResults && items.length <= page.limit);
  const complete = data.status === 'complete';
  requireValue(complete === (data.stopReason === null) && complete === (page.nextCursor === null));
  requireValue((progress.remainingFiles === 0) === complete && progress.remainingFiles <= scope.searchableFiles);
  requireValue(scope.searchableFiles + scope.notViewable + scope.declaredBinary + scope.tooLarge === scope.filesInScope);
  // A page that stops inside a file counts that file as both scanned and remaining.
  requireValue(progress.unsearchableText <= progress.scannedFiles
    && progress.scannedFiles + progress.unavailableFiles + progress.remainingFiles <= scope.searchableFiles + (complete ? 0 : 1)
    && BigInt(progress.scannedBytes) <= BigInt(limits.maxScannedBytes));
  const gaps = data.coverageGaps;
  requireValue(gaps.unsearchableText >= progress.unsearchableText && gaps.unavailableFiles >= progress.unavailableFiles
    && gaps.unsearchableText + gaps.unavailableFiles <= scope.searchableFiles);
  if (query.match === 'symbol') requireValue(/^[A-Za-z_][A-Za-z0-9_]*$/u.test(query.text));
  const seen = new Set<string>(); let previous: SourceSearch['items'][number] | undefined;
  for (const item of items) {
    const line = BigInt(item.line), column = BigInt(item.column), offset = BigInt(item.offsetBytes), lineOffset = BigInt(item.lineOffsetBytes);
    requireValue(line >= 1n && column >= 1n && lineOffset <= offset && (line === 1n) === (lineOffset === 0n));
    requireValue(![item.before, item.match, item.after].some(text => text.includes('\n')));
    const before = codePoints(item.before), after = codePoints(item.after);
    requireValue(before <= 80 && after <= 80 && (!item.truncatedBefore || before === 80) && (!item.truncatedAfter || after === 80)
      && column - 1n >= BigInt(before) && (item.truncatedBefore || column - 1n === BigInt(before)));
    requireValue((!query.caseSensitive || item.match === query.text) && codePoints(item.match) === codePoints(query.text));
    if (query.match === 'symbol') requireValue(!/[A-Za-z0-9_]$/u.test(item.before) && !/^[A-Za-z0-9_]/u.test(item.after));
    if (previous?.fileId === item.fileId) {
      requireValue(previous.displayName === item.displayName
        && offset >= BigInt(previous.offsetBytes) + BigInt(new TextEncoder().encode(previous.match).length));
    } else {
      requireValue(!seen.has(item.fileId) && (previous === undefined || previous.displayName < item.displayName));
    }
    seen.add(item.fileId); previous = item;
  }
}

/** Mirrors the shared verifier's cross-field rules; fixtures exercise both implementations. */
export function checkSemantics(document: ContractDocument, basePath = '/'): void {
  function checkHref(href: string, resource: ApiResource) {
    try { validateResourceHref(basePath, href, resource); } catch { throw new ApiClientError('invalid_response'); }
  }
  // Catalog entries carry family and verification together; only revision-bound source metadata is verified.
  function checkCatalogArtifact(item: Artifact) {
    checkHref(item.contentHref, { kind: 'artifact-content', jobId: item.binding.jobId, artifactId: item.artifactId });
    requireValue((item.family === undefined) === (item.verification === undefined));
    if (item.family === undefined) return;
    requireValue(item.artifactId === `${ARTIFACT_CODES[item.family]}_${item.artifactId.split('_')[1] ?? ''}_${item.sha256}`
      && /^[a-z]+_[a-f0-9]{32}_[a-f0-9]{64}$/u.test(item.artifactId) && item.binding.runId !== null);
    if (item.verification === 'revision-commitment') {
      requireValue((item.family === 'source-manifest' || item.family === 'build-contract') && item.binding.revisionId !== null);
    }
  }
  switch (document.kind) {
    case 'validationHistory':
      checkValidationHistory(document.data);
      break;
    case 'error': {
      const { code, recovery, retryable, retryAfterMs } = document.error;
      requireValue((code === 'EVENT_GAP') === (recovery !== undefined));
      if (recovery) {
        requireValue(!retryable && retryAfterMs === null);
        requireValue(recovery.oldestCursor === null || recovery.latestCursor !== null);
        checkHref(recovery.snapshotHref, { kind: 'snapshot', jobId: recovery.jobId, runId: recovery.runId });
      }
      break;
    }
    case 'uploadProgress': {
      const progress = document.data;
      requireValue(BigInt(progress.receivedBytes) <= 33554433n);
      requireValue(progress.totalBytes === null || BigInt(progress.totalBytes) <= 33554432n);
      requireValue((progress.state === 'published') === (progress.jobId !== null));
      break;
    }
    case 'run':
      checkRun(document.data);
      break;
    case 'runs': {
      const { items, page, jobId } = document.data;
      requireValue(items.length <= page.limit && new Set(items.map(item => item.runId)).size === items.length);
      requireValue(items.every(item => item.jobId === jobId));
      items.forEach(checkRun);
      break;
    }
    case 'sourceCatalog': {
      const { items, totalFiles, page, manifestSha256 } = document.data;
      checkSourcePage(items, totalFiles, page, manifestSha256);
      break;
    }
    case 'revisionSources': {
      const { items, totalFiles, page, metadataVersion } = document.data;
      checkSourcePage(items, totalFiles, page, metadataVersion);
      break;
    }
    case 'revisionDirectory':
      checkDirectory(document.data);
      break;
    case 'sourceChunk':
      checkSourceChunk(document.data);
      break;
    case 'sourceSearch':
      checkSourceSearch(document.data);
      break;
    case 'revisionFile': {
      const { item, parentDirectoryId } = document.data;
      requireValue(item.displayName.split('/').every(part => part.length <= 255 && isDirectoryLabel(part)));
      requireValue((parentDirectoryId === 'root') === !item.displayName.includes('/'));
      const recorded = document.data.recordedModule;
      if (recorded) {
        requireValue(item.declaredUtf8Text && recorded.implementationSha256 === item.sha256);
        const used = recorded.promptCharacters; const maximum = recorded.promptBudgetCharacters;
        requireValue((used === null) === (maximum === null));
        if (used !== null && maximum !== null) requireValue(BigInt(maximum) > 0n && BigInt(used) <= BigInt(maximum));
      }
      break;
    }
    case 'recovery': {
      const inventory = document.data;
      const candidates = inventory.retainedUploadStages + inventory.retainedMetadataFiles;
      requireValue(candidates <= 128 && candidates <= inventory.scannedEntries);
      requireValue(BigInt(inventory.observedBytes) <= 67108864n);
      break;
    }
    case 'jobs': {
      const { items, page } = document.data;
      requireValue(items.length <= page.limit && new Set(items.map((item) => item.jobId)).size === items.length);
      const snapshotFields = [page.currentCursor, page.previousCursor, page.pageNumber];
      requireValue(snapshotFields.every(field => field === undefined) || snapshotFields.every(field => field !== undefined));
      if (page.pageNumber !== undefined) {
        requireValue(page.currentCursor !== null && page.currentCursor !== undefined);
        requireValue((page.pageNumber === 1) === (page.previousCursor === null));
        requireValue(page.nextCursor === null || page.nextCursor !== page.currentCursor);
        requireValue(page.previousCursor === null || page.previousCursor !== page.currentCursor);
        requireValue(page.previousCursor === null || page.previousCursor !== page.nextCursor);
        requireValue(page.pageNumber === 1 || items.length > 0);
      }
      break;
    }
    case 'bootstrap': {
      const retention = document.data.runtime.progressRetention;
      if (retention && (BigInt(retention.expired) > BigInt(retention.examined)
        || ((BigInt(retention.failures) === 0n) !== (retention.lastFailureCode === null)))) throw new ApiClientError('invalid_response');
      const scheduler = document.data.runtime.scheduler;
      if (scheduler?.state === 'available') {
        requireValue(BigInt(scheduler.activeWorkers) <= BigInt(scheduler.workerLimit));
        requireValue(BigInt(scheduler.queuedTasks) <= BigInt(scheduler.queueCapacity));
      }
      const { limits, capabilities, apiVersions } = document.data;
      requireValue(limits.defaultPageLimit <= limits.maxPageLimit);
      requireValue(new Set(capabilities.map((item) => item.id)).size === capabilities.length);
      if (!apiVersions.includes(1)) throw new ApiClientError('unsupported_contract');
      try {
        requireValue(document.data.basePath === `${normalizeBasePath(basePath)}/`);
      } catch { throw new ApiClientError('invalid_response'); }
      break;
    }
    case 'report': {
      const { sourceArtifact, binding, reportType, summary, acceptance, state, adapterVersion, producerSchemaVersion, validationCases } = document.data;
      if (sourceArtifact) requireValue(sourceArtifact.binding.jobId === binding.jobId
        && sourceArtifact.binding.runId === binding.runId && sourceArtifact.binding.revisionId === binding.revisionId);
      if (sourceArtifact) checkHref(sourceArtifact.contentHref, {
        kind: 'artifact-content', jobId: binding.jobId, artifactId: sourceArtifact.artifactId,
      });
      if (summary && reportType === 'exploration') requireValue('confidence' in summary);
      if (summary && reportType === 'revision-validation') requireValue('result' in summary);
      if (acceptance === 'accepted') requireValue(summary !== null && 'result' in summary && summary.result === 'passed');
      // Unknown producer bytes may have an explicit unsupported adapter result, never an available summary.
      const recognizedProducer = (reportType === 'exploration' && (producerSchemaVersion === null
        || (producerSchemaVersion === 1 && state === 'partial' && summary === null
          && document.data.authority === 'observations' && acceptance === 'not-evaluated'
          && document.data.acceptanceArtifactId === null)))
        || (reportType === 'revision-validation' && producerSchemaVersion === 2);
      if (adapterVersion !== 1 || ((state === 'available' || state === 'partial') && !recognizedProducer)) {
        throw new ApiClientError('unsupported_contract');
      }
      if (reportType === 'revision-validation' && state === 'partial') {
        requireValue(summary === null && validationCases == null && document.data.validationFailure == null);
      }
      if (validationCases) {
        if (!summary || !('result' in summary)) throw new ApiClientError('invalid_response');
        checkValidationCases(validationCases, summary);
      }
      if (document.data.validationFailure) checkValidationFailure(document.data.validationFailure);
      break;
    }
    case 'artifact':
      checkCatalogArtifact(document.data);
      break;
    case 'artifacts': {
      const { binding, items, page, catalogedFamilies } = document.data;
      requireValue((binding.revisionId === null || binding.runId !== null) && items.length <= page.limit
        && new Set(items.map(item => item.artifactId)).size === items.length);
      for (const item of items) {
        checkCatalogArtifact(item);
        requireValue(item.family !== undefined && catalogedFamilies.includes(item.family) && item.binding.jobId === binding.jobId
          && (binding.runId === null || item.binding.runId === binding.runId)
          && (binding.revisionId === null || item.binding.revisionId === binding.revisionId));
      }
      break;
    }
    case 'event':
      if (document.type === 'retention.gap') checkHref(document.payload.snapshotHref, {
        kind: 'snapshot', jobId: document.jobId, runId: document.runId,
      });
      break;
    case 'snapshot':
      checkRun(document.data.run);
      requireValue((document.data.throughCursor === null) === (document.data.throughSequence === null));
      if (document.data.progress) {
        const { nextSequence, queueDropped, historyDropped, retainedEventCount } = document.data.progress;
        const next = BigInt(nextSequence), count = BigInt(retainedEventCount);
        requireValue(count <= 1024n && count + BigInt(queueDropped) + BigInt(historyDropped) <= next);
        requireValue((count === 0n) === (document.data.oldestCursor === null));
        requireValue((next === 0n) === (document.data.throughSequence === null));
        if (document.data.throughSequence !== null) requireValue(BigInt(document.data.throughSequence) + 1n === next);
      }
      break;
    case 'events': {
      const { items, nextCursor } = document.data;
      const seen = new Set<string>();
      let previous = -1n;
      let binding: string | undefined;
      for (const event of items) {
        if (event.type === 'retention.gap' || event.cursor === null || event.sequence === null) throw new ApiClientError('invalid_response');
        const current = `${event.jobId}/${event.runId}`;
        requireValue(binding === undefined || binding === current);
        binding = current;
        const sequence = BigInt(event.sequence);
        requireValue(!seen.has(event.cursor) && sequence > previous);
        seen.add(event.cursor); previous = sequence;
      }
      if (items.length) requireValue(nextCursor === items.at(-1)?.cursor);
      break;
    }
    case 'gitWorkspace': {
      const { objectFormat, headObjectId, refs, mapping, repositoryId } = document.data;
      const length = objectFormat === 'sha1' ? 40 : objectFormat === 'sha256' ? 64 : undefined;
      const ids = [headObjectId, ...refs.map((ref) => ref.objectId)];
      if (mapping) {
        ids.push(mapping.objectId);
        requireValue(mapping.repositoryId === repositoryId && mapping.objectId === headObjectId);
        if (mapping.acceptance === 'accepted') requireValue(mapping.acceptanceArtifactId !== null);
      }
      if (length !== undefined) requireValue(ids.every((id) => id === null || id.length === length));
      break;
    }
  }
}
