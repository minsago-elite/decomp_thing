import type { ContractDocument, Page, RevisionDirectory, Run, SourceChunk } from './generated';
import { ApiClientError } from './errors';
import { normalizeBasePath, validateResourceHref } from '../app/paths';
import type { ApiResource } from '../app/paths';

const requireValue = (condition: boolean): void => {
  if (!condition) throw new ApiClientError('invalid_response');
};

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

function checkSourceChunk(data: SourceChunk): void {
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

/** Mirrors the shared verifier's cross-field rules; fixtures exercise both implementations. */
export function checkSemantics(document: ContractDocument, basePath = '/'): void {
  function checkHref(href: string, resource: ApiResource) {
    try { validateResourceHref(basePath, href, resource); } catch { throw new ApiClientError('invalid_response'); }
  }
  switch (document.kind) {
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
      const { sourceArtifact, binding, reportType, summary, acceptance, state, adapterVersion, producerSchemaVersion } = document.data;
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
      break;
    }
    case 'artifact':
      checkHref(document.data.contentHref, {
        kind: 'artifact-content', jobId: document.data.binding.jobId, artifactId: document.data.artifactId,
      });
      break;
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
