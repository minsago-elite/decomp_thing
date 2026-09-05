import type { ContractDocument } from './generated';
import { ApiClientError } from './errors';
import { normalizeBasePath, validateResourceHref } from '../app/paths';
import type { ApiResource } from '../app/paths';

const requireValue = (condition: boolean): void => {
  if (!condition) throw new ApiClientError('invalid_response');
};

/** Mirrors the shared verifier's cross-field rules; fixtures exercise both implementations. */
export function checkSemantics(document: ContractDocument, basePath = '/'): void {
  function checkHref(href: string, resource: ApiResource) {
    try { validateResourceHref(basePath, href, resource); } catch { throw new ApiClientError('invalid_response'); }
  }
  switch (document.kind) {
    case 'uploadProgress': {
      const progress = document.data;
      requireValue(BigInt(progress.receivedBytes) <= 33554433n);
      requireValue(progress.totalBytes === null || BigInt(progress.totalBytes) <= 33554432n);
      requireValue((progress.state === 'published') === (progress.jobId !== null));
      break;
    }
    case 'runs': {
      const { items, page, jobId } = document.data;
      requireValue(items.length <= page.limit && new Set(items.map(item => item.runId)).size === items.length);
      requireValue(items.every(item => item.jobId === jobId));
      break;
    }
    case 'jobs': {
      const { items, page } = document.data;
      requireValue(items.length <= page.limit && new Set(items.map((item) => item.jobId)).size === items.length);
      break;
    }
    case 'bootstrap': {
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
      const recognizedProducer = (reportType === 'exploration' && producerSchemaVersion === null)
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
      requireValue((document.data.throughCursor === null) === (document.data.throughSequence === null));
      if (document.data.progress) {
        const { nextSequence, queueDropped, historyDropped, retainedEventCount } = document.data.progress;
        const next = BigInt(nextSequence), count = BigInt(retainedEventCount);
        requireValue(count <= 1024n && count + BigInt(queueDropped) + BigInt(historyDropped) <= next);
        requireValue((count === 0n) === (document.data.oldestCursor === null));
        requireValue((count === 0n) === (document.data.throughSequence === null));
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
