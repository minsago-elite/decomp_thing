import { useEffect, useRef, useState } from 'preact/hooks';
import type { RevisionFile } from '../api/generated';
import type { SourceDigestObservation } from '../api/sourceDigest';
import { sourceCopy as copy } from '../copy/sources';
import { usePrivateTransport } from '../session/PrivateTransport';
import { beginSourceRead, currentSourceRead, sourceReadMessage } from './navigation';
import type { SourceReadState } from './navigation';

/** Keyed by the parent to one metadata observation. Reads require an explicit click. */
export function SourceDigestCheck({ metadata, basePath }: { metadata: RevisionFile; basePath: string }) {
  const { client } = usePrivateTransport(basePath);
  const key = [metadata.binding.jobId, metadata.binding.runId, metadata.binding.revisionId, metadata.item.fileId,
    metadata.sourceSha256, metadata.metadataVersion, metadata.item.sha256, metadata.item.sizeBytes].join('/');
  const [read, setRead] = useState<SourceReadState<SourceDigestObservation> | null>(null);
  const stop = useRef<(() => void) | null>(null);
  useEffect(() => () => { stop.current?.(); stop.current = null; }, []);
  const current = read ? currentSourceRead(read, key) : null;
  const loading = current?.state === 'loading';
  return <section aria-label={copy.digestCheckTitle}>
    <h3>{copy.digestCheckTitle}</h3>
    <p>{copy.digestCheckBoundary}</p>
    <button type="button" disabled={loading} onClick={() => {
      stop.current?.();
      stop.current = beginSourceRead(key, signal => client.checkSourceFileDigest(metadata, { signal }), setRead);
    }}>{copy.checkDigest}</button>
    <p role="status">{loading ? copy.digestChecking : current?.state === 'ready' ? copy.digestMatched : copy.digestNotChecked}</p>
    {current?.state === 'failed' && <p role="alert">{sourceReadMessage(current.failure)}</p>}
  </section>;
}
