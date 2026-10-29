import { useEffect, useMemo, useState } from 'preact/hooks';
import { sourceDirectoryPath } from '../app/paths';
import { ApiClientError, withApiFailureReference } from '../api/errors';
import { recordedValidationCopy as copy } from '../copy/attempt';
import { commonCopy } from '../copy/common';
import { message } from '../shared/messages';
import { usePrivateTransport } from '../session/PrivateTransport';
import { bindDirectory, directoryReadRoute } from '../sources/navigation';

import { receive } from '../shared/receiptTime';
import type { Received } from '../shared/receiptTime';
import { MetadataReceipt } from '../shared/MetadataReceipt';

/** Resolve the durable workflow candidate by its exact source commitment, without equating revision namespaces. */
export function ValidationSourceSnapshot({ jobId, runId, validationRevisionId, sourceSha256, basePath }: {
  jobId: string; runId: string; validationRevisionId: string; sourceSha256: string; basePath: string;
}) {
  const { client } = usePrivateTransport(basePath);
  const binding = useMemo(() => ({ client, jobId, runId, validationRevisionId, sourceSha256, active: null as AbortController | null }),
    [client, jobId, runId, validationRevisionId, sourceSha256]);
  const [stored, setStored] = useState<{ binding: typeof binding; data: Received<{ href: string; revisionId: string }> | null;
    loading: boolean; error: string } | null>(null);
  const view = stored?.binding === binding ? stored : null;
  useEffect(() => () => { binding.active?.abort(); }, [binding]);
  async function resolve() {
    binding.active?.abort(); const controller = new AbortController(); binding.active = controller;
    setStored({ binding, data: null, loading: true, error: '' });
    try {
      const { data: run } = await client.get('run', `/jobs/${jobId}/runs/${runId}`, { signal: controller.signal });
      if (controller.signal.aborted) return;
      if (run.jobId !== jobId || run.runId !== runId || run.resultRevisionId === null ||
        !['completed', 'failed', 'cancelled', 'interrupted'].includes(run.state)) throw new ApiClientError('invalid_response');
      const selected = { jobId, runId, revisionId: run.resultRevisionId, directoryId: 'root' };
      const { data } = await client.get('revisionDirectory', directoryReadRoute(selected), { signal: controller.signal });
      if (controller.signal.aborted) return;
      const directory = bindDirectory(data, selected);
      if (directory.authority !== 'source-input-commitments' || directory.sourceSha256 !== sourceSha256) throw new ApiClientError('invalid_response');
      const href = sourceDirectoryPath(basePath, selected, 'root', undefined,
        { sourceSha256, metadataVersion: directory.metadataVersion });
      setStored(current => current?.binding === binding ? { binding, data: receive({ href, revisionId: selected.revisionId }), loading: false, error: '' } : current);
    } catch (failure: unknown) {
      if (!controller.signal.aborted) setStored(current => current?.binding === binding ? { binding, data: null, loading: false,
        error: withApiFailureReference(copy.sourceUnavailable, failure) } : current);
    }
  }
  return <section aria-label={copy.sourceTitle}>
    <h3>{copy.sourceTitle}</h3><p>{copy.sourceBoundary}</p>
    <button type="button" disabled={view?.loading ?? false} onClick={() => { void resolve(); }}>{copy.findSource}</button>
    {view?.loading && <p role="status">{copy.readingSource}</p>}
    {view?.error && <p role="alert">{view.error}</p>}
    {view?.data && <><MetadataReceipt kind="sourceResolution" receipt={view.data.receipt} /><p>{message(commonCopy.labeledValue, { label: copy.retainedRevision, value: <code>{view.data.value.revisionId}</code> })}</p><a href={view.data.value.href}>{copy.openSource}</a></>}
  </section>;
}
