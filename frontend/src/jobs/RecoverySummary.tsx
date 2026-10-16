import { useEffect, useState } from 'preact/hooks';
import { withApiFailureReference } from '../api/client';
import type { createApiClient } from '../api/client';
import type { Recovery } from '../api/generated';

type RecoveryClient = ReturnType<typeof createApiClient>;

/** Independent display-only snapshot: one bounded read on entry and each explicit refresh. */
export function RecoverySummary({ client, refresh }: {
  client: RecoveryClient;
  refresh: number;
}) {
  const [state, setState] = useState<{ client: RecoveryClient | null; refresh: number; data: Recovery | null; error: string }>({
    client: null, refresh: -1, data: null, error: '',
  });
  useEffect(() => {
    const controller = new AbortController();
    setState({ client, refresh, data: null, error: '' });
    void client.get('recovery', '/recovery', { signal: controller.signal }).then(response => {
      if (!controller.signal.aborted) setState({ client, refresh, data: response.data, error: '' });
    }).catch((failure: unknown) => {
      if (!controller.signal.aborted) setState({ client, refresh, data: null, error: withApiFailureReference(
        'Recovery files could not be inspected. Recovery state is unknown; preserve stored data before retrying.', failure) });
    });
    return () => { controller.abort(); };
  }, [client, refresh]);
  // Never paint a previous client/refresh snapshot while its effect is being replaced.
  const current = state.client === client && state.refresh === refresh;
  const data = current ? state.data : null;
  const error = current ? state.error : '';
  if (data?.inventoryComplete && data.retainedUploadStages === 0 && data.retainedMetadataFiles === 0) return null;
  return <section aria-labelledby="recovery-summary-title" class="notice">
    <h3 id="recovery-summary-title">Retained recovery files</h3>
    {error ? <p role="status">{error}</p> : !data ? <p role="status">Inspecting recovery files…</p> : <>
      <p>{data.inventoryComplete ? 'Observed' : 'At least'} {data.retainedUploadStages} upload stages and {data.retainedMetadataFiles} metadata temporary files; {data.observedBytes} observed bytes.</p>
      {!data.inventoryComplete && <p>Inspection is incomplete. Additional files or bytes may remain.</p>}
      <p>Preserve these files until recovery has been verified. Counts are a display-only snapshot and do not authorize cleanup or establish accepted source revisions.</p>
      <p>Refresh jobs to inspect recovery files again.</p>
    </>}
  </section>;
}
