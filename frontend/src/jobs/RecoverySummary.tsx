import { recoverySummaryCopy as copy } from '../copy/workspace';
import { message as displayMessage } from '../shared/messages';
import { useEffect, useState } from 'preact/hooks';
import { ApiClientError, withApiFailureReference } from '../api/client';
import type { createApiClient } from '../api/client';
import type { Recovery } from '../api/generated';

type RecoveryClient = ReturnType<typeof createApiClient>;

/** Independent display-only snapshot: one bounded read on entry and each explicit refresh. */
export function RecoverySummary({ client, refresh }: {
  client: RecoveryClient;
  refresh: number;
}) {
  const [state, setState] = useState<{ client: RecoveryClient | null; refresh: number; data: Recovery | null; error: string; busy: boolean }>({
    client: null, refresh: -1, data: null, error: '', busy: false,
  });
  useEffect(() => {
    const controller = new AbortController();
    setState({ client, refresh, data: null, error: '', busy: false });
    void client.get('recovery', '/recovery', { signal: controller.signal }).then(response => {
      if (!controller.signal.aborted) setState({ client, refresh, data: response.data, error: '', busy: false });
    }).catch((failure: unknown) => {
      if (controller.signal.aborted) return;
      const busy = failure instanceof ApiClientError && failure.serverCode === 'RECOVERY_INSPECTION_BUSY';
      setState({ client, refresh, data: null, busy, error: busy ? '' : withApiFailureReference(
        copy.recoveryFilesCouldNotBeInspectedRecoveryStateIsUnknown, failure) });
    });
    return () => { controller.abort(); };
  }, [client, refresh]);
  // Never paint a previous client/refresh snapshot while its effect is being replaced.
  const current = state.client === client && state.refresh === refresh;
  const data = current ? state.data : null;
  const error = current ? state.error : '';
  const busy = current && state.busy;
  if (data?.inventoryComplete && data.retainedUploadStages === 0 && data.retainedMetadataFiles === 0) return null;
  return <section aria-labelledby="recovery-summary-title" class="notice">
    <h3 id="recovery-summary-title">{busy ? copy.recoveryInspectionPaused : copy.retainedRecoveryFiles}</h3>
    {busy ? <p role="status">{copy.anUploadIsInProgressRefreshJobsAfterUploadsFinish}</p>
      : error ? <p role="status">{error}</p> : !data ? <p role="status">{copy.inspectingRecoveryFiles}</p> : <>
      <p>{displayMessage(copy.inventory, { qualifier: data.inventoryComplete ? copy.observed : copy.atLeast, stages: data.retainedUploadStages, metadata: data.retainedMetadataFiles, bytes: data.observedBytes })}</p>
      {!data.inventoryComplete && <p>{copy.inspectionIsIncompleteAdditionalFilesOrBytesMayRemain}</p>}
      <p>{copy.preserveTheseFilesUntilRecoveryHasBeenVerifiedCountsAre}</p>
      <p>{copy.refreshJobsToInspectRecoveryFilesAgain}</p>
    </>}
  </section>;
}
