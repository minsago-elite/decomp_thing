import { recoverySummaryCopy as copy } from '../copy/workspace';
import { message as displayMessage } from '../shared/messages';
import { useEffect, useState } from 'preact/hooks';
import { ApiClientError, withApiFailureReference } from '../api/client';
import type { createApiClient } from '../api/client';
import { canRetainMetadata, metadataFailureKind } from '../shared/retainMetadata';
import type { Recovery } from '../api/generated';

import { receive } from '../shared/receiptTime';
import type { Received } from '../shared/receiptTime';
import { MetadataReceipt } from '../shared/MetadataReceipt';

type RecoveryClient = ReturnType<typeof createApiClient>;

type Failure = keyof typeof copy.failures;

/** Fixed panel-local categories: storage refusals stay unverified, local binding refusals are invalid responses, never outages. */
function failureKind(failure: unknown): Failure {
  if (!(failure instanceof ApiClientError)) return 'unverified';
  const kind = metadataFailureKind(failure);
  if (kind !== 'unverified' && kind !== 'failed') return kind;
  if (kind === 'unverified') return failure.code === 'response_too_large' && failure.serverCode === undefined ? 'sizeLimit' : kind;
  if (failure.status === 413) return 'sizeLimit';
  return canRetainMetadata(failure) ? 'transient' : 'failed';
}

/** Independent display-only snapshot: one bounded read on entry and each explicit refresh. */
export function RecoverySummary({ client, refresh }: {
  client: RecoveryClient;
  refresh: number;
}) {
  const [state, setState] = useState<{ client: RecoveryClient | null; refresh: number; data: Received<Recovery> | null; error: string; busy: boolean }>({
    client: null, refresh: -1, data: null, error: '', busy: false,
  });
  useEffect(() => {
    const controller = new AbortController();
    setState({ client, refresh, data: null, error: '', busy: false });
    void client.get('recovery', '/recovery', { signal: controller.signal }).then(response => {
      if (!controller.signal.aborted) setState({ client, refresh, data: receive(response.data), error: '', busy: false });
    }).catch((failure: unknown) => {
      if (controller.signal.aborted) return;
      const busy = failure instanceof ApiClientError && failure.serverCode === 'RECOVERY_INSPECTION_BUSY';
      setState({ client, refresh, data: null, busy, error: busy ? '' : withApiFailureReference(copy.failures[failureKind(failure)], failure) });
    });
    return () => { controller.abort(); };
  }, [client, refresh]);
  // Never paint a previous client/refresh snapshot while its effect is being replaced.
  const current = state.client === client && state.refresh === refresh;
  const observation = current ? state.data : null;
  const data = observation?.value;
  const error = current ? state.error : '';
  const busy = current && state.busy;
  if (data?.inventoryComplete && data.retainedUploadStages === 0 && data.retainedMetadataFiles === 0) return null;
  return <section aria-labelledby="recovery-summary-title" class="notice">
    <h3 id="recovery-summary-title">{busy ? copy.recoveryInspectionPaused : copy.retainedRecoveryFiles}</h3>
    {busy ? <p role="status">{copy.anUploadIsInProgressRefreshJobsAfterUploadsFinish}</p>
      : error ? <p role="status">{error}</p> : !data ? <p role="status">{copy.inspectingRecoveryFiles}</p> : <>
      <MetadataReceipt kind="recovery" receipt={observation?.receipt} />
      <p>{displayMessage(copy.inventory, { qualifier: data.inventoryComplete ? copy.observed : copy.atLeast, stages: data.retainedUploadStages, metadata: data.retainedMetadataFiles, bytes: data.observedBytes })}</p>
      {!data.inventoryComplete && <p>{copy.inspectionIsIncompleteAdditionalFilesOrBytesMayRemain}</p>}
      <p>{copy.preserveTheseFilesUntilRecoveryHasBeenVerifiedCountsAre}</p>
      <p>{copy.refreshJobsToInspectRecoveryFilesAgain}</p>
    </>}
  </section>;
}
