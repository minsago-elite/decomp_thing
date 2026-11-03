import { storageSummaryCopy as copy } from '../copy/runtime';
import { textMessage } from '../shared/messages';
import { Fragment } from 'preact';
import { useRef, useState } from 'preact/hooks';
import { withApiFailureReference } from '../api/client';
import { registerContractExtension } from '../api/decode';
import { lazyContractSchema } from '../api/generated-schema-lazy';
import type { MaintenancePreview, StorageSummary as Summary } from '../api/generated';
import { usePrivateTransport } from '../session/PrivateTransport';
import { formatExactBytes } from './metadataFormat';

registerContractExtension(lazyContractSchema);

const CATEGORIES = ['originalInputs', 'reports', 'sourceSnapshots', 'logs', 'archives', 'metadata', 'temporary', 'other'] as const;

/** Explicit read-only reads: storage accounting and a maintenance dry run. Neither writes or starts work. */
export function StorageSummary({ basePath }: { basePath: string }) {
  const { client } = usePrivateTransport(basePath);
  const [summary, setSummary] = useState<Summary | null>(null);
  const [preview, setPreview] = useState<MaintenancePreview | null>(null);
  const [busy, setBusy] = useState(false);
  const [notice, setNotice] = useState('');
  const active = useRef<AbortController | null>(null);
  async function read() {
    if (active.current) return;
    const controller = new AbortController(); active.current = controller;
    setBusy(true); setNotice(copy.reading);
    try {
      const [storage, maintenance] = await Promise.all([
        client.get('storageSummary', '/storage', { signal: controller.signal }),
        client.get('maintenancePreview', '/storage/maintenance-preview', { signal: controller.signal }),
      ]);
      setSummary(storage.data); setPreview(maintenance.data); setNotice('');
    } catch (failure: unknown) {
      if (!controller.signal.aborted) { setSummary(null); setPreview(null); setNotice(withApiFailureReference(copy.failed, failure)); }
    } finally {
      active.current = null; setBusy(false);
    }
  }
  return <section aria-labelledby="storage-summary-title">
    <h3 id="storage-summary-title">{copy.storage}</h3>
    <p>{copy.explanation}</p>
    <button type="button" disabled={busy} onClick={() => { void read(); }}>{copy.read}</button>
    <p role="status">{notice}</p>
    {summary && <>
      {!summary.complete && <p>{copy.partial}</p>}
      <dl class="job-facts">
        <dt>{copy.total}</dt><dd>{formatExactBytes(summary.totalBytes)}</dd>
        <dt>{copy.jobs}</dt><dd>{summary.jobCount}</dd>
        {CATEGORIES.map(name => <Fragment key={name}><dt>{copy[name]}</dt><dd>{formatExactBytes(summary.categories[name].bytes)}</dd></Fragment>)}
        <dt>{copy.pendingDeletions}</dt><dd>{summary.pendingDeletions}</dd>
      </dl>
    </>}
    {preview && <>
      <h4>{copy.maintenance}</h4>
      <p>{copy.automaticDeletionDisabled}</p>
      <p>{textMessage(copy.affected, { jobs: preview.affectedJobs, bytes: formatExactBytes(preview.reclaimableBytes) })}</p>
      <p>{textMessage(copy.protectedJobs, { count: String(preview.protectedJobs.length + Number(preview.omittedProtectedJobs)) })}</p>
      {!preview.complete && <p>{copy.partial}</p>}
    </>}
  </section>;
}
