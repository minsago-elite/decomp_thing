import { supportExportCopy as copy } from '../copy/supportExport';
import { message as displayMessage, textMessage } from '../shared/messages';
import { formatExactBytes, formatExactTimestamp } from './metadataFormat';
import { useEffect, useRef, useState } from 'preact/hooks';
import { withApiFailureReference } from '../api/client';
import type { createApiClient } from '../api/client';
import type { SupportExport as SupportExportData } from '../api/generated';
import { registerContractExtension } from '../api/decode';
import { lazyContractSchema } from '../api/generated-schema-lazy';

// The Runtime route is lazily loaded; its export contract stays out of the initial bundle.
registerContractExtension(lazyContractSchema);

type ExportClient = ReturnType<typeof createApiClient>;
type Omission = SupportExportData['omittedSections'][number];

export const MAX_SUPPORT_EXPORT_BYTES = 1024 * 1024;

const reasonCopy: Record<Omission['reason'], string> = {
  'not-in-scope': copy.reasonNotInScope,
  unavailable: copy.reasonUnavailable,
  'job-content': copy.reasonJobContent,
  'private-configuration': copy.reasonPrivateConfiguration,
  secret: copy.reasonSecret,
  'not-recorded': copy.reasonNotRecorded,
};

/** The download is the previewed document byte for byte; no second request can change it. */
export function supportExportDownload(data: SupportExportData): { href: string; filename: string; bytes: number } | null {
  const text = JSON.stringify({ apiVersion: 1, kind: 'supportExport', data }, null, 2) + '\n';
  const bytes = new TextEncoder().encode(text).byteLength;
  if (bytes > MAX_SUPPORT_EXPORT_BYTES) return null;
  const scope = data.scope.kind === 'job' && data.scope.jobId ? `job-${data.scope.jobId}` : 'server';
  return { href: `data:application/json;charset=utf-8,${encodeURIComponent(text)}`, filename: `support-export-${scope}.json`, bytes };
}

/** Explicit, scoped and previewed: one bounded read per Preview activation, never on render. */
export function SupportExport({ client }: { client: ExportClient }) {
  const [scope, setScope] = useState<'server' | 'job'>('server');
  const [jobId, setJobId] = useState('');
  const [state, setState] = useState<{ status: 'idle' | 'loading' | 'ready' | 'error'; data: SupportExportData | null; error: string }>({
    status: 'idle', data: null, error: '',
  });
  const [invalid, setInvalid] = useState(false);
  const controller = useRef<AbortController | null>(null);
  const previewHeading = useRef<HTMLHeadingElement>(null);
  useEffect(() => () => { controller.current?.abort(); }, [client]);
  useEffect(() => { if (state.status === 'ready') previewHeading.current?.focus(); }, [state.status, state.data]);

  async function preview(event: Event) {
    event.preventDefault();
    const trimmed = jobId.trim();
    if (scope === 'job' && !/^[a-f0-9]{32}$/.test(trimmed)) { setInvalid(true); return; }
    setInvalid(false);
    controller.current?.abort();
    const current = new AbortController();
    controller.current = current;
    setState({ status: 'loading', data: null, error: '' });
    const query = scope === 'job' ? `scope=job&jobId=${trimmed}` : 'scope=server';
    try {
      const response = await client.get('supportExport', `/support-export?${query}`, { signal: current.signal });
      if (!current.signal.aborted) setState({ status: 'ready', data: response.data, error: '' });
    } catch (failure) {
      if (!current.signal.aborted) setState({ status: 'error', data: null, error: withApiFailureReference(copy.previewFailed, failure) });
    }
  }

  const data = state.status === 'ready' ? state.data : null;
  const download = data ? supportExportDownload(data) : null;
  return <section aria-labelledby="support-export-title" class="upload-panel">
    <h2 id="support-export-title">{copy.supportExport}</h2>
    <p>{copy.intro}</p>
    <form onSubmit={event => { void preview(event); }} noValidate>
      <fieldset>
        <legend>{copy.scope}</legend>
        <label><input type="radio" name="support-export-scope" value="server" checked={scope === 'server'}
          onChange={() => { setScope('server'); setInvalid(false); }} /> {copy.serverScope}</label>
        <label><input type="radio" name="support-export-scope" value="job" checked={scope === 'job'}
          onChange={() => { setScope('job'); }} /> {copy.jobScope}</label>
      </fieldset>
      {scope === 'job' && <p>
        <label for="support-export-job">{copy.jobId}</label>
        <input id="support-export-job" value={jobId} maxLength={32} spellcheck={false} autoComplete="off"
          aria-invalid={invalid ? 'true' : undefined} aria-describedby={invalid ? 'support-export-job-error' : undefined}
          onInput={event => { setJobId(event.currentTarget.value); }} />
        {invalid && <span id="support-export-job-error" role="alert">{copy.invalidJobId}</span>}
      </p>}
      <p class="job-actions"><button type="submit" disabled={state.status === 'loading'}>{copy.preview}</button></p>
    </form>
    <p role="status">{state.status === 'loading' ? copy.previewing : state.status === 'ready' ? copy.previewReady : state.error}</p>
    {data && <div>
      <h3 id="support-export-preview" ref={previewHeading} tabIndex={-1}>{copy.document}</h3>
      <dl class="job-facts">
        <dt>{copy.generatedAt}</dt><dd><time dateTime={data.generatedAt}>{formatExactTimestamp(data.generatedAt)}</time></dd>
        <dt>{copy.redactionVersion}</dt><dd><code>{data.redactionVersion}</code></dd>
        <dt>{copy.includedSections}</dt>
        <dd>{data.sections.length === 0 ? copy.noSections : data.sections.map(section => section.id).join(', ')}</dd>
      </dl>
      <h4>{copy.omittedSections}</h4>
      <ul>{data.omittedSections.map(omission => <li key={omission.id}>
        {displayMessage(copy.omission, { section: <code>{omission.id}</code>, reason: reasonCopy[omission.reason] })}
      </li>)}</ul>
      <pre class="source-rows" tabIndex={0} aria-labelledby="support-export-preview">{JSON.stringify(data, null, 2)}</pre>
      {download ? <p><a class="button-link" href={download.href} download={download.filename}>
        {textMessage(copy.download, { bytes: formatExactBytes(String(download.bytes)) })}</a></p>
        : <p role="alert">{copy.tooLarge}</p>}
    </div>}
  </section>;
}
