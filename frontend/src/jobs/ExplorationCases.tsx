import { useEffect, useMemo, useState } from 'preact/hooks';
import type { Artifact } from '../api/generated';
import { withApiFailureReference } from '../api/errors';
import { usePrivateTransport } from '../session/PrivateTransport';
import { explorationCasesCopy as copy } from '../copy/attempt';
import { message } from '../shared/messages';
import { bytePreview, CASE_PAGE_SIZE, parseRetainedCases, textPreview } from './explorationCases';
import type { RetainedCase, RetainedCases } from './explorationCases';

function Preview({ value }: { value: string }) {
  const preview = textPreview(value);
  return <><code>{preview.text}</code>{preview.truncated && <span> {copy.truncated}</span>}</>;
}
function Bytes({ label, value }: { label: string; value: string }) {
  const preview = bytePreview(value);
  return <section>
    <h5>{label}</h5>
    <p>{message(copy.bytes, { count: preview.bytes })}{preview.truncated && <> {copy.first128Bytes}</>}</p>
    <dl><dt>{copy.hex}</dt><dd><code>{preview.hex || copy.empty}</code></dd>
      <dt>{copy.escapedBytes}</dt><dd><code>{preview.text || copy.empty}</code></dd></dl>
  </section>;
}
function CaseDetail({ value, artifact, jobId, runId }: { value: RetainedCase; artifact: Artifact; jobId: string; runId: string }) {
  return <section aria-labelledby="retained-case-title" class="retained-case-detail">
    <h4 id="retained-case-title">{copy.caseDetails}</h4>
    <dl class="job-facts"><dt>{copy.caseIdentity}</dt><dd><Preview value={value.id} /></dd>
      <dt>{copy.reportedSource}</dt><dd><Preview value={value.source} /></dd>
      <dt>{copy.job}</dt><dd><code>{jobId}</code></dd><dt>{copy.attempt}</dt><dd><code>{runId}</code></dd>
      <dt>{copy.artifactDigest}</dt><dd><code>{artifact.sha256}</code></dd></dl>
    <h5>{copy.argumentVector}</h5>
    {value.args.length === 0 ? <p>{copy.noArguments}</p> : <>
      <ol start={0}>{value.args.slice(0, 32).map((arg, index) => <li key={index}><Preview value={arg} /></li>)}</ol>
      {value.args.length > 32 && <p>{message(copy.firstArguments, { total: value.args.length })}</p>}
    </>}
    <Bytes label={copy.stdin} value={value.stdinHex} />
    {value.observation ? <>
      <p>{message(copy.exitCode, { value: value.observation.exitCode })}</p>
      <p>{message(copy.isolation, { value: value.observation.networkIsolated ? copy.yes : copy.no })}</p>
      <Bytes label={copy.stdout} value={value.observation.stdoutHex} />
      <Bytes label={copy.stderr} value={value.observation.stderrHex} />
    </> : <p role="status">{copy.observationMissing}</p>}
    <a href={artifact.contentHref} download="exploration.json">{copy.retainedRecord}</a>
    <p>{copy.reference}</p>
  </section>;
}

/** Explicit read only; navigation and filters never submit a workflow or persist report bytes. */
type CasesProps = { artifact: Artifact; jobId: string; runId: string; basePath: string };

export function ExplorationCases(props: CasesProps) {
  const scope = JSON.stringify([props.jobId, props.runId, props.basePath, props.artifact]);
  // Equivalent decoded descriptor objects retain one read; changed authority discards all private data.
  const artifact = useMemo(() => ({ ...props.artifact, binding: { ...props.artifact.binding } }), [scope]);
  return <CaseReader key={scope} {...props} artifact={artifact} />;
}

function CaseReader({ artifact, jobId, runId, basePath }: CasesProps) {
  const { client } = usePrivateTransport(basePath);
  const [intent, setIntent] = useState<{ client: typeof client } | null>(null);
  const [data, setData] = useState<RetainedCases | null>(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState('');
  const [source, setSource] = useState('');
  const [page, setPage] = useState(0);
  const [selected, setSelected] = useState<string | null>(null);
  const active = intent?.client === client;
  useEffect(() => {
    if (!intent || intent.client !== client) { setData(null); setError(''); setLoading(false); return; }
    const controller = new AbortController();
    setLoading(true); setError(''); setData(null); setSelected(null); setPage(0); setSource('');
    void client.readArtifactText(artifact, { jobId, runId }, { signal: controller.signal }).then(text => {
      if (!controller.signal.aborted) setData(parseRetainedCases(text));
    }).catch((failure: unknown) => {
      if (!controller.signal.aborted) setError(withApiFailureReference(copy.unavailable, failure));
    }).finally(() => { if (!controller.signal.aborted) setLoading(false); });
    return () => { controller.abort(); };
  }, [artifact, jobId, runId, client, intent]);
  const filtered = useMemo(() => data?.cases.filter(value => !source || value.source === source) ?? [], [data, source]);
  const visible = filtered.slice(page * CASE_PAGE_SIZE, (page + 1) * CASE_PAGE_SIZE);
  const detail = filtered.find(value => value.id === selected);
  return <section aria-labelledby="retained-cases-title" class="retained-cases">
    <h3 id="retained-cases-title">{copy.title}</h3>
    <p>{copy.scope}</p>
    <p>{copy.outcomesUnreported}</p>
    <button type="button" disabled={active && loading} onClick={() => setIntent({ client })}>{active ? copy.refresh : copy.read}</button>
    {active && loading && <p role="status">{copy.loading}</p>}
    {active && error && <p role="alert">{error}</p>}
    {active && data && <>
      <p>{message(copy.observationCount, { count: data.observationCount, total: data.cases.length })}</p>
      <label>{copy.filter} <select value={source ? String(data.sources.indexOf(source)) : ''} onChange={event => {
        const value = event.currentTarget.value;
        setSource(value === '' ? '' : data.sources[Number(value)] ?? ''); setPage(0); setSelected(null);
      }}>
        <option value="">{copy.allSources}</option>
        {data.sources.map((value, index) => <option key={value} value={String(index)}>{textPreview(value).text}</option>)}
      </select></label>
      <p role="status">{message(copy.page, { count: visible.length, total: filtered.length, page: page + 1 })}</p>
      {filtered.length === 0 ? <p>{copy.emptyCases}</p> : <>
        <div class="retained-case-table" role="region" aria-label={copy.table} tabIndex={0}>
          <table><caption>{copy.table}</caption><thead><tr><th scope="col">{copy.caseIdentity}</th><th scope="col">{copy.reportedSource}</th><th scope="col">{copy.observation}</th><th scope="col">{copy.inspect}</th></tr></thead>
            <tbody>{visible.map(value => <tr key={value.id}>
              <th scope="row"><Preview value={value.id} /></th><td><Preview value={value.source} /></td>
              <td>{value.observation ? message(copy.exitCode, { value: value.observation.exitCode }) : copy.notRecorded}</td>
              <td><button type="button" aria-pressed={selected === value.id} onClick={() => setSelected(value.id)}>{message(copy.inspectCase, { id: textPreview(value.id).text })}</button></td>
            </tr>)}</tbody></table>
        </div>
        <nav aria-label={copy.pagination}>
          <button type="button" disabled={page === 0} onClick={() => { setPage(value => value - 1); setSelected(null); }}>{copy.previous}</button>
          <button type="button" disabled={(page + 1) * CASE_PAGE_SIZE >= filtered.length} onClick={() => { setPage(value => value + 1); setSelected(null); }}>{copy.next}</button>
        </nav>
      </>}
      {detail && <CaseDetail value={detail} artifact={artifact} jobId={jobId} runId={runId} />}
    </>}
  </section>;
}
