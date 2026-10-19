import { useEffect, useMemo, useState } from 'preact/hooks';
import type { Artifact } from '../api/generated';
import { withApiFailureReference } from '../api/errors';
import { usePrivateTransport } from '../session/PrivateTransport';
import { explorationCasesCopy as copy } from '../copy/attempt';
import { message } from '../shared/messages';
import { bytePreview, CASE_PAGE_SIZE, parseRetainedCases, textPreview } from './explorationCases';
import type { RetainedCase, RetainedCases } from './explorationCases';
import { parseFailureCases } from './explorationFailureCases';
import type { FailureRetainedCase, FailureRetainedCases } from './explorationFailureCases';

function failureCase(value: RetainedCase): FailureRetainedCase | null {
  return 'sample' in value ? value as FailureRetainedCase : null;
}
function caseKey(value: RetainedCase): string {
  const partial = failureCase(value);
  return partial ? JSON.stringify([partial.sample, partial.index]) : value.id;
}
function caseName(value: RetainedCase): string {
  const partial = failureCase(value);
  return partial ? message(copy.sampleCase, { sample: partial.sample, index: partial.index, id: textPreview(value.id).text }) : textPreview(value.id).text;
}

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
function CaseDetail({ value, artifact, jobId, runId, partial }: { value: RetainedCase; artifact: Artifact; jobId: string; runId: string; partial: FailureRetainedCases | null }) {
  const position = failureCase(value);
  return <section aria-labelledby="retained-case-title" class="retained-case-detail">
    <h4 id="retained-case-title">{copy.caseDetails}</h4>
    <dl class="job-facts"><dt>{copy.caseIdentity}</dt><dd><Preview value={value.id} /></dd>
      <dt>{copy.reportedSource}</dt><dd><Preview value={value.source} /></dd>
      <dt>{copy.job}</dt><dd><code>{jobId}</code></dd><dt>{copy.attempt}</dt><dd><code>{runId}</code></dd>
      <dt>{copy.artifactDigest}</dt><dd><code>{artifact.sha256}</code></dd>
      {position && <><dt>{copy.samplePosition}</dt><dd>{message(copy.position, { sample: position.sample, index: position.index })}</dd></>}
    </dl>
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
    </> : position?.outcome === 'failed' && partial ? <p role="status">{copy.failureReasons[partial.failure.code]} <code>{partial.failure.code}</code></p>
      : <p role="status">{position ? copy.unobserved : copy.observationMissing}</p>}
    <a href={artifact.contentHref} download="exploration.json">{copy.retainedRecord}</a>
    <p>{copy.reference}</p>
  </section>;
}

/** Explicit read only; navigation and filters never submit a workflow or persist report bytes. */
type CasesProps = { artifact: Artifact; jobId: string; runId: string; basePath: string; producerSchemaVersion?: 1 | null };

export function ExplorationCases(props: CasesProps) {
  const scope = JSON.stringify([props.jobId, props.runId, props.basePath, props.artifact, props.producerSchemaVersion ?? null]);
  // Equivalent decoded descriptor objects retain one read; changed authority discards all private data.
  const artifact = useMemo(() => ({ ...props.artifact, binding: { ...props.artifact.binding } }), [scope]);
  return <CaseReader key={scope} {...props} artifact={artifact} />;
}

function CaseReader({ artifact, jobId, runId, basePath, producerSchemaVersion = null }: CasesProps) {
  const { client } = usePrivateTransport(basePath);
  const [intent, setIntent] = useState<{ client: typeof client } | null>(null);
  const [data, setData] = useState<RetainedCases | FailureRetainedCases | null>(null);
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
      if (!controller.signal.aborted) setData(producerSchemaVersion === 1 ? parseFailureCases(text) : parseRetainedCases(text));
    }).catch((failure: unknown) => {
      if (!controller.signal.aborted) setError(withApiFailureReference(copy.unavailable, failure));
    }).finally(() => { if (!controller.signal.aborted) setLoading(false); });
    return () => { controller.abort(); };
  }, [artifact, jobId, runId, client, intent, producerSchemaVersion]);
  const filtered = useMemo(() => data?.cases.filter(value => !source || value.source === source) ?? [], [data, source]);
  const visible = filtered.slice(page * CASE_PAGE_SIZE, (page + 1) * CASE_PAGE_SIZE);
  const detail = filtered.find(value => caseKey(value) === selected);
  const partial = data && 'failure' in data ? data : null;
  return <section aria-labelledby="retained-cases-title" class="retained-cases">
    <h3 id="retained-cases-title">{copy.title}</h3>
    <p>{copy.scope}</p>
    <p>{producerSchemaVersion === 1 ? copy.partialFormat : copy.outcomesUnreported}</p>
    <button type="button" disabled={active && loading} onClick={() => setIntent({ client })}>{active ? copy.refresh : copy.read}</button>
    {active && loading && <p role="status">{copy.loading}</p>}
    {active && error && <p role="alert">{error}</p>}
    {active && data && <>
      {partial && <>
        <p role="status">{copy.failureReasons[partial.failure.code]} <code>{partial.failure.code}</code></p>
        <p>{message(copy.failurePosition, { sample: partial.failure.phase, index: partial.failure.candidateIndex })}</p>
        <table><caption>{copy.progress}</caption><thead><tr><th scope="col">{copy.sample}</th><th scope="col">{copy.planned}</th><th scope="col">{copy.completed}</th></tr></thead>
          <tbody>{(['baseline', 'expanded'] as const).map(sample => <tr key={sample}><th scope="row">{sample}</th>
            <td>{partial.samples[sample].planned}</td><td>{partial.samples[sample].completed}</td></tr>)}</tbody></table>
      </>}
      {partial?.detailsOmitted ? <>
        <p role="status">{copy.detailsOmitted}</p>
        <a href={artifact.contentHref} download="exploration.json">{copy.downloadPartial}</a>
      </> : <>
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
            <tbody>{visible.map(value => <tr key={caseKey(value)}>
              <th scope="row">{failureCase(value) ? caseName(value) : <Preview value={value.id} />}</th><td><Preview value={value.source} /></td>
              <td>{value.observation ? message(copy.exitCode, { value: value.observation.exitCode })
                : failureCase(value)?.outcome === 'failed' && partial ? copy.failureReasons[partial.failure.code] : partial ? copy.unobserved : copy.notRecorded}</td>
              <td><button type="button" aria-pressed={selected === caseKey(value)} onClick={() => setSelected(caseKey(value))}>{message(copy.inspectCase, { id: caseName(value) })}</button></td>
            </tr>)}</tbody></table>
        </div>
        <nav aria-label={copy.pagination}>
          <button type="button" disabled={page === 0} onClick={() => { setPage(value => value - 1); setSelected(null); }}>{copy.previous}</button>
          <button type="button" disabled={(page + 1) * CASE_PAGE_SIZE >= filtered.length} onClick={() => { setPage(value => value + 1); setSelected(null); }}>{copy.next}</button>
        </nav>
      </>}
      {detail && <CaseDetail value={detail} artifact={artifact} jobId={jobId} runId={runId} partial={partial} />}
      </>}
    </>}
  </section>;
}
