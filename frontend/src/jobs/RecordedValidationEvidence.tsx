import { useEffect, useMemo, useState } from 'preact/hooks';
import type { Report, ValidationBytePreview, ValidationHistory, ValidationOwner } from '../api/generated';
import { withApiFailureReference } from '../api/errors';
import { recordedValidationCopy as copy } from '../copy/attempt';
import { usePrivateTransport } from '../session/PrivateTransport';
import { ValidationSourceSnapshot } from './ValidationSourceSnapshot';
import { validationPageDownload } from './recordedValidationExport';
import { compareValidationSnapshots, validationComparisonSnapshot } from './recordedValidationComparison';
import type { ValidationComparisonSnapshot } from './recordedValidationComparison';

export function RecordedValidationEvidence({ jobId, runId, basePath }: { jobId: string; runId: string; basePath: string }) {
  const { client } = usePrivateTransport(basePath);
  const binding = useMemo(() => ({ client, jobId, runId, active: null as AbortController | null }), [client, jobId, runId]);
  type View = { binding: typeof binding; history: ValidationHistory | null; selected: ValidationOwner | null;
    report: Report | null; loading: boolean; error: string };
  const [stored, setStored] = useState<View | null>(null);
  type Baseline = { binding: typeof binding; snapshot: ValidationComparisonSnapshot; history: ValidationHistory; owner: ValidationOwner };
  const [savedBaseline, setSavedBaseline] = useState<Baseline | null>(null);
  const baseline = savedBaseline?.binding === binding ? savedBaseline : null;
  const view = stored?.binding === binding ? stored : null;
  useEffect(() => () => { binding.active?.abort(); }, [binding]);
  const root = `/jobs/${jobId}/runs/${runId}`;

  function begin(history: ValidationHistory | null = null, selected: ValidationOwner | null = null) {
    binding.active?.abort();
    const controller = new AbortController(); binding.active = controller;
    setStored({ binding, history, selected, report: null, loading: true, error: '' });
    return controller;
  }
  function failed(controller: AbortController, failure: unknown) {
    if (!controller.signal.aborted) {
      setSavedBaseline(null);
      setStored({ binding, history: null, selected: null, report: null, loading: false,
        error: withApiFailureReference(copy.failed, failure) });
    }
  }
  async function readHistory(page?: number, graph?: string) {
    if (page === undefined) setSavedBaseline(null);
    const controller = begin();
    try {
      const query = page === undefined ? '' : `?historyGraph=${graph}&historyPage=${page}`;
      const { data } = await client.get('validationHistory', `${root}/validation-history${query}`, { signal: controller.signal });
      if (controller.signal.aborted) return;
      if (data.binding.jobId !== jobId || data.binding.runId !== runId || data.binding.revisionId !== null ||
        data.authority !== 'recorded-metadata' || (page !== undefined && (data.page !== page || data.graphSha256 !== graph)))
        throw new Error('validation history binding');
      setStored({ binding, history: data, selected: null, report: null, loading: false, error: '' });
    } catch (failure: unknown) { failed(controller, failure); }
  }
  async function readCases(history: ValidationHistory, owner: ValidationOwner, page = 1, reportId?: string) {
    if (!owner.canInspect || history.graphSha256 === null || history.page === null) return;
    if (baseline && baseline.snapshot.graphSha256 !== history.graphSha256) setSavedBaseline(null);
    const controller = begin(history, owner);
    try {
      const failureOwner = owner.ownerKind === 'run-failure';
      const ownerKey = owner.ownerKind === 'attempt' ? 'historyEvidence' : failureOwner ? 'historyFailureRun' : 'historyRunEvidence';
      const query = `historyGraph=${history.graphSha256}&historyPage=${history.page}&${ownerKey}=${owner.ownerId}&historyValidationPage=${page}`;
      const { data } = await client.get('report', `${root}/reports/revision-validation?${query}`, { signal: controller.signal });
      if (controller.signal.aborted) return;
      const cases = data.validationCases;
      const failure = data.validationFailure;
      if (data.binding.jobId !== jobId || data.binding.runId !== runId || data.binding.revisionId !== owner.candidateId ||
        data.reportType !== 'revision-validation' || data.authority !== 'observations' || data.acceptance !== 'not-evaluated' ||
        data.acceptanceArtifactId !== null || data.sourceArtifact !== null || (reportId !== undefined && data.reportId !== reportId) ||
        (data.summary !== null && (!('sourceSha256' in data.summary) || data.summary.sourceSha256 !== owner.sourceSha256)) ||
        (data.state === 'available' && !(failureOwner ? failure : cases)) ||
        (failureOwner ? Boolean(cases) || data.summary !== null : Boolean(failure)) ||
        (failure && (failure.graphSha256 !== history.graphSha256 || failure.ownerId !== owner.ownerId ||
          failure.sourceSha256 !== owner.sourceSha256 || failure.corpusSha256 !== owner.corpusSha256 ||
          failure.classification !== owner.failureKind)) ||
        (cases && (cases.graphSha256 !== history.graphSha256 || cases.ownerKind !== owner.ownerKind || cases.ownerId !== owner.ownerId ||
          cases.sourceSha256 !== owner.sourceSha256 || cases.corpusSha256 !== owner.corpusSha256 ||
          cases.normalOutcome !== owner.normalOutcome || cases.page !== page))) throw new Error('validation receipt binding');
      setStored({ binding, history, selected: owner, report: data, loading: false, error: '' });
    } catch (failure: unknown) { failed(controller, failure); }
  }
  const history = view?.history, report = view?.report, cases = report?.validationCases, failure = report?.validationFailure, selected = view?.selected;
  const download = useMemo(() => report && history && selected
    ? validationPageDownload(report, { jobId, runId, graphSha256: history.graphSha256, owner: selected }) : null,
  [report, history, selected, jobId, runId]);
  const comparisonSnapshot = useMemo(() => report && history && selected
    ? validationComparisonSnapshot(report, { jobId, runId, graphSha256: history.graphSha256, owner: selected }) : null,
  [report, history, selected, jobId, runId]);
  const loading = view?.loading ?? false;
  const flag = (value: boolean | null) => value === null ? copy.notCompared : value ? copy.matches : copy.differs;
  return <section aria-labelledby="recorded-validation-title">
    <h2 id="recorded-validation-title">{copy.title}</h2>
    <p>{copy.scope}</p>
    <button type="button" disabled={loading} onClick={() => { void readHistory(); }}>{copy.read}</button>
    {loading && <p role="status">{copy.loading}</p>}
    {view?.error && <p role="alert">{view.error}</p>}
    {history && <>
      <p>{copy.historyState}: {history.state}</p>
      <ul aria-label={copy.limitations}>{history.limitations.map((text, index) => <li key={index}>{text}</li>)}</ul>
      {history.state === 'recorded' && <>
        <p>{copy.historyPage} {history.page} / {history.totalPages}</p>
        <div role="region" aria-label={copy.owners} tabIndex={0}>
          <table><caption>{copy.owners}</caption><thead><tr>
            <th scope="col">{copy.operation}</th><th scope="col">{copy.candidate}</th><th scope="col">{copy.source}</th><th scope="col">{copy.receipt}</th>
          </tr></thead><tbody>{history.items.map(owner => <tr key={`${owner.ownerKind}:${owner.ownerId}`}>
            <th scope="row">{owner.ownerKind}: <code>{owner.ownerId}</code></th>
            <td><code>{owner.candidateId ?? copy.withheld}</code></td><td><code>{owner.sourceSha256 ?? copy.withheld}</code></td>
            <td>{owner.normalOutcome ?? owner.failureKind ?? copy.notRecorded} <button type="button" disabled={loading || !owner.canInspect}
              aria-label={`${owner.ownerKind === 'run-failure' ? copy.inspectFailure : copy.inspect}: ${owner.ownerKind} ${owner.ownerId}`}
              onClick={() => { void readCases(history, owner); }}>{owner.ownerKind === 'run-failure' ? copy.inspectFailure : copy.inspect}</button></td>
          </tr>)}</tbody></table>
        </div>
        {history.items.length === 0 && <p>{copy.noOwners}</p>}
        <nav aria-label={copy.historyNavigation}>
          <button type="button" disabled={loading || history.previousPage === null} onClick={() => {
            if (history.previousPage !== null && history.graphSha256 !== null) void readHistory(history.previousPage, history.graphSha256);
          }}>{copy.previousHistory}</button>
          <button type="button" disabled={loading || history.nextPage === null} onClick={() => {
            if (history.nextPage !== null && history.graphSha256 !== null) void readHistory(history.nextPage, history.graphSha256);
          }}>{copy.nextHistory}</button>
        </nav>
      </>}
    </>}
    {report && <>
      <p>{copy.reportState}: {report.state}</p>
      <p>{copy.acceptance}</p>
      {report.state === 'available' && (cases || failure) && <>
        <p>{copy.exportScope}</p>
        {download ? <a href={download.href} download={download.filename}>{cases ? copy.exportPage : copy.exportFailure}</a>
          : <p>{copy.exportUnavailable}</p>}
      </>}
      <ul aria-label={copy.reportLimitations}>{report.limitations.map((text, index) => <li key={index}>{text}</li>)}</ul>
      {report.state === 'available' && report.binding.revisionId !== null && (cases || failure) &&
        <ValidationSourceSnapshot key={report.reportId} jobId={jobId} runId={runId} validationRevisionId={report.binding.revisionId}
          sourceSha256={cases?.sourceSha256 ?? failure!.sourceSha256} basePath={basePath} />}
      {report.summary && 'result' in report.summary && <dl>
        <dt>{copy.result}</dt><dd>{report.summary.result}</dd><dt>{copy.compared}</dt><dd>{report.summary.casesCompared}</dd>
      </dl>}
      {failure && <section aria-labelledby="validation-failure-title">
        <h3 id="validation-failure-title">{copy.failureTitle}</h3><p>{copy.failureScope}</p>
        <dl><dt>{copy.failureReason}</dt><dd>{failure.reason}</dd><dt>{copy.failurePhase}</dt><dd>{failure.phase}</dd>
          <dt>{copy.source}</dt><dd><code>{failure.sourceSha256}</code></dd><dt>{copy.corpus}</dt><dd><code>{failure.corpusSha256}</code></dd>
          <dt>{copy.inputs}</dt><dd>{failure.inputCount}</dd><dt>{copy.failurePosition}</dt><dd>{failure.inputOrdinal ?? copy.notRecorded}</dd>
          <dt>{copy.reportedPairs}</dt><dd>{failure.reportedCompletedPairs}</dd>
          <dt>{copy.reportedCleanup}</dt><dd>{failure.reportedCleanupVerified ? copy.producerReportsComplete : copy.unverifiedCleanup}</dd>
        </dl>
      </section>}
      {cases ? <>
        <section aria-labelledby="validation-comparison-title">
          <h3 id="validation-comparison-title">{copy.comparisonTitle}</h3><p>{copy.comparisonScope}</p>
          {comparisonSnapshot ? <button type="button" disabled={loading} onClick={() => {
            if (history && selected) setSavedBaseline({ binding, snapshot: comparisonSnapshot, history, owner: selected });
          }}>{copy.setComparisonBaseline}</button> : <p>{copy.comparisonUnavailable}</p>}
          {baseline && <>
            <dl><dt>{copy.comparisonBaseline}</dt><dd><code>{baseline.snapshot.ownerKind}: {baseline.snapshot.ownerId}</code></dd>
              <dt>{copy.candidate}</dt><dd><code>{baseline.snapshot.candidateId}</code></dd>
              <dt>{copy.source}</dt><dd><code>{baseline.snapshot.sourceSha256}</code></dd></dl>
            <button type="button" onClick={() => { setSavedBaseline(null); }}>{copy.clearComparisonBaseline}</button>
            {comparisonSnapshot && <MismatchComparison key={`${baseline.snapshot.reportId}:${comparisonSnapshot.reportId}`}
              first={baseline.snapshot} second={comparisonSnapshot} onInspectPage={page => {
                if (history && selected) void readCases(history, selected, page, report.reportId);
              }} onSwap={() => {
                if (history && selected) {
                  setSavedBaseline({ binding, snapshot: comparisonSnapshot, history, owner: selected });
                  void readCases(baseline.history, baseline.owner, 1, baseline.snapshot.reportId);
                }
              }} />}
          </>}
        </section>
        <dl><dt>{copy.source}</dt><dd><code>{cases.sourceSha256}</code></dd><dt>{copy.corpus}</dt><dd><code>{cases.corpusSha256}</code></dd>
          <dt>{copy.inputs}</dt><dd>{cases.totalInputs}</dd><dt>{copy.matched}</dt><dd>{cases.matchedInputs ?? copy.notCompared}</dd></dl>
        <p>{copy.casePage} {cases.page} / {cases.totalPages}</p>
        <div role="region" aria-label={copy.cases} tabIndex={0}>
          <table><caption>{copy.cases}</caption><thead><tr><th scope="col">{copy.case}</th><th scope="col">{copy.outcome}</th>
            <th scope="col">{copy.exit}</th><th scope="col">{copy.stdout}</th><th scope="col">{copy.stderr}</th><th scope="col">{copy.previews}</th>
          </tr></thead><tbody>{cases.items.map(item => <tr key={item.caseId}>
            <th scope="row">{item.ordinal}: <code>{item.caseId}</code></th><td>{item.outcome}</td><td>{flag(item.exitCodeMatches)}</td>
            <td>{flag(item.stdoutMatches)}</td><td>{flag(item.stderrMatches)}</td><td>
              <Preview title={copy.originalStdout} value={item.originalStdoutPreview} />
              <Preview title={copy.rebuiltStdout} value={item.rebuiltStdoutPreview} />
              <Preview title={copy.originalStderr} value={item.originalStderrPreview} />
              <Preview title={copy.rebuiltStderr} value={item.rebuiltStderrPreview} />
            </td>
          </tr>)}</tbody></table>
        </div>
        {cases.normalOutcome === 'behavior-checked' && cases.matchedInputs !== cases.totalInputs && <>
          <p>{copy.mismatchScope}</p>
          {cases.firstMismatchPage === undefined ? <p>{copy.mismatchUnavailable}</p> : <nav aria-label={copy.mismatchNavigation}>
            <button type="button" disabled={loading || cases.firstMismatchPage == null || cases.firstMismatchPage === cases.page} onClick={() => {
              if (history && selected && cases.firstMismatchPage != null) void readCases(history, selected, cases.firstMismatchPage, report.reportId);
            }}>{copy.firstMismatch}</button>
            <button type="button" disabled={loading || cases.previousMismatchPage == null} onClick={() => {
              if (history && selected && cases.previousMismatchPage != null) void readCases(history, selected, cases.previousMismatchPage, report.reportId);
            }}>{copy.previousMismatch}</button>
            <button type="button" disabled={loading || cases.nextMismatchPage == null} onClick={() => {
              if (history && selected && cases.nextMismatchPage != null) void readCases(history, selected, cases.nextMismatchPage, report.reportId);
            }}>{copy.nextMismatch}</button>
          </nav>}
        </>}
        <nav aria-label={copy.caseNavigation}>
          <button type="button" disabled={loading || cases.previousPage === null} onClick={() => {
            if (history && selected && cases.previousPage !== null) void readCases(history, selected, cases.previousPage, report.reportId);
          }}>{copy.previousCases}</button>
          <button type="button" disabled={loading || cases.nextPage === null} onClick={() => {
            if (history && selected && cases.nextPage !== null) void readCases(history, selected, cases.nextPage, report.reportId);
          }}>{copy.nextCases}</button>
        </nav>
      </> : !failure && <p>{copy.noCases}</p>}
    </>}
  </section>;
}

function MismatchComparison({ first, second, onInspectPage, onSwap }: { first: ValidationComparisonSnapshot;
  second: ValidationComparisonSnapshot; onInspectPage: (page: number) => void; onSwap: () => void }) {
  const [page, setPage] = useState(1);
  const result = useMemo(() => compareValidationSnapshots(first, second), [first, second]);
  if (result.state !== 'available') return <p>{result.state === 'same-observation' ? copy.selectComparisonTarget : copy.comparisonIncompatible}</p>;
  const groups = [[copy.newMismatch, result.newMismatches], [copy.persistentMismatch, result.persistentMismatches],
    [copy.resolvedMismatch, result.resolvedMismatches]] as const;
  const pages = Math.max(1, Math.ceil(Math.max(...groups.map(([, ordinals]) => ordinals.length)) / 20));
  return <>
    <p>{copy.comparisonPopulation}: {second.totalInputs}. {copy.comparisonPolicy}: {second.comparisonPolicy}.</p>
    <dl>{groups.map(([label, ordinals]) => <div key={label}><dt>{label}</dt><dd>{ordinals.length}</dd></div>)}
      <dt>{copy.matchingBoth}</dt><dd>{result.matched}</dd></dl>
    <p>{copy.comparisonWindow} {page} / {pages}. {copy.comparisonOrdinals}</p>
    <div role="region" aria-label={copy.comparisonDifferences} tabIndex={0}>
      <table><caption>{copy.comparisonDifferences}</caption><thead><tr><th scope="col">{copy.outcome}</th>
        <th scope="col">{copy.caseOrdinal}</th><th scope="col">{copy.inspectSelected}</th></tr></thead><tbody>
        {groups.flatMap(([label, ordinals]) => ordinals.slice((page - 1) * 20, page * 20).map(ordinal => <tr key={`${label}:${ordinal}`}>
          <th scope="row">{label}</th><td>{ordinal}</td><td><button type="button" onClick={() => { onInspectPage(Math.floor((ordinal - 1) / 20) + 1); }}
            aria-label={`${copy.inspectSelected}: ${ordinal}`}>{copy.inspectSelected}</button></td>
        </tr>))}
      </tbody></table>
    </div>
    {groups.every(([, ordinals]) => ordinals.length === 0) && <p>{copy.noComparisonDifferences}</p>}
    <nav aria-label={copy.comparisonNavigation}>
      <button type="button" disabled={page === 1} onClick={() => { setPage(page - 1); }}>{copy.previousComparison}</button>
      <button type="button" disabled={page === pages} onClick={() => { setPage(page + 1); }}>{copy.nextComparison}</button>
    </nav>
    <button type="button" onClick={onSwap}>{copy.swapComparison}</button>
  </>;
}

function Preview({ title, value }: { title: string; value: ValidationBytePreview | null }) {
  return <details><summary>{title}</summary>{value === null ? <p>{copy.notCompared}</p> : <>
    <p>{copy.bytes}: {value.totalBytes}. {copy.prefix}: {value.prefixBytes}. {value.truncated ? copy.truncated : copy.complete}</p>
    <pre aria-label={`${title}: ${copy.hex}`}>{value.hex === '' ? copy.empty : value.hex}</pre>
    <pre aria-label={`${title}: ${copy.text}`}>{value.text === null ? copy.noText : value.text === '' ? copy.empty : value.text}</pre>
  </>}</details>;
}
