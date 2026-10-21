import { useEffect, useMemo, useState } from 'preact/hooks';
import type { Report, ValidationBytePreview, ValidationHistory, ValidationOwner } from '../api/generated';
import { withApiFailureReference } from '../api/errors';
import { recordedValidationCopy as copy } from '../copy/attempt';
import { usePrivateTransport } from '../session/PrivateTransport';

export function RecordedValidationEvidence({ jobId, runId, basePath }: { jobId: string; runId: string; basePath: string }) {
  const { client } = usePrivateTransport(basePath);
  const binding = useMemo(() => ({ client, jobId, runId, active: null as AbortController | null }), [client, jobId, runId]);
  type View = { binding: typeof binding; history: ValidationHistory | null; selected: ValidationOwner | null;
    report: Report | null; loading: boolean; error: string };
  const [stored, setStored] = useState<View | null>(null);
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
    if (!controller.signal.aborted) setStored({ binding, history: null, selected: null, report: null, loading: false,
      error: withApiFailureReference(copy.failed, failure) });
  }
  async function readHistory(page?: number, graph?: string) {
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
    const controller = begin(history, owner);
    try {
      const ownerKey = owner.ownerKind === 'attempt' ? 'historyEvidence' : 'historyRunEvidence';
      const query = `historyGraph=${history.graphSha256}&historyPage=${history.page}&${ownerKey}=${owner.ownerId}&historyValidationPage=${page}`;
      const { data } = await client.get('report', `${root}/reports/revision-validation?${query}`, { signal: controller.signal });
      if (controller.signal.aborted) return;
      const cases = data.validationCases;
      if (data.binding.jobId !== jobId || data.binding.runId !== runId || data.binding.revisionId !== owner.candidateId ||
        data.reportType !== 'revision-validation' || data.authority !== 'observations' || data.acceptance !== 'not-evaluated' ||
        data.acceptanceArtifactId !== null || data.sourceArtifact !== null || (reportId !== undefined && data.reportId !== reportId) ||
        (data.summary !== null && (!('sourceSha256' in data.summary) || data.summary.sourceSha256 !== owner.sourceSha256)) ||
        (data.state === 'available' && !cases) ||
        (cases && (cases.graphSha256 !== history.graphSha256 || cases.ownerKind !== owner.ownerKind || cases.ownerId !== owner.ownerId ||
          cases.sourceSha256 !== owner.sourceSha256 || cases.corpusSha256 !== owner.corpusSha256 ||
          cases.normalOutcome !== owner.normalOutcome || cases.page !== page))) throw new Error('validation receipt binding');
      setStored({ binding, history, selected: owner, report: data, loading: false, error: '' });
    } catch (failure: unknown) { failed(controller, failure); }
  }
  const history = view?.history, report = view?.report, cases = report?.validationCases, selected = view?.selected;
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
            <td>{owner.normalOutcome ?? copy.notRecorded} <button type="button" disabled={loading || !owner.canInspect}
              aria-label={`${copy.inspect}: ${owner.ownerKind} ${owner.ownerId}`}
              onClick={() => { void readCases(history, owner); }}>{copy.inspect}</button></td>
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
      <ul aria-label={copy.reportLimitations}>{report.limitations.map((text, index) => <li key={index}>{text}</li>)}</ul>
      {report.summary && 'result' in report.summary && <dl>
        <dt>{copy.result}</dt><dd>{report.summary.result}</dd><dt>{copy.compared}</dt><dd>{report.summary.casesCompared}</dd>
      </dl>}
      {cases ? <>
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
        <nav aria-label={copy.caseNavigation}>
          <button type="button" disabled={loading || cases.previousPage === null} onClick={() => {
            if (history && selected && cases.previousPage !== null) void readCases(history, selected, cases.previousPage, report.reportId);
          }}>{copy.previousCases}</button>
          <button type="button" disabled={loading || cases.nextPage === null} onClick={() => {
            if (history && selected && cases.nextPage !== null) void readCases(history, selected, cases.nextPage, report.reportId);
          }}>{copy.nextCases}</button>
        </nav>
      </> : <p>{copy.noCases}</p>}
    </>}
  </section>;
}

function Preview({ title, value }: { title: string; value: ValidationBytePreview | null }) {
  return <details><summary>{title}</summary>{value === null ? <p>{copy.notCompared}</p> : <>
    <p>{copy.bytes}: {value.totalBytes}. {copy.prefix}: {value.prefixBytes}. {value.truncated ? copy.truncated : copy.complete}</p>
    <pre aria-label={`${title}: ${copy.hex}`}>{value.hex === '' ? copy.empty : value.hex}</pre>
    <pre aria-label={`${title}: ${copy.text}`}>{value.text === null ? copy.noText : value.text === '' ? copy.empty : value.text}</pre>
  </>}</details>;
}
