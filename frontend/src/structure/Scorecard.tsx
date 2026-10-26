import { useEffect, useRef, useState } from 'preact/hooks';
import { useLocation } from 'preact-iso/router';
import type { Acceptance, Run, ScorecardComparison, ScorecardMetric, ScorecardReconciliation, StructureScorecard } from '../api/generated';
import { ApiClientError } from '../api/errors';
import { scorecardCopy as copy } from '../copy/scorecard';
import { structureCopy } from '../copy/structure';
import { message, textMessage } from '../shared/messages';
import { apiPath } from '../app/paths';
import type { SourceSelection } from '../app/paths';
import { usePrivateTransport } from '../session/PrivateTransport';
import { structureItemPath, structureListPath } from './paths';
import { bindStructure, revisionReadRoute, structureReadMessage, structureRecordRoute } from './navigation';
import { Frame, useStructureRead } from './Frame';

import { SCORECARD_PAGE_LIMIT, scorecardLocation, scorecardSearch } from './scorecardQuery';
import type { ScorecardQuery } from './scorecardQuery';

const RUN_PAGE_LIMIT = 50;

type Measure = Pick<ScorecardMetric, 'state' | 'reason' | 'value' | 'numerator' | 'denominator'>;

/** State and reason in words; a recorded value is shown verbatim and never re-rounded or recolored into a pass. */
function stateText(measure: Measure): string {
  if (measure.state === 'measured') return copy.states.measured;
  const reason = measure.reason ? copy.reasons[measure.reason] ?? measure.reason : copy.notRecorded;
  return textMessage(copy.stateText, { state: copy.states[measure.state], reason });
}

function fraction(measure: Measure): string {
  return measure.numerator !== null && measure.denominator !== null
    ? textMessage(copy.of, { numerator: measure.numerator, denominator: measure.denominator }) : copy.notRecorded;
}

function StateCell({ measure }: { measure: Measure }) {
  return <td><span class={`score-state is-${measure.state}`}>{stateText(measure)}</span></td>;
}

function Metrics({ metrics }: { metrics: readonly ScorecardMetric[] }) {
  return <div class="structure-table"><table>
    <caption>{copy.measuresTitle}</caption>
    <thead><tr>{Object.values(copy.columns).map(label => <th scope="col" key={label}>{label}</th>)}</tr></thead>
    <tbody>{metrics.map(metric => <tr key={metric.id}>
      <th scope="row">{copy.metrics[metric.id]}</th>
      <StateCell measure={metric} />
      <td>{metric.value === null ? copy.notRecorded : <code>{metric.value}</code>}</td>
      <td>{fraction(metric)}</td>
      <td>{metric.recomputed === null ? '—' : <code>{metric.recomputed}</code>}</td>
      <td>{textMessage(copy.field, { record: copy.records[metric.source.record], field: metric.source.field })}</td>
    </tr>)}</tbody>
  </table></div>;
}

function Reconciliation({ value }: { value: ScorecardReconciliation | null }) {
  if (value === null) return <p>{copy.noReconciliation}</p>;
  const row = (label: string, numerator: string, denominator: string) => <tr key={label}>
    <th scope="row">{label}</th><td><code>{numerator}</code></td><td><code>{denominator}</code></td></tr>;
  return <>
    <div class="structure-table"><table>
      <caption>{copy.reconciliationTitle}</caption>
      <thead><tr>{Object.values(copy.reconciliationColumns).map(label => <th scope="col" key={label}>{label}</th>)}</tr></thead>
      <tbody>
        {row(copy.reconciliationRows.project, value.projectNumerator, value.projectDenominator)}
        {row(copy.reconciliationRows.modules, value.moduleNumeratorSum, value.moduleDenominatorSum)}
        {row(copy.reconciliationRows.excluded, value.excludedNumerator, value.excludedEntities)}
        {row(copy.reconciliationRows.shared, value.duplicateNumerator, value.duplicateMemberships)}
        {row(copy.reconciliationRows.unrecorded, '—', String(value.unrecordedPlanReferences))}
        {row(copy.reconciliationRows.unplanned, '—', String(value.unplannedScoreRows))}
      </tbody>
    </table></div>
    <p>{value.reconciles ? copy.reconciles : copy.doesNotReconcile}</p>
    <p>{copy.nonAdditive}</p>
  </>;
}

/** Bars are supplementary: every value, state and reason is in the table that follows, and in each bar's text. */
type ModuleScores = NonNullable<StructureScorecard['scorecard']>['modules']['items'];

function Chart({ items }: { items: ModuleScores }) {
  if (items.length === 0) return null;
  const row = 28, labelWidth = 200, barWidth = 320, width = labelWidth + barWidth + 120;
  return <figure class="score-chart">
    <figcaption>{copy.chartTitle}</figcaption>
    <svg role="img" aria-label={copy.chartLabel} viewBox={`0 0 ${width} ${items.length * row + 8}`} width={width} height={items.length * row + 8}>
      {items.map((item, position) => {
        const measured = item.metric.state === 'measured' && item.metric.value !== null;
        const ratio = measured ? Math.min(1, Math.max(0, Number(item.metric.value))) : 0;
        const y = position * row + 4;
        return <g key={item.moduleId}>
          <text x="0" y={y + 17} class="score-chart-label">{item.moduleId.length > 26 ? `${item.moduleId.slice(0, 25)}…` : item.moduleId}</text>
          <rect x={labelWidth} y={y + 4} width={barWidth} height={row - 10} class="score-chart-track" />
          {measured && <rect x={labelWidth} y={y + 4} width={barWidth * ratio} height={row - 10} class="score-chart-bar" />}
          <text x={labelWidth + barWidth + 8} y={y + 17} class="score-chart-value">{measured ? item.metric.value : copy.states[item.metric.state]}</text>
        </g>;
      })}
    </svg>
  </figure>;
}

function Comparison({ selected, basePath, query, version, onRoute }: {
  selected: SourceSelection; basePath: string; query: ScorecardQuery; version: string; onRoute: (query: ScorecardQuery) => void;
}) {
  const { client } = usePrivateTransport(basePath);
  // Attempts are listed newest first, one bounded page at a time; older pages load on request, so an older
  // baseline stays selectable and "no baselines" is said only once every page has been listed.
  const [runs, setRuns] = useState<{ items: Run[]; nextCursor: string | null } | 'failed' | null>(null);
  const [cursor, setCursor] = useState<string | undefined>(undefined);
  const [choice, setChoice] = useState(query.baseline ? `${query.baseline.runId}/${query.baseline.revisionId}` : '');
  useEffect(() => {
    const controller = new AbortController();
    const values = new URLSearchParams({ limit: String(RUN_PAGE_LIMIT) });
    if (cursor) values.set('cursor', cursor);
    void client.get('runs', `/jobs/${selected.jobId}/runs?${values}`, { signal: controller.signal })
      .then(response => {
        if (controller.signal.aborted) return;
        if (response.data.jobId !== selected.jobId || response.data.items.some(run => run.jobId !== selected.jobId)) throw new ApiClientError('invalid_response');
        setRuns(previous => ({ items: [...(cursor && previous && previous !== 'failed' ? previous.items : []), ...response.data.items],
          nextCursor: response.data.page.nextCursor }));
      })
      .catch(() => { if (!controller.signal.aborted) setRuns('failed'); });
    return () => controller.abort();
  }, [selected.jobId, cursor]);
  const key = query.baseline ? [selected.jobId, selected.runId, selected.revisionId, query.baseline.runId, query.baseline.revisionId,
    query.compareCursor ?? '', version].join('/') : '';
  const [read] = useStructureRead<ScorecardComparison | null>(key, async signal => {
    if (!query.baseline) return null;
    const values = new URLSearchParams({ baselineRunId: query.baseline.runId, baselineRevisionId: query.baseline.revisionId,
      limit: String(SCORECARD_PAGE_LIMIT) });
    if (query.compareCursor) values.set('cursor', query.compareCursor);
    values.set('structureVersion', version);
    const data = (await client.get('scorecardComparison', `${revisionReadRoute(selected)}/scorecard-comparison?${values}`, { signal })).data;
    const binding = data.binding, base = data.baseline.binding;
    if (binding.jobId !== selected.jobId || binding.runId !== selected.runId || binding.revisionId !== selected.revisionId
      || base.jobId !== selected.jobId || base.runId !== query.baseline.runId || base.revisionId !== query.baseline.revisionId) {
      throw new ApiClientError('invalid_response');
    }
    if (data.structureVersion !== version || data.current.structureVersion !== version) {
      throw new ApiClientError('http_error', { serverCode: 'STRUCTURE_CHANGED' });
    }
    return data;
  });
  const candidates = runs && runs !== 'failed' ? runs.items.filter((run: Run, position, all) => run.resultRevisionId !== null
    && !(run.runId === selected.runId && run.resultRevisionId === selected.revisionId)
    && all.findIndex(other => other.runId === run.runId) === position) : [];
  const data = read.state === 'ready' ? read.value : null;
  const offset = query.compareCursor ? Number(query.compareCursor.split('_')[1]) : 0;
  const side = (value: Measure | null) => value === null ? copy.notRecorded
    : value.state === 'measured' ? (value.value ?? fraction(value)) : stateText(value);
  const delta = (value: ScorecardComparison['metrics'][number]['delta'], unit: 'ratio' | 'count') => value.state !== 'computed'
    ? textMessage(copy.stateText, { state: copy.deltaStates[value.state], reason: value.reason ?? copy.notRecorded })
    : unit === 'ratio' ? textMessage(copy.deltaValue, { value: value.value ?? '—', numerator: value.numerator ?? '—', denominator: value.denominator ?? '—' })
      : textMessage(copy.deltaCount, { numerator: value.numerator ?? '—', denominator: value.denominator ?? '—' });
  return <section aria-labelledby="scorecard-compare-title">
    <h2 id="scorecard-compare-title">{copy.compareTitle}</h2>
    <p>{copy.compareHint}</p>
    {runs === 'failed' && <p role="alert">{copy.baselinesUnavailable}</p>}
    {runs !== null && runs !== 'failed' && runs.nextCursor !== null && <p>
      {textMessage(copy.olderAttempts, { count: runs.items.length })}{' '}
      <button type="button" onClick={() => setCursor(runs.nextCursor ?? undefined)}>{copy.showOlderAttempts}</button></p>}
    {runs !== null && runs !== 'failed' && (candidates.length === 0 && !query.baseline ? runs.nextCursor === null && <p>{copy.noBaselines}</p>
      : <form class="job-filters" aria-label={copy.compareTitle} onSubmit={event => {
        event.preventDefault();
        const [runId, revisionId] = choice.split('/');
        if (!runId || !revisionId) return;
        const next: ScorecardQuery = { ...query, baseline: { runId, revisionId } };
        delete next.compareCursor;
        onRoute(next);
      }}>
        <label>{copy.baseline}<select name="baseline" value={choice} required onChange={event => setChoice(event.currentTarget.value)}>
          <option value="">{copy.chooseBaseline}</option>
          {candidates.map(run => <option key={run.runId} value={`${run.runId}/${run.resultRevisionId}`}>
            {textMessage(copy.baselineOption, { run: run.runId, revision: run.resultRevisionId ?? '' })}</option>)}
        </select></label>
        <div class="job-actions"><button type="submit">{copy.compare}</button>
          {query.baseline && <button type="button" onClick={() => { setChoice(''); const next = { ...query }; delete next.baseline; delete next.compareCursor; onRoute(next); }}>
            {copy.clearComparison}</button>}</div>
      </form>)}
    {read.state === 'loading' && query.baseline && <p role="status">{structureCopy.loading}</p>}
    {read.state === 'failed' && <p role="alert">{structureReadMessage(read.failure)}</p>}
    {data && <>
      <p role="status"><strong>{copy.compatibility[data.compatibility.state]}</strong></p>
      <div class="structure-table"><table>
        <caption>{copy.checksTitle}</caption>
        <thead><tr>{Object.values(copy.checkColumns).map(label => <th scope="col" key={label}>{label}</th>)}</tr></thead>
        <tbody>{data.compatibility.checks.map(check => <tr key={check.id}>
          <th scope="row">{copy.checks[check.id]}</th>
          <td><span class={`score-state is-${check.state === 'match' ? 'measured' : check.blocking ? 'failed' : 'partial'}`}>{copy.checkStates[check.state]}</span></td>
          <td>{check.blocking ? copy.yes : copy.no}</td>
          <td>{check.current === null ? copy.notRecorded : <code>{check.current}</code>}</td>
          <td>{check.baseline === null ? copy.notRecorded : <code>{check.baseline}</code>}</td>
        </tr>)}</tbody>
      </table></div>
      {(['current', 'baseline'] as const).map(name => <p key={name}>{textMessage(copy.sideReconciliation, { side: copy.sides[name],
        result: data[name].reconciliation === null ? copy.noBreakdown : data[name].reconciliation.reconciles ? copy.reconciled : copy.notReconciled })}</p>)}
      {data.metrics.length > 0 && <div class="structure-table"><table>
        <caption>{copy.measuresTitle}</caption>
        <thead><tr>{Object.values(copy.comparisonColumns).map(label => <th scope="col" key={label}>{label}</th>)}</tr></thead>
        <tbody>{data.metrics.map(metric => <tr key={metric.id}>
          <th scope="row">{copy.metrics[metric.id]}</th>
          <td>{side(metric.current)}</td><td>{side(metric.baseline)}</td><td>{delta(metric.delta, metric.unit)}</td>
        </tr>)}</tbody>
      </table></div>}
      {data.modules.total > 0 && <>
        <p role="status">{textMessage(copy.comparisonRange, { first: offset + 1, last: offset + data.modules.items.length, total: data.modules.total })}</p>
        <div class="structure-table"><table>
          <caption>{copy.moduleComparisonTitle}</caption>
          <thead><tr>{Object.values(copy.moduleComparisonColumns).map(label => <th scope="col" key={label}>{label}</th>)}</tr></thead>
          <tbody>{data.modules.items.map(item => <tr key={item.moduleId}>
            <th scope="row">{item.selector ? <a href={structureItemPath(basePath, selected, 'modules', item.selector, version)}><bdi>{item.moduleId}</bdi></a>
              : <bdi>{item.moduleId}</bdi>}</th>
            <td>{copy.presence[item.presence]}</td><td>{side(item.current)}</td><td>{side(item.baseline)}</td><td>{delta(item.delta, 'ratio')}</td>
          </tr>)}</tbody>
        </table></div>
        <nav class="job-actions" aria-label={copy.moduleComparisonTitle}>
          <button type="button" disabled={!query.compareCursor} onClick={() => { const next = { ...query }; delete next.compareCursor; onRoute(next); }}>{copy.first}</button>
          <button type="button" disabled={!data.modules.page.nextCursor} onClick={() => {
            if (data.modules.page.nextCursor) onRoute({ ...query, compareCursor: data.modules.page.nextCursor });
          }}>{copy.next}</button>
        </nav>
      </>}
    </>}
  </section>;
}

/** The recorded scorecard of one revision and an optional comparison with another attempt of the same job. */
export default function Scorecard({ selected, basePath, search }: { selected: SourceSelection; basePath: string; search: string }) {
  const location = useLocation();
  const { client } = usePrivateTransport(basePath);
  const query = scorecardLocation(search);
  const results = useRef<HTMLHeadingElement>(null);
  const moveFocus = useRef(false);
  const key = [selected.jobId, selected.runId, selected.revisionId, query.sort, query.order, query.cursor ?? '', query.version ?? ''].join('/');
  const [read, refresh] = useStructureRead<StructureScorecard>(key, async signal => {
    const values = new URLSearchParams({ limit: String(SCORECARD_PAGE_LIMIT) });
    if (query.sort !== 'module') values.set('sort', query.sort);
    if (query.order !== 'asc') values.set('order', query.order);
    if (query.cursor) values.set('cursor', query.cursor);
    if (query.version) values.set('structureVersion', query.version);
    return bindStructure((await client.get('structureScorecard', `${revisionReadRoute(selected)}/scorecard?${values}`, { signal })).data,
      selected, query.version);
  });
  const [acceptance, setAcceptance] = useState<Acceptance | null>(null);
  useEffect(() => {
    const controller = new AbortController();
    void client.get('run', `/jobs/${selected.jobId}/runs/${selected.runId}`, { signal: controller.signal })
      .then(response => { if (!controller.signal.aborted && response.data.runId === selected.runId) setAcceptance(response.data.acceptance); })
      .catch(() => undefined);
    return () => controller.abort();
  }, [selected.jobId, selected.runId]);
  useEffect(() => { if (read.state !== 'loading' && moveFocus.current) { moveFocus.current = false; results.current?.focus(); } }, [read]);
  const route = (next: ScorecardQuery, focus = false) => {
    moveFocus.current = focus;
    location.route(structureListPath(basePath, selected, 'scorecard', scorecardSearch(next)));
  };
  const data = read.state === 'ready' ? read.value : null;
  const card = data?.scorecard ?? null;
  const offset = query.cursor ? Number(query.cursor.split('_')[1]) : 0;
  const [sort, setSort] = useState(query.sort); const [order, setOrder] = useState(query.order);
  // Inventory links stay outside the read gate; refreshing a pinned or paged view reads the current first page.
  return <Frame selected={selected} data={data} read={read} pinned={query.version !== undefined} boundary={copy.boundary}
    onRefresh={() => {
      if (!query.version && !query.cursor) { refresh(); return; }
      const next = { ...query }; delete next.version; delete next.cursor; route(next);
    }}
    navigation={<p><a href={structureListPath(basePath, selected, 'functions')}>{structureCopy.browseFunctions}</a>{' '}
      <a href={structureListPath(basePath, selected, 'modules')}>{structureCopy.browseModules}</a></p>}>
    {data && <>
      <h2>{copy.record}</h2>
      <p role={data.confidence.state === 'available' ? undefined : 'alert'}>{copy.recordStates[data.confidence.state]}
        {data.confidence.stateReason && <> {message(structureCopy.reason, { code: <code>{data.confidence.stateReason}</code> })}</>}</p>
      {data.confidence.path && data.confidence.sha256 && <p>
        {message(structureCopy.recordDigest, { path: <bdi>{data.confidence.path}</bdi>, sha256: <code>{data.confidence.sha256}</code>,
          schema: data.confidence.schemaVersion ?? structureCopy.notRecorded })}{' '}
        <a href={apiPath(basePath, structureRecordRoute(selected, 'confidence', data.structureVersion))} download="">{copy.download}</a></p>}
      <dl class="job-facts">
        <dt>{copy.acceptance}</dt><dd>{acceptance ? copy.acceptanceStates[acceptance] : copy.acceptanceUnavailable}</dd>
      </dl>
      {card && <>
        <p>{message(copy.thresholds, { code: <code>{card.thresholds.reason}</code> })}</p>
        <Metrics metrics={card.metrics} />
        <details>
          <summary>{copy.definitionTitle}</summary>
          <dl class="job-facts">
            <dt>{copy.interpretation}</dt><dd>{textMessage(copy.interpretationValue, { kind: card.interpretation.kind,
              version: card.interpretation.schemaVersion, calibration: card.interpretation.calibrationStatus })}</dd>
            <dt>{copy.formula}</dt><dd>{textMessage(copy.formulaValue, { id: card.formula.id })}</dd>
            <dt>{copy.weights}</dt><dd>{card.formula.weights.map(item => `${item.label} ${item.weight}`).join(', ')}</dd>
            <dt>{copy.basis}</dt><dd>{card.interpretation.basis.text}</dd>
            <dt>{copy.meaning}</dt><dd>{card.interpretation.scoreMeaning.text}</dd>
            <dt>{copy.scope}</dt><dd>{textMessage(copy.scopeValue, { entities: card.scope.entities, functions: card.scope.functions,
              globals: card.scope.globals, types: card.scope.types })}</dd>
            <dt>{copy.modulesInScope}</dt><dd>{card.scope.modules ?? structureCopy.notRecorded}</dd>
            <dt>{copy.input}</dt><dd><code>{card.scope.inputSha256}</code></dd>
            <dt>{copy.model}</dt><dd><code>{card.scope.modelSha256}</code> (schema {card.scope.modelSchemaVersion})</dd>
          </dl>
        </details>
        <div class="structure-table"><table>
          <caption>{copy.labelsTitle}</caption>
          <thead><tr>{Object.values(copy.labelColumns).map(label => <th scope="col" key={label}>{label}</th>)}</tr></thead>
          <tbody>{card.labels.map(label => <tr key={label.label}>
            <th scope="row">{structureCopy.extraction[label.label]}</th><td>{label.functions}</td><td>{label.globals}</td><td>{label.types}</td>
            <td>{label.entities}</td><td><code>{label.weight}</code></td><td><code>{label.contribution}</code></td>
          </tr>)}</tbody>
        </table></div>
        <Reconciliation value={card.reconciliation} />
        <h2 ref={results} tabIndex={-1}>{copy.modulesTitle}</h2>
        <form class="job-filters" aria-label={copy.applySort} onSubmit={event => {
          event.preventDefault(); const next = { ...query, sort, order }; delete next.cursor; route(next, true);
        }}>
          <label>{copy.sort}<select name="sort" value={sort} onChange={event => setSort(event.currentTarget.value as ScorecardQuery['sort'])}>
            {(['module', 'score'] as const).map(value => <option key={value} value={value}>{copy.sorts[value]}</option>)}</select></label>
          <label>{copy.order}<select name="order" value={order} onChange={event => setOrder(event.currentTarget.value as ScorecardQuery['order'])}>
            {(['asc', 'desc'] as const).map(value => <option key={value} value={value}>{copy.orders[value]}</option>)}</select></label>
          <div class="job-actions"><button type="submit">{copy.applySort}</button></div>
        </form>
        {card.modules.total !== null && card.modules.total > 0 && <>
          <p role="status">{textMessage(copy.moduleRange, { first: offset + 1, last: offset + card.modules.items.length, total: card.modules.total })}</p>
          <Chart items={card.modules.items} />
          <div class="structure-table"><table>
            <caption>{copy.modulesTitle}</caption>
            <thead><tr>{Object.values(copy.moduleColumns).map(label => <th scope="col" key={label}>{label}</th>)}</tr></thead>
            <tbody>{card.modules.items.map(item => <tr key={item.moduleId}>
              <th scope="row">{item.selector ? <a href={structureItemPath(basePath, selected, 'modules', item.selector, data.structureVersion)}><bdi>{item.moduleId}</bdi></a>
                : <bdi>{item.moduleId}</bdi>}</th>
              <td>{structureCopy.declarations[item.implementationDeclaration]}</td>
              <StateCell measure={item.metric} />
              <td>{item.metric.value === null ? copy.notRecorded : <code>{item.metric.value}</code>}</td>
              <td>{fraction(item.metric)}</td>
              <td>{item.metric.recomputed === null ? '—' : <code>{item.metric.recomputed}</code>}</td>
            </tr>)}</tbody>
          </table></div>
          <nav class="job-actions" aria-label={copy.pages}>
            <button type="button" disabled={read.state === 'loading' || !query.cursor} onClick={() => { const next = { ...query }; delete next.cursor; route(next, true); }}>{copy.first}</button>
            <button type="button" disabled={read.state === 'loading' || !card.modules.page.nextCursor} onClick={() => {
              if (card.modules.page.nextCursor) route({ ...query, cursor: card.modules.page.nextCursor }, true);
            }}>{copy.next}</button>
          </nav>
        </>}
      </>}
      <Comparison selected={selected} basePath={basePath} query={query} version={data.structureVersion} onRoute={next => route(next)} />
    </>}
  </Frame>;
}
