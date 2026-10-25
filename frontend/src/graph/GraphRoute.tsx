import { useState } from 'preact/hooks';
import { useLocation } from 'preact-iso/router';
import type { StructureNeighborhood } from '../api/generated';
import { graphCopy as copy } from '../copy/graph';
import { structureCopy } from '../copy/structure';
import { message, textMessage } from '../shared/messages';
import type { SourceSelection } from '../app/paths';
import { usePrivateTransport } from '../session/PrivateTransport';
import { structureListPath } from '../structure/paths';
import { bindStructure, revisionReadRoute } from '../structure/navigation';
import { Frame, useStructureRead } from '../structure/Frame';
import { GRAPH_LIMITS, graphLocation, graphPath, graphReadRoute } from './query';
import type { GraphQuery } from './query';
import { GraphView } from './GraphView';
import { graphLayoutRuntime } from './layoutRuntime';
import type { LayoutRuntime } from './layoutOperation';

function count(value: number | null) { return value === null ? copy.unknown : value; }

function Completeness({ data }: { data: NonNullable<StructureNeighborhood['neighborhood']> }) {
  const { completeness } = data;
  return <section aria-labelledby="graph-completeness-title">
    <h2 id="graph-completeness-title">{copy.completenessTitle}</h2>
    <p role="status">{completeness.state === 'complete' ? copy.complete
      : <>{copy.truncated} {completeness.reasons.map(reason => copy.reasons[reason]).join('; ')}.</>}</p>
    <dl class="job-facts">
      <dt>{copy.shownNodes}</dt><dd>{data.nodes.length}</dd>
      <dt>{copy.shownEdges}</dt><dd>{data.edges.length}</dd>
      <dt>{copy.reachableNodes}</dt><dd>{count(completeness.reachableNodes)}</dd>
      <dt>{copy.reachableEdges}</dt><dd>{count(completeness.reachableEdges)}</dd>
      <dt>{copy.omittedNodes}</dt><dd>{count(completeness.omittedNodes)}</dd>
      <dt>{copy.omittedEdges}</dt><dd>{count(completeness.omittedEdges)}</dd>
      <dt>{copy.beyondDepth}</dt><dd>{count(completeness.edgesBeyondDepth)}</dd>
      {completeness.filteredEdges !== 0 && <><dt>{copy.filteredEdges}</dt><dd>{count(completeness.filteredEdges)}</dd></>}
    </dl>
  </section>;
}

function Controls({ query, onApply }: { query: GraphQuery; onApply: (query: GraphQuery) => void }) {
  // The parent keys this form by the URL, so a new location starts a fresh draft without a racing reset.
  const [draft, setDraft] = useState(query);
  const number = (key: 'depth' | 'nodeLimit' | 'edgeLimit', maximum: number) => <label>{copy[key]}
    <input type="number" name={key} min={1} max={maximum} required value={draft[key]}
      onInput={event => { const value = Number(event.currentTarget.value); if (Number.isInteger(value)) setDraft(current => ({ ...current, [key]: value })); }} /></label>;
  return <form class="job-filters" aria-label={copy.controls} onSubmit={event => {
    event.preventDefault();
    if (event.currentTarget.reportValidity()) onApply(draft);
  }}>
    <label>{copy.direction}<select name="direction" value={draft.direction}
      onChange={event => { const direction = event.currentTarget.value as GraphQuery['direction']; setDraft(current => ({ ...current, direction })); }}>
      {(['both', 'outgoing', 'incoming'] as const).map(value => <option key={value} value={value}>{copy.directions[query.view][value]}</option>)}
    </select></label>
    {number('depth', GRAPH_LIMITS.depth)}
    {number('nodeLimit', GRAPH_LIMITS.nodes)}
    {number('edgeLimit', GRAPH_LIMITS.edges)}
    {query.view === 'calls' && <label>{copy.unresolved}<select name="unresolved" value={draft.unresolved}
      onChange={event => { const unresolved = event.currentTarget.value as GraphQuery['unresolved']; setDraft(current => ({ ...current, unresolved })); }}>
      {(['include', 'exclude'] as const).map(value => <option key={value} value={value}>{copy.unresolvedOptions[value]}</option>)}
    </select></label>}
    <p>{textMessage(copy.limitsHint, { depth: GRAPH_LIMITS.depth, nodes: GRAPH_LIMITS.nodes, edges: GRAPH_LIMITS.edges })}</p>
    <div class="job-actions"><button type="submit">{copy.apply}</button></div>
  </form>;
}

/** A bounded relationship neighborhood of one recorded function or module. The URL holds focus and limits. */
export default function GraphRoute({ selected, basePath, search, runtime = graphLayoutRuntime }: {
  selected: SourceSelection; basePath: string; search: string; runtime?: LayoutRuntime;
}) {
  const location = useLocation();
  const { client } = usePrivateTransport(basePath);
  const { query, version } = graphLocation(search);
  const key = [selected.jobId, selected.runId, selected.revisionId, search].join('/');
  const [read, refresh] = useStructureRead<StructureNeighborhood>(key, async signal => {
    const data = bindStructure((await client.get('structureNeighborhood', graphReadRoute(revisionReadRoute(selected), query, version), { signal })).data,
      selected, version);
    const echoed = data.query;
    if (echoed.view !== query.view || echoed.focus !== query.focus || echoed.depth !== query.depth || echoed.nodeLimit !== query.nodeLimit
      || echoed.edgeLimit !== query.edgeLimit || echoed.direction !== query.direction) throw new Error('Neighborhood answers another request.');
    return data;
  });
  const data = read.state === 'ready' ? read.value : null;
  return <Frame selected={selected} data={data} read={read} pinned={version !== undefined} boundary={copy.boundary} onRefresh={refresh}>
    {data && <>
      <p><a href={structureListPath(basePath, selected, query.view === 'calls' ? 'functions' : 'modules')}>
        {query.view === 'calls' ? structureCopy.returnFunctions : structureCopy.returnModules}</a></p>
      <h2>{copy.views[query.view]}: <bdi>{data.neighborhood?.nodes[0] && 'name' in data.neighborhood.nodes[0]
        ? data.neighborhood.nodes[0].name ?? query.focus : query.focus}</bdi></h2>
      <Controls key={search} query={query} onApply={next => location.route(graphPath(basePath, selected, next, version))} />
      <p role={data.graphState === 'available' ? undefined : 'alert'}>{copy.graphStates[data.graphState]}
        {data.graphReason && <> {message(structureCopy.reason, { code: <code>{data.graphReason}</code> })}</>}</p>
      <details>
        <summary>{copy.familiesTitle}</summary>
        <ul>{data.relationships.map(family => <li key={family.id}>{copy.families[family.id]}: {copy.familyStates[family.state]}
          {family.reason && <> ({message(structureCopy.reason, { code: <code>{family.reason}</code> })})</>}</li>)}</ul>
      </details>
      {data.neighborhood && <>
        <Completeness data={data.neighborhood} />
        <GraphView key={data.structureVersion + key} response={data} selected={selected} basePath={basePath} query={query} runtime={runtime} />
      </>}
    </>}
  </Frame>;
}
