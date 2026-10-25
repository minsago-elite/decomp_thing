import { useEffect, useMemo, useRef, useState } from 'preact/hooks';
import type { StructureGraphEdge, StructureGraphNode, StructureNeighborhood } from '../api/generated';
import { graphCopy as copy } from '../copy/graph';
import { structureCopy } from '../copy/structure';
import { message, textMessage } from '../shared/messages';
import { apiPath, sourceFilePath } from '../app/paths';
import type { SourceSelection } from '../app/paths';
import { structureItemPath } from '../structure/paths';
import { structureRecordRoute } from '../structure/navigation';
import { NODE_HEIGHT, NODE_WIDTH } from './layout';
import type { GraphLayout } from './layout';
import { beginGraphLayout } from './layoutOperation';
import type { LayoutResult, LayoutRuntime } from './layoutOperation';
import { graphPath } from './query';
import type { GraphQuery } from './query';

type Neighborhood = NonNullable<StructureNeighborhood['neighborhood']>;
type Selection = { kind: 'node'; index: number } | { kind: 'edge'; position: number } | null;
type LayoutState = { status: 'pending' } | { status: 'running' } | { status: 'cancelled' } | LayoutResult;
const TABLE_ROWS = 100;

export function nodeLabel(node: StructureGraphNode): string {
  return node.kind === 'module' ? node.moduleId : node.kind === 'function' ? node.name ?? node.entityId : node.entityId;
}

/** Text marks that repeat every visual style, so no state relies on color or line style alone. */
function marks(node: StructureGraphNode): string[] {
  const values: string[] = [];
  if (node.index === 0) values.push(copy.marks.focus);
  if (node.kind === 'unrecorded-function') values.push(copy.marks.unrecorded);
  if (node.kind === 'function' && node.evidenceState !== 'recovered') values.push(copy.marks[node.evidenceState]);
  const hidden = node.outgoing.total - node.outgoing.shown + node.incoming.total - node.incoming.shown;
  if (hidden > 0) values.push(textMessage(copy.marks.hidden, { count: hidden }));
  return values;
}

function outline(node: StructureGraphNode): string {
  if (node.kind === 'unrecorded-function') return 'unrecorded';
  if (node.kind === 'module') return node.inDependencyCycle ? 'cycle' : 'recovered';
  return node.evidenceState;
}

function Drawing({ data, layout, selection, onSelect }: {
  data: Neighborhood; layout: GraphLayout; selection: Selection; onSelect: (selection: Selection) => void;
}) {
  const center = (index: number) => [layout.x[index]! + NODE_WIDTH / 2, layout.y[index]! + NODE_HEIGHT / 2] as const;
  const focus = data.nodes[0]!;
  return <div class="graph-canvas">
    <svg role="img" aria-label={textMessage(copy.drawingLabel, { nodes: data.nodes.length, edges: data.edges.length, focus: nodeLabel(focus) })}
      width={layout.width} height={layout.height} viewBox={`0 0 ${layout.width} ${layout.height}`}>
      <defs><marker id="graph-arrow" viewBox="0 0 10 10" refX="10" refY="5" markerWidth="7" markerHeight="7" orient="auto-start-reverse">
        <path d="M0 0L10 5L0 10z" class="graph-arrow" /></marker></defs>
      {data.edges.map((edge, position) => {
        const [x1, y1] = center(edge.source); const [x2, y2] = center(edge.target);
        const selected = selection?.kind === 'edge' && selection.position === position;
        const self = edge.source === edge.target;
        const startX = x1 + (x2 >= x1 ? NODE_WIDTH / 2 : -NODE_WIDTH / 2), endX = x2 + (x2 >= x1 ? -NODE_WIDTH / 2 : NODE_WIDTH / 2);
        const path = self ? `M${x1 + NODE_WIDTH / 2} ${y1}c40 -34 40 34 0 ${NODE_HEIGHT / 4}`
          : `M${startX} ${y1}C${(startX + endX) / 2} ${y1} ${(startX + endX) / 2} ${y2} ${endX} ${y2}`;
        return <path key={position} d={path} class={`graph-edge is-${edge.resolution === 'no-record' ? 'unrecorded' : edge.relationship}${selected ? ' is-selected' : ''}`}
          marker-end="url(#graph-arrow)" onClick={() => onSelect({ kind: 'edge', position })} />;
      })}
      {data.nodes.map(node => {
        const selected = selection?.kind === 'node' && selection.index === node.index;
        const label = nodeLabel(node);
        const text = label.length > 22 ? `${label.slice(0, 21)}…` : label;
        return <g key={node.index} class={`graph-node is-${outline(node)}${node.index === 0 ? ' is-focus' : ''}${selected ? ' is-selected' : ''}`}
          transform={`translate(${layout.x[node.index]} ${layout.y[node.index]})`} onClick={() => onSelect({ kind: 'node', index: node.index })}>
          <title>{[label, ...marks(node)].join(' · ')}</title>
          <rect width={NODE_WIDTH} height={NODE_HEIGHT} rx="4" />
          {node.index === 0 && <rect class="graph-focus-ring" x="3" y="3" width={NODE_WIDTH - 6} height={NODE_HEIGHT - 6} rx="3" />}
          <text x="8" y="14">{text}</text>
          <text x="8" y="28" class="graph-mark">{marks(node).join(' · ')}</text>
        </g>;
      })}
    </svg>
  </div>;
}

function Paged<T>({ items, caption, render, header }: {
  items: readonly T[]; caption: string; header: preact.ComponentChildren; render: (item: T, position: number) => preact.ComponentChildren;
}) {
  const [start, setStart] = useState(0);
  const shown = items.slice(start, start + TABLE_ROWS);
  return <>
    <div class="structure-table"><table>
      <caption>{caption}{items.length > TABLE_ROWS && <> ({textMessage(copy.tablePage, { first: start + 1, last: start + shown.length, total: items.length })})</>}</caption>
      <thead><tr>{header}</tr></thead>
      <tbody>{shown.map((item, offset) => render(item, start + offset))}</tbody>
    </table></div>
    {items.length > TABLE_ROWS && <div class="job-actions">
      <button type="button" disabled={start === 0} onClick={() => setStart(Math.max(0, start - TABLE_ROWS))}>{copy.previousRows}</button>
      <button type="button" disabled={start + TABLE_ROWS >= items.length} onClick={() => setStart(start + TABLE_ROWS)}>{copy.nextRows}</button>
    </div>}
  </>;
}

function nodeKind(node: StructureGraphNode): string {
  if (node.kind === 'function') return `${copy.kinds.function}: ${structureCopy.evidence[node.evidenceState]}`;
  if (node.kind === 'module') return node.inDependencyCycle ? `${copy.kinds.module}, ${copy.inCycle}` : copy.kinds.module;
  return copy.kinds['unrecorded-function'];
}

function Selected({ data, response, selection, selected, basePath, query }: {
  data: Neighborhood; response: StructureNeighborhood; selection: Selection; selected: SourceSelection; basePath: string; query: GraphQuery;
}) {
  const version = response.structureVersion;
  const record = (kind: 'program-model' | 'module-plan', label: string, value: StructureNeighborhood['model']) => value.path && value.sha256
    ? <li><a href={apiPath(basePath, structureRecordRoute(selected, kind, version))} download="">{label}</a>{' '}
      ({message(copy.evidenceRecord, { path: <bdi>{value.path}</bdi>, sha256: <code>{value.sha256}</code> })})</li> : null;
  const source = (label: string, path: string | null, fileId: string | null) => path === null ? null
    : <li>{fileId ? <a href={sourceFilePath(basePath, selected, fileId)}>{label}: <bdi>{path}</bdi></a>
      : <>{label}: <bdi>{path}</bdi> ({copy.noSourceFile})</>}</li>;
  const entity = (node: StructureGraphNode, label: string) => node.kind === 'function' && node.selector
    ? <li><a href={structureItemPath(basePath, selected, 'functions', node.selector, version)}>{label}: <bdi>{nodeLabel(node)}</bdi></a></li> : null;
  const module = (node: StructureGraphNode, label: string) => node.kind === 'module' && node.selector
    ? <li><a href={structureItemPath(basePath, selected, 'modules', node.selector, version)}>{label}: <bdi>{node.moduleId}</bdi></a></li> : null;
  const recenter = (node: StructureGraphNode) => node.index !== 0 && node.kind !== 'unrecorded-function' && node.selector
    ? <li><a href={graphPath(basePath, selected, { ...query, focus: node.selector }, version)}>{copy.links.focus}</a></li> : null;
  if (selection === null) return <p>{copy.noSelection}</p>;
  if (selection.kind === 'node') {
    const node = data.nodes[selection.index]!;
    return <>
      <p role="status">{textMessage(copy.selectedNode, { name: nodeLabel(node) })}</p>
      <dl class="job-facts">
        <dt>{copy.nodeColumns.kind}</dt><dd>{nodeKind(node)}</dd>
        {node.kind !== 'module' && <><dt>{copy.facts.identity}</dt><dd><code>{node.entityId}</code></dd></>}
        {node.kind === 'function' && <>
          <dt>{copy.facts.address}</dt><dd><code>{node.address ?? structureCopy.notRecorded}</code></dd>
          <dt>{copy.facts.extraction}</dt><dd>{structureCopy.extraction[node.extractionStatus]}</dd>
          <dt>{copy.facts.evidence}</dt><dd>{structureCopy.evidenceMeanings[node.evidenceState]}</dd>
          <dt>{copy.facts.module}</dt><dd>{node.ownership === 'owned' && node.moduleId ? <bdi>{node.moduleId}</bdi> : structureCopy.ownership[node.ownership]}</dd>
        </>}
        {node.kind === 'module' && <>
          <dt>{copy.facts.functions}</dt><dd>{node.functionCount}</dd>
          <dt>{copy.facts.declaration}</dt><dd>{structureCopy.declarations[node.implementationDeclaration]}</dd>
          <dt>{copy.facts.unattributed}</dt><dd>{node.unattributedReferences}</dd>
        </>}
        <dt>{copy.facts.distance}</dt><dd>{node.depth}</dd>
        <dt>{copy.facts.outgoing}</dt><dd>{textMessage(copy.degree, node.outgoing)}</dd>
        <dt>{copy.facts.incoming}</dt><dd>{textMessage(copy.degree, node.incoming)}</dd>
      </dl>
      {node.kind === 'unrecorded-function' && <p>{copy.unrecordedNote}</p>}
      <ul>
        {entity(node, copy.links.entity)}
        {node.kind === 'function' && node.moduleSelector && <li><a href={structureItemPath(basePath, selected, 'modules', node.moduleSelector, version)}>
          {copy.links.module}: <bdi>{node.moduleId}</bdi></a></li>}
        {module(node, copy.links.module)}
        {node.kind !== 'unrecorded-function' && source(copy.links.source, node.implementationPath, node.implementationFileId)}
        {node.kind === 'module' && source(copy.links.header, node.interfacePath, node.interfaceFileId)}
        {recenter(node)}
        {record('program-model', copy.links.model, response.model)}
        {node.kind === 'module' && record('module-plan', copy.links.plan, response.plan)}
      </ul>
    </>;
  }
  const edge = data.edges[selection.position]!;
  const from = data.nodes[edge.source]!, to = data.nodes[edge.target]!;
  return <>
    <p role="status">{textMessage(copy.selectedEdge, { from: nodeLabel(from), to: nodeLabel(to) })}</p>
    <dl class="job-facts">
      <dt>{copy.facts.relationship}</dt><dd>{copy.relationships[edge.relationship]}</dd>
      <dt>{copy.facts.resolution}</dt><dd>{copy.resolutions[edge.resolution]}</dd>
      <dt>{copy.facts.references}</dt><dd>{edge.references}</dd>
      {edge.relationship !== 'call' && <><dt>{copy.facts.cycle}</dt><dd>{edge.recordedCycle ? copy.yes : copy.no}</dd></>}
    </dl>
    <p>{edge.relationship === 'call' ? copy.callNote : copy.derivedNote}</p>
    <ul>
      {entity(from, copy.links.caller)}
      {entity(to, copy.links.callee)}
      {module(from, copy.links.sourceModule)}
      {module(to, copy.links.targetModule)}
      {from.kind !== 'unrecorded-function' && source(copy.links.source, from.implementationPath, from.implementationFileId)}
      {record('program-model', copy.links.model, response.model)}
      {edge.relationship !== 'call' && record('module-plan', copy.links.plan, response.plan)}
    </ul>
  </>;
}

/**
 * The drawing and its equivalent tables. Layout runs in a worker that the reader can cancel and that is always
 * terminated on unmount or a new neighborhood; the tables, links and job controls never wait for it.
 */
export function GraphView({ response, selected, basePath, query, runtime }: {
  response: StructureNeighborhood; selected: SourceSelection; basePath: string; query: GraphQuery; runtime: LayoutRuntime;
}) {
  const data = response.neighborhood!;
  // Pending until the effect owns a worker, so a cancel can never precede the work it should stop.
  const [layout, setLayout] = useState<LayoutState>({ status: 'pending' });
  const [attempt, setAttempt] = useState(0);
  const [selection, setSelection] = useState<Selection>(null);
  const stop = useRef<(() => void) | null>(null);
  const details = useRef<HTMLHeadingElement>(null);
  const nodes = useMemo(() => data.nodes.map(node => ({ index: node.index, depth: node.depth })), [data]);
  useEffect(() => {
    setLayout({ status: 'running' });
    const cancel = beginGraphLayout(nodes, data.edges, runtime, setLayout);
    stop.current = cancel;
    return () => { cancel(); stop.current = null; };
  }, [data, attempt, runtime]);
  const select = (next: Selection) => { setSelection(next); };
  const focusDetails = (next: Selection) => { select(next); details.current?.focus(); };
  return <>
    <h2>{copy.drawingTitle}</h2>
    <p>{copy.legend}</p>
    {layout.status === 'running' && <div class="job-actions" role="status">
      <span>{copy.layoutRunning}</span>
      <button type="button" onClick={() => { stop.current?.(); setLayout({ status: 'cancelled' }); }}>{copy.cancelLayout}</button>
    </div>}
    {layout.status === 'cancelled' && <p role="status">{copy.layoutCancelled}</p>}
    {layout.status === 'failed' && <p role="status">{copy.layoutFailed[layout.reason]}</p>}
    {(layout.status === 'cancelled' || layout.status === 'failed') && <p>
      <button type="button" onClick={() => setAttempt(value => value + 1)}>{copy.drawAgain}</button></p>}
    {layout.status === 'ready' && <Drawing data={data} layout={layout.value} selection={selection} onSelect={select} />}
    <section aria-labelledby="graph-selection-title" class="graph-selection">
      <h2 id="graph-selection-title" ref={details} tabIndex={-1}>{copy.selectionTitle}</h2>
      <Selected data={data} response={response} selection={selection} selected={selected} basePath={basePath} query={query} />
    </section>
    <Paged items={data.nodes} caption={copy.nodesTitle} header={<>
      {Object.values(copy.nodeColumns).map(label => <th scope="col" key={label}>{label}</th>)}
    </>} render={(node: StructureGraphNode) => <tr key={node.index} class={selection?.kind === 'node' && selection.index === node.index ? 'is-selected' : undefined}>
      <th scope="row"><bdi>{nodeLabel(node)}</bdi>{node.index === 0 && <> <span class="structure-flag">({copy.marks.focus})</span></>}</th>
      <td>{nodeKind(node)}</td>
      <td>{node.depth}</td>
      <td>{textMessage(copy.degree, node.outgoing)}</td>
      <td>{textMessage(copy.degree, node.incoming)}</td>
      <td><button type="button" onClick={() => focusDetails({ kind: 'node', index: node.index })}>
        {textMessage(copy.inspect, { name: nodeLabel(node) })}</button></td>
    </tr>} />
    {data.edges.length > 0 && <Paged items={data.edges} caption={copy.edgesTitle} header={<>
      {Object.values(copy.edgeColumns).map(label => <th scope="col" key={label}>{label}</th>)}
    </>} render={(edge: StructureGraphEdge, position: number) => {
      const from = nodeLabel(data.nodes[edge.source]!), to = nodeLabel(data.nodes[edge.target]!);
      return <tr key={position} class={selection?.kind === 'edge' && selection.position === position ? 'is-selected' : undefined}>
        <td><bdi>{from}</bdi></td><td><bdi>{to}</bdi></td>
        <td>{copy.relationships[edge.relationship]}{edge.recordedCycle && <> ({copy.inCycle})</>}</td>
        <td>{copy.resolutions[edge.resolution]}</td>
        <td>{edge.references}</td>
        <td><button type="button" onClick={() => focusDetails({ kind: 'edge', position })}>{textMessage(copy.inspectEdge, { from, to })}</button></td>
      </tr>;
    }} />}
  </>;
}
