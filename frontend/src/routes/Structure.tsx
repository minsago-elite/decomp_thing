import { useEffect, useRef, useState } from 'preact/hooks';
import { useLocation } from 'preact-iso/router';
import lazy from 'preact-iso/lazy';
import { structureCopy as copy } from '../copy/structure';
import { ApiClientError } from '../api/errors';
import { message } from '../shared/messages';
import type { EntityDetail, FunctionInventory, ModuleDetail, ModuleInventory, StructureEntity, StructureReference,
  StructureReferences, StructureText, StructureUnrecordedEntity } from '../api/generated';
import { structureView } from '../copy/structureTitles';
import type { StructureView } from '../copy/structureTitles';
import { appPath, runPath, sourceFilePath } from '../app/paths';
import type { SourceSelection } from '../app/paths';
import { structureItemPath, structureListPath } from '../structure/paths';
import type { StructureItem } from '../structure/paths';
import { usePrivateTransport } from '../session/PrivateTransport';
import { useSession } from '../session/useSession';
import type { BrowserSession } from '../session/session';
import { DEFAULT_FUNCTION_QUERY, EVIDENCE_CLASSES, EXTRACTION_LABELS, MODULE_PAGE_LIMIT, OWNED_KINDS, OWNED_PAGE_LIMIT,
  OWNERSHIP_STATES, bindStructure, withField, functionLocation, functionReadRoute, functionSearch, listLocation,
  structureReadRoute } from '../structure/navigation';
import type { FunctionQuery } from '../structure/navigation';
import { Frame, useStructureRead } from '../structure/Frame';
import { graphLocation, graphPath } from '../graph/query';
import { scorecardLocation } from '../structure/scorecardQuery';

// Relationship drawing and scorecards load only when opened, after the structure route itself.
const Graph = lazy(() => import('../graph/GraphRoute'));
const Scorecard = lazy(() => import('../structure/Scorecard'));
const ITEM: Record<'function' | 'global' | 'type', StructureItem> = { function: 'functions', global: 'globals', type: 'types' };

function EntityName({ basePath, selected, entity, version }: {
  basePath: string; selected: SourceSelection; entity: { kind: 'function' | 'global' | 'type'; selector: string | null; name: string | null; entityId: string };
  version: string;
}) {
  const label = <bdi>{entity.name ?? entity.entityId}</bdi>;
  return entity.selector ? <a href={structureItemPath(basePath, selected, ITEM[entity.kind], entity.selector, version)}>{label}</a>
    : <span title={copy.notAddressable}>{label}</span>;
}

function ModuleLink({ basePath, selected, moduleId, selector, version }: {
  basePath: string; selected: SourceSelection; moduleId: string | null; selector: string | null; version: string;
}) {
  if (moduleId === null) return null;
  return selector ? <a href={structureItemPath(basePath, selected, 'modules', selector, version)}><bdi>{moduleId}</bdi></a> : <bdi>{moduleId}</bdi>;
}

function Ownership({ entity, basePath, selected, version }: { entity: StructureEntity; basePath: string; selected: SourceSelection; version: string }) {
  return entity.ownership === 'owned'
    ? <ModuleLink basePath={basePath} selected={selected} moduleId={entity.moduleId} selector={entity.moduleSelector} version={version} />
    : <>{copy.ownership[entity.ownership]}</>;
}

function EntityTable({ items, basePath, selected, version, caption }: {
  items: (StructureEntity | StructureUnrecordedEntity)[]; basePath: string; selected: SourceSelection; version: string; caption: string;
}) {
  return <div class="structure-table"><table>
    <caption>{caption}</caption>
    <thead><tr>
      <th scope="col">{copy.columns.address}</th><th scope="col">{copy.columns.name}</th><th scope="col">{copy.columns.identity}</th>
      <th scope="col">{copy.columns.extraction}</th><th scope="col">{copy.columns.evidence}</th><th scope="col">{copy.columns.module}</th>
      <th scope="col">{copy.columns.calls}</th>
    </tr></thead>
    <tbody>{items.map(item => item.recorded ? <tr key={item.entityId}>
      <td><code>{item.address ?? copy.notRecorded}</code></td>
      <td><EntityName basePath={basePath} selected={selected} entity={item} version={version} />
        {item.nameCollision && <> <span class="structure-flag">{copy.collision}</span></>}</td>
      <td><code>{item.entityId}</code></td>
      <td>{copy.extraction[item.extractionStatus]}</td>
      <td>{copy.evidence[item.evidenceState]}</td>
      <td><Ownership entity={item} basePath={basePath} selected={selected} version={version} /></td>
      <td>{item.callCount ?? '—'}</td>
    </tr> : <tr key={item.entityId}>
      <td>—</td><td>{copy.unrecordedEntity}</td><td><code>{item.entityId}</code></td><td colSpan={4}>{copy.notRecorded}</td>
    </tr>)}</tbody>
  </table></div>;
}

function EvidenceMeanings() {
  return <details>
    <summary>{copy.evidenceTitle}</summary>
    <ul>{EVIDENCE_CLASSES.map(value => <li key={value}>{copy.evidenceMeanings[value]}</li>)}</ul>
  </details>;
}

function Functions({ selected, basePath, search }: { selected: SourceSelection; basePath: string; search: string }) {
  const location = useLocation();
  const { client } = usePrivateTransport(basePath);
  const query = functionLocation(search);
  const [draft, setDraft] = useState<FunctionQuery>(() => withField(query, 'cursor', ''));
  const results = useRef<HTMLHeadingElement>(null);
  const moveFocus = useRef(false);
  const key = [selected.jobId, selected.runId, selected.revisionId, search].join('/');
  const [read, refresh] = useStructureRead<FunctionInventory>(key, async signal =>
    bindStructure((await client.get('functionInventory', functionReadRoute(selected, query), { signal })).data, selected));
  useEffect(() => { setDraft(withField(query, 'cursor', '')); }, [search]);
  useEffect(() => {
    if (read.state !== 'loading' && moveFocus.current) { moveFocus.current = false; results.current?.focus(); }
  }, [read]);
  const data = read.state === 'ready' ? read.value : null;
  const go = (next: FunctionQuery, cursor?: string) => {
    moveFocus.current = true;
    location.route(structureListPath(basePath, selected, 'functions', functionSearch(withField(next, 'cursor', cursor ?? ''))));
  };
  const offset = query.cursor ? Number(query.cursor.split('_')[1]) : 0;
  const unscoped = withField(withField(query, 'module', ''), 'cursor', '');
  return <Frame selected={selected} data={data} read={read} onRefresh={() => { moveFocus.current = true; if (query.cursor) go(query); else refresh(); }}
    navigation={<p><a href={structureListPath(basePath, selected, 'modules')}>{copy.browseModules}</a></p>}>
    <form class="job-filters" aria-label={copy.filters} onSubmit={event => { event.preventDefault(); go({ ...draft }); }}>
      <label>{copy.search}<input name="search" type="search" maxLength={256} value={draft.search ?? ''} aria-describedby="structure-search-hint"
        onInput={event => { const value = event.currentTarget.value; setDraft(current => withField(current, 'search', value)); }} /></label>
      <p id="structure-search-hint">{copy.searchHint}</p>
      <label>{copy.status}<select name="status" value={draft.status ?? ''} onChange={event => {
        const value = event.currentTarget.value as FunctionQuery['status'] | '';
        setDraft(current => withField(current, 'status', value));
      }}><option value="">{copy.any}</option>{EXTRACTION_LABELS.map(value => <option key={value} value={value}>{copy.extraction[value]}</option>)}</select></label>
      <label>{copy.evidenceFilter}<select name="evidence" value={draft.evidence ?? ''} onChange={event => {
        const value = event.currentTarget.value as FunctionQuery['evidence'] | '';
        setDraft(current => withField(current, 'evidence', value));
      }}><option value="">{copy.any}</option>{EVIDENCE_CLASSES.map(value => <option key={value} value={value}>{copy.evidence[value]}</option>)}</select></label>
      <label>{copy.ownershipFilter}<select name="ownership" value={draft.ownership ?? ''} onChange={event => {
        const value = event.currentTarget.value as FunctionQuery['ownership'] | '';
        setDraft(current => withField(current, 'ownership', value));
      }}><option value="">{copy.any}</option>{OWNERSHIP_STATES.map(value => <option key={value} value={value}>{copy.ownership[value]}</option>)}</select></label>
      <label>{copy.sort}<select name="sort" value={draft.sort} onChange={event => { const sort = event.currentTarget.value as FunctionQuery['sort']; setDraft(current => ({ ...current, sort })); }}>
        {(['address', 'name', 'id'] as const).map(value => <option key={value} value={value}>{copy.sorts[value]}</option>)}</select></label>
      <label>{copy.order}<select name="order" value={draft.order} onChange={event => { const order = event.currentTarget.value as FunctionQuery['order']; setDraft(current => ({ ...current, order })); }}>
        {(['asc', 'desc'] as const).map(value => <option key={value} value={value}>{copy.orders[value]}</option>)}</select></label>
      <div class="job-actions"><button type="submit">{copy.apply}</button>
        <button type="button" onClick={() => { setDraft(DEFAULT_FUNCTION_QUERY); go(DEFAULT_FUNCTION_QUERY); }}>{copy.reset}</button></div>
    </form>
    {query.module && <p>{message(copy.moduleFilter, { module: <bdi>{query.module}</bdi> })}{' '}
      <a href={structureListPath(basePath, selected, 'functions', functionSearch(unscoped))}>{copy.clearModule}</a></p>}
    <EvidenceMeanings />
    <h2 ref={results} tabIndex={-1}>{copy.results}</h2>
    {data?.state === 'available' && data.matchedFunctions !== null && data.totalFunctions !== null && <>
      <p role="status">{data.matchedFunctions === 0 ? message(copy.noResults, { total: data.totalFunctions })
        : message(copy.resultsRange, { first: offset + 1, last: offset + data.items.length,
          matched: data.matchedFunctions, total: data.totalFunctions })}</p>
      {data.items.length > 0 && <EntityTable items={data.items} basePath={basePath} selected={selected} version={data.structureVersion} caption={copy.functionsTitle} />}
    </>}
    <nav class="job-actions" aria-label={copy.pages}>
      <button type="button" disabled={read.state === 'loading' || query.cursor === undefined} onClick={() => go(query)}>{copy.first}</button>
      <button type="button" disabled={read.state === 'loading' || !data?.page.nextCursor} onClick={() => {
        if (data?.page.nextCursor) go(query, data.page.nextCursor);
      }}>{copy.next}</button>
    </nav>
  </Frame>;
}

function Modules({ selected, basePath, search }: { selected: SourceSelection; basePath: string; search: string }) {
  const location = useLocation();
  const { client } = usePrivateTransport(basePath);
  const { cursor, version } = listLocation(search);
  const results = useRef<HTMLHeadingElement>(null);
  const moveFocus = useRef(false);
  const key = [selected.jobId, selected.runId, selected.revisionId, search].join('/');
  const [read, refresh] = useStructureRead<ModuleInventory>(key, async signal => bindStructure((await client.get('moduleInventory',
    structureReadRoute(selected, 'modules', null, { limit: MODULE_PAGE_LIMIT, ...(cursor ? { cursor } : {}), ...(version ? { version } : {}) }), { signal })).data, selected, version));
  useEffect(() => { if (read.state !== 'loading' && moveFocus.current) { moveFocus.current = false; results.current?.focus(); } }, [read]);
  const data = read.state === 'ready' ? read.value : null;
  const offset = cursor ? Number(cursor.split('_')[1]) : 0;
  const summary = data?.summary;
  return <Frame selected={selected} data={data} read={read} pinned={version !== undefined} onRefresh={() => {
    if (cursor || version) { moveFocus.current = true; location.route(structureListPath(basePath, selected, 'modules')); } else refresh();
  }} navigation={<p><a href={structureListPath(basePath, selected, 'functions')}>{copy.browseFunctions}</a></p>}>
    {summary && <>
      <div class="structure-table"><table>
        <caption>{copy.summaryTitle}</caption>
        <thead><tr><th scope="col">{copy.summaryColumns.kind}</th><th scope="col">{copy.summaryColumns.total}</th>
          {EVIDENCE_CLASSES.map(value => <th scope="col" key={value}>{copy.evidence[value]}</th>)}
          <th scope="col">{copy.summaryColumns.owned}</th><th scope="col">{copy.summaryColumns.unowned}</th><th scope="col">{copy.summaryColumns.ambiguous}</th></tr></thead>
        <tbody>{(['functions', 'globals', 'types'] as const).map(kind => <tr key={kind}>
          <th scope="row">{copy.summaryKinds[kind]}</th><td>{summary[kind].total}</td>
          {EVIDENCE_CLASSES.map(value => <td key={value}>{summary[kind].evidence[value]}</td>)}
          <td>{summary[kind].ownership.owned}</td><td>{summary[kind].ownership.unowned}</td><td>{summary[kind].ownership.ambiguous}</td>
        </tr>)}</tbody>
      </table></div>
      <h2>{copy.diagnostics}</h2>
      <dl class="job-facts">
        <dt>{copy.modulesCount}</dt><dd>{summary.modules}</dd>
        <dt>{copy.modulesAccepted}</dt><dd>{summary.modulesDeclaredAccepted}</dd>
        <dt>{copy.cycles}</dt><dd>{summary.dependencyCycles}</dd>
        <dt>{copy.unknownReferences}</dt><dd>{summary.unknownPlanReferences}</dd>
        <dt>{copy.collisions}</dt><dd>{summary.nameCollisions}</dd>
        <dt>{copy.unresolvedCalls}</dt><dd>{summary.unresolvedCallTargets}</dd>
        <dt>{copy.unresolvedGlobals}</dt><dd>{summary.unresolvedGlobalReferences}</dd>
      </dl>
      <EvidenceMeanings />
    </>}
    <h2 ref={results} tabIndex={-1}>{copy.moduleResults}</h2>
    {data?.state === 'available' && (data.totalModules === null ? <p>{copy.noModules}</p> : <>
      <p role="status">{message(copy.moduleRange, { first: data.items.length ? offset + 1 : 0, last: offset + data.items.length, total: data.totalModules })}</p>
      <div class="structure-table"><table>
        <caption>{copy.modulesTitle}</caption>
        <thead><tr>{Object.values(copy.moduleColumns).map(label => <th scope="col" key={label}>{label}</th>)}</tr></thead>
        <tbody>{data.items.map(module => <tr key={module.moduleId}>
          <td><ModuleLink basePath={basePath} selected={selected} moduleId={module.moduleId} selector={module.selector} version={data.structureVersion} />
            {module.inDependencyCycle && <> <span class="structure-flag">{copy.inCycle}</span></>}</td>
          <td>{module.functionCount}</td><td>{module.globalCount}</td><td>{module.typeCount}</td>
          <td>{copy.declarations[module.implementationDeclaration]}</td>
          <td>{message(copy.progress, module.functionEvidence)}</td>
        </tr>)}</tbody>
      </table></div>
    </>)}
    <nav class="job-actions" aria-label={copy.modulePages}>
      <button type="button" disabled={read.state === 'loading' || cursor === undefined} onClick={() => { moveFocus.current = true; location.route(structureListPath(basePath, selected, 'modules')); }}>{copy.first}</button>
      <button type="button" disabled={read.state === 'loading' || !data?.page.nextCursor} onClick={() => {
        if (data?.page.nextCursor) { moveFocus.current = true; location.route(structureListPath(basePath, selected, 'modules', `?cursor=${data.page.nextCursor}`)); }
      }}>{copy.next}</button>
    </nav>
  </Frame>;
}

function SourceLink({ basePath, selected, label, path, fileId }: { basePath: string; selected: SourceSelection; label: string; path: string | null; fileId: string | null }) {
  if (path === null) return null;
  return <><dt>{label}</dt><dd>{fileId ? <a href={sourceFilePath(basePath, selected, fileId)}><bdi>{path}</bdi></a>
    : message(copy.sourceUnavailable, { path: <bdi>{path}</bdi> })}</dd></>;
}

function Module({ selected, basePath, selector, search }: { selected: SourceSelection; basePath: string; selector: string; search: string }) {
  const location = useLocation();
  const { client } = usePrivateTransport(basePath);
  const { cursor, version, kind = 'functions' } = listLocation(search, ['kind']);
  const results = useRef<HTMLHeadingElement>(null);
  const moveFocus = useRef(false);
  const key = [selected.jobId, selected.runId, selected.revisionId, selector, search].join('/');
  const [read, refresh] = useStructureRead<ModuleDetail>(key, async signal => bindStructure((await client.get('moduleDetail',
    structureReadRoute(selected, 'modules', selector, { kind, limit: OWNED_PAGE_LIMIT, ...(cursor ? { cursor } : {}), ...(version ? { version } : {}) }), { signal })).data, selected, version));
  useEffect(() => { if (read.state !== 'loading' && moveFocus.current) { moveFocus.current = false; results.current?.focus(); } }, [read]);
  const data = read.state === 'ready' ? read.value : null;
  const module = data?.module, owned = data?.owned;
  const base = structureItemPath(basePath, selected, 'modules', selector);
  const route = (next: Record<string, string>) => {
    moveFocus.current = true;
    const values = new URLSearchParams({ ...(version ? { structureVersion: version } : {}), ...next });
    location.route(`${base}${values.toString() ? `?${values.toString()}` : ''}`);
  };
  const offset = cursor ? Number(cursor.split('_')[1]) : 0;
  const kindLabel = copy.ownedKinds[kind as typeof OWNED_KINDS[number]];
  return <Frame selected={selected} data={data} read={read} pinned={version !== undefined} onRefresh={() => {
    if (cursor || version) { moveFocus.current = true; location.route(`${base}?kind=${kind}`); } else refresh();
  }} navigation={<p><a href={structureListPath(basePath, selected, 'modules')}>{copy.returnModules}</a></p>}>
    {module && data && <>
      <h2><bdi>{module.moduleId}</bdi></h2>
      <dl class="job-facts">
        <dt>{copy.moduleColumns.declaration}</dt><dd>{copy.declarations[module.implementationDeclaration]}</dd>
        <dt>{copy.moduleColumns.progress}</dt><dd>{message(copy.progress, module.functionEvidence)}</dd>
        <dt>{copy.moduleColumns.functions}</dt><dd>{module.functionCount}</dd>
        <dt>{copy.moduleColumns.globals}</dt><dd>{module.globalCount}</dd>
        <dt>{copy.moduleColumns.types}</dt><dd>{module.typeCount}</dd>
        <SourceLink basePath={basePath} selected={selected} label={copy.implementationFile} path={module.implementationPath} fileId={module.implementationFileId} />
        <SourceLink basePath={basePath} selected={selected} label={copy.interfaceFile} path={module.interfacePath} fileId={module.interfaceFileId} />
        {module.cycle.total > 0 && <><dt>{copy.cycleMembers}</dt><dd><ul>{module.cycle.items.map(item => <li key={item.moduleId}>
          <ModuleLink basePath={basePath} selected={selected} moduleId={item.moduleId} selector={item.selector} version={data.structureVersion} /></li>)}</ul>
          {module.cycle.total > module.cycle.items.length && message(copy.boundedList, { shown: module.cycle.items.length, total: module.cycle.total })}</dd></>}
        {module.boundaryEvidence.total > 0 && <><dt>{copy.boundaryEvidence}</dt><dd><ul>{module.boundaryEvidence.items.map((item, index) =>
          <li key={index}><code>{item.text}</code></li>)}</ul>
          {module.boundaryEvidence.total > module.boundaryEvidence.items.length && message(copy.boundedList, { shown: module.boundaryEvidence.items.length, total: module.boundaryEvidence.total })}</dd></>}
      </dl>
      {module.selector && <p><a href={structureListPath(basePath, selected, 'functions', functionSearch({ ...DEFAULT_FUNCTION_QUERY, module: module.selector }))}>{copy.showInInventory}</a>
        {' '}<a href={graphPath(basePath, selected, { view: 'modules', focus: module.selector }, data.structureVersion)}>{copy.exploreModules}</a></p>}
      <nav class="job-actions" aria-label={copy.ownedTitle}>
        {OWNED_KINDS.map(value => <a key={value} href={`${base}?${new URLSearchParams({ ...(version ? { structureVersion: version } : {}), kind: value })}`}
          aria-current={value === kind ? 'page' : undefined}>{copy.ownedKinds[value]}</a>)}
      </nav>
    </>}
    <h2 ref={results} tabIndex={-1}>{copy.ownedTitle}</h2>
    {owned && data && (owned.total === 0 ? <p role="status">{message(copy.noOwned, { kind: kindLabel.toLowerCase() })}</p> : <>
      <p role="status">{message(copy.ownedRange, { first: offset + 1, last: offset + owned.items.length, total: owned.total, kind: kindLabel.toLowerCase() })}</p>
      <EntityTable items={owned.items} basePath={basePath} selected={selected} version={data.structureVersion} caption={kindLabel} />
      <nav class="job-actions" aria-label={copy.pages}>
        <button type="button" disabled={read.state === 'loading' || cursor === undefined} onClick={() => route({ kind })}>{copy.first}</button>
        <button type="button" disabled={read.state === 'loading' || !owned.page.nextCursor} onClick={() => {
          if (owned.page.nextCursor) route({ kind, cursor: owned.page.nextCursor });
        }}>{copy.next}</button>
      </nav>
    </>)}
  </Frame>;
}

function Preview({ label, value }: { label: string; value: { recorded: boolean; preview: StructureText | null } }) {
  return <section>
    <h3>{label}</h3>
    {value.preview ? <>
      <pre class="structure-preview">{value.preview.text}</pre>
      <p>{value.preview.truncated ? message(copy.textTruncated, { shown: [...value.preview.text].length, total: value.preview.characters })
        : message(copy.textComplete, { total: value.preview.characters })}</p>
    </> : <p>{copy.textNotRecorded}</p>}
  </section>;
}

function References({ title, value, basePath, selected, version }: {
  title: string; value: StructureReferences | null; basePath: string; selected: SourceSelection; version: string;
}) {
  if (value === null) return null;
  return <section>
    <h3>{title}</h3>
    {value.total === 0 ? <p>{copy.noReferences}</p> : <>
      <ul>{value.items.map((item: StructureReference) => <li key={`${item.kind}/${item.entityId}`}>
        {item.resolution === 'recorded' ? <><EntityName basePath={basePath} selected={selected} entity={item} version={version} /> (<code>{item.entityId}</code>)</>
          : message(copy.noRecord, { id: <code>{item.entityId}</code> })}
      </li>)}</ul>
      {value.total > value.items.length && <p>{message(copy.boundedList, { shown: value.items.length, total: value.total })}</p>}
    </>}
  </section>;
}

function Entity({ selected, basePath, kind, selector, search }: {
  selected: SourceSelection; basePath: string; kind: 'function' | 'global' | 'type'; selector: string; search: string;
}) {
  const location = useLocation();
  const { client } = usePrivateTransport(basePath);
  const { version } = listLocation(search);
  const key = [selected.jobId, selected.runId, selected.revisionId, kind, selector, search].join('/');
  const [read, refresh] = useStructureRead<EntityDetail>(key, async signal => {
    const data = bindStructure((await client.get('entityDetail',
      structureReadRoute(selected, ITEM[kind], selector, version ? { version } : {}), { signal })).data, selected, version);
    if (data.entity && (data.entity.kind !== kind || data.entity.selector !== selector)) throw new ApiClientError('invalid_response');
    return data;
  });
  const data = read.state === 'ready' ? read.value : null;
  const entity = data?.entity;
  return <Frame selected={selected} data={data} read={read} pinned={version !== undefined}
    onRefresh={() => { if (version) location.route(structureItemPath(basePath, selected, ITEM[kind], selector)); else refresh(); }}
    navigation={<p><a href={structureListPath(basePath, selected, 'functions')}>{copy.returnFunctions}</a></p>}>
    {entity && data && <>
      <h2><bdi>{entity.name ?? entity.entityId}</bdi></h2>
      {entity.kind === 'function' && entity.selector && <p>
        <a href={graphPath(basePath, selected, { view: 'calls', focus: entity.selector }, data.structureVersion)}>{copy.exploreCalls}</a></p>}
      <dl class="job-facts" aria-label={copy.entityFacts}>
        <dt>{copy.kind}</dt><dd>{entity.kind}</dd>
        <dt>{copy.identity}</dt><dd><code>{entity.entityId}</code></dd>
        <dt>{copy.name}</dt><dd>{entity.name === null ? copy.notRecorded : <bdi>{entity.name}</bdi>}</dd>
        <dt>{copy.address}</dt><dd><code>{entity.address ?? copy.notRecorded}</code></dd>
        <dt>{copy.extractionLabel}</dt><dd>{copy.extraction[entity.extractionStatus]}</dd>
        <dt>{copy.evidenceClass}</dt><dd>{copy.evidenceMeanings[entity.evidenceState]}</dd>
        <dt>{copy.module}</dt><dd><Ownership entity={entity} basePath={basePath} selected={selected} version={data.structureVersion} /></dd>
        <dt>{copy.implementationUnresolved}</dt><dd>{entity.implementationUnresolved ? copy.yes : copy.no}</dd>
        <dt>{copy.reportedUnresolved}</dt><dd>{entity.reportedUnresolved ? copy.yes : copy.no}</dd>
        {entity.byteEvidence && <><dt>{copy.byteEvidence}</dt><dd>{copy.byteEvidenceStates[entity.byteEvidence]}</dd></>}
      </dl>
      {entity.texts.map(text => <Preview key={text.field} label={copy.textFields[text.field]} value={text} />)}
      <section>
        <h3>{copy.sourcesTitle}</h3>
        {entity.sources.implementationPath || entity.sources.sharedInterfacePath ? <dl class="job-facts">
          <SourceLink basePath={basePath} selected={selected} label={copy.implementationFile} path={entity.sources.implementationPath} fileId={entity.sources.implementationFileId} />
          <SourceLink basePath={basePath} selected={selected} label={copy.interfaceFile} path={entity.sources.interfacePath} fileId={entity.sources.interfaceFileId} />
          <SourceLink basePath={basePath} selected={selected} label={copy.sharedInterface} path={entity.sources.sharedInterfacePath} fileId={entity.sources.sharedInterfaceFileId} />
        </dl> : <p>{copy.noSources}</p>}
      </section>
      {entity.strings && <section>
        <h3>{copy.strings}</h3>
        {entity.strings.total === 0 ? <p>{copy.noReferences}</p> : <>
          <ul>{entity.strings.items.map((item, index) => <li key={index}><code>{item.text}</code></li>)}</ul>
          {entity.strings.total > entity.strings.items.length && <p>{message(copy.boundedList, { shown: entity.strings.items.length, total: entity.strings.total })}</p>}
        </>}
      </section>}
      <References title={copy.calls} value={entity.calls} basePath={basePath} selected={selected} version={data.structureVersion} />
      <References title={copy.calledBy} value={entity.calledBy} basePath={basePath} selected={selected} version={data.structureVersion} />
      <References title={copy.referencedGlobals} value={entity.referencedGlobals} basePath={basePath} selected={selected} version={data.structureVersion} />
      <References title={copy.referencedBy} value={entity.referencedBy} basePath={basePath} selected={selected} version={data.structureVersion} />
      <section>
        <h3>{copy.collisionsTitle}</h3>
        {entity.collisions.total === 0 ? <p>{copy.noCollisions}</p> : <ul>{entity.collisions.items.map(item => <li key={`${item.kind}/${item.entityId}`}>
          {item.kind}: <EntityName basePath={basePath} selected={selected} entity={item} version={data.structureVersion} /> (<code>{item.entityId}</code>)</li>)}</ul>}
      </section>
    </>}
  </Frame>;
}

const TITLES: Record<StructureView, string> = {
  functions: copy.functionsTitle, modules: copy.modulesTitle, module: copy.moduleTitle,
  function: copy.entityTitles.function, global: copy.entityTitles.global, type: copy.entityTitles.type,
  graph: copy.graphTitle, scorecard: copy.scorecardTitle,
};

export function structureTitle(view: StructureView): string { return TITLES[view]; }

export default function Structure({ jobId, runId, revisionId, section, selector, basePath, session }: {
  jobId: string; runId: string; revisionId: string; section: string; selector?: string; basePath: string; session: BrowserSession | null;
}) {
  const state = useSession(session);
  const location = useLocation();
  const selected = { jobId, runId, revisionId };
  const search = new URL(location.url, 'https://structure.invalid').search;
  const view = structureView(section, selector !== undefined);
  let valid = view !== null && /^[0-9a-f]{32}$/.test(jobId) && [runId, revisionId, ...(selector === undefined ? [] : [selector])]
    .every(value => /^[A-Za-z0-9][A-Za-z0-9_-]{0,127}$/.test(value));
  try {
    if (view === 'functions') functionLocation(search);
    else if (view === 'graph') graphLocation(search);
    else if (view === 'scorecard') scorecardLocation(search);
    else listLocation(search, view === 'module' ? ['kind'] : []);
    if (view !== 'functions' && view !== 'modules' && view !== 'module' && view !== 'graph' && view !== 'scorecard'
      && search.includes('cursor=')) valid = false;
  } catch { valid = false; }
  const generation = state?.status === 'authenticated' ? state.generation : 0;
  const keyed = `${generation}/${jobId}/${runId}/${revisionId}/${view ?? ''}/${selector ?? ''}`;
  return <section class="source-navigation structure-view" aria-labelledby="structure-title">
    <h1 id="structure-title">{view ? TITLES[view] : copy.invalidTitle}</h1>
    {valid && view ? <>
      <p><a href={runPath(basePath, jobId, runId)}>{copy.returnAttempt}</a></p>
      {session && state?.status === 'authenticated'
        ? view === 'functions' ? <Functions key={keyed} selected={selected} basePath={basePath} search={search} />
          : view === 'modules' ? <Modules key={keyed} selected={selected} basePath={basePath} search={search} />
            : view === 'module' ? <Module key={keyed} selected={selected} basePath={basePath} selector={selector ?? ''} search={search} />
              : view === 'graph' ? <Graph key={keyed} selected={selected} basePath={basePath} search={search} />
                : view === 'scorecard' ? <Scorecard key={keyed} selected={selected} basePath={basePath} search={search} />
                  : <Entity key={keyed} selected={selected} basePath={basePath} kind={view} selector={selector ?? ''} search={search} />
        : <p>{copy.connect}</p>}
    </> : <><p role="alert">{copy.invalid}</p><a href={appPath(basePath, '/')}>{copy.returnJobs}</a></>}
  </section>;
}
