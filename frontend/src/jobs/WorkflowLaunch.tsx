import { Fragment } from 'preact';
import { useEffect, useMemo, useRef, useState } from 'preact/hooks';
import { ApiClientError, withApiFailureReference } from '../api/client';
import type { Capability, ExecutionLimits, HarnessFacts, Job, Run, Workflow, WorkflowLaunch as Launch, WorkflowStart } from '../api/generated';
import { appPath, runPath } from '../app/paths';
import { launchCopy as copy } from '../copy/launch';
import { jobCopy } from '../copy/job';
import { usePrivateTransport } from '../session/PrivateTransport';
import type { BrowserSession, RuntimeSnapshot } from '../session/session';
import { message, textMessage } from '../shared/messages';

type LaunchOption = Capability & { launch: Launch; limits: ExecutionLimits };
type LimitKey = keyof ExecutionLimits;

const order: Workflow[] = ['explore', 'reconstruct', 'build', 'validate', 'repair'];
const workflowLabels = {
  explore: jobCopy.exploration, reconstruct: jobCopy.reconstruction, build: jobCopy.build,
  validate: jobCopy.validation, repair: jobCopy.repair,
} satisfies Record<Workflow, string>;
const modeLabels = { tools: copy.modeTools, agent: copy.modeAgent, 'evidence-only': copy.modeEvidenceOnly } satisfies Record<Launch['mode'], string>;
// Labels stay transport-neutral; the harness kind itself is shown as provenance in each option's facts.
const harnessLabels = { acp: copy.modeAgent, 'legacy-openai': copy.modeLegacyAgent, builtin: copy.modeBuiltinAgent } satisfies Record<HarnessFacts['kind'], string>;
const modeLabel = (launch: Launch) => launch.harness ? harnessLabels[launch.harness.kind] : modeLabels[launch.mode];
/** Fixed actionable text per server reason code; server message text and configuration are never interpreted. */
const requirements: Partial<Record<string, string>> = {
  HARNESS_NOT_CONFIGURED: copy.requirementHarnessNotConfigured, HARNESS_CONFIGURATION_INVALID: copy.requirementHarnessInvalid,
  HARNESS_UNSUPPORTED: copy.requirementHarnessUnsupported, AGENT_PREFLIGHT_FAILED: copy.requirementPreflightFailed,
  SANDBOX_HELPER_MISSING: copy.requirementSandbox, GHIDRA_MISSING: copy.requirementGhidra,
  PROBE_TIMEOUT: copy.requirementUnknown, PROBE_FAILED: copy.requirementUnknown, PREREQUISITES_UNKNOWN: copy.requirementUnknown,
};
// Owning issues for the built-in harness: the harness parity tracker and each workflow's built-in delivery.
const issue = (number: number) => `https://github.com/minsago-elite/decomp_thing/issues/${number}`;
const builtinIssues: Partial<Record<Workflow, number>> = { reconstruct: 76, repair: 77 };
const toolLabels = {
  sandbox: copy.toolSandbox, ghidra: copy.toolGhidra, 'agent-harness': copy.toolAgentHarness,
  'c-toolchain': copy.toolCToolchain, angr: copy.toolAngr,
} satisfies Record<Launch['requiredTools'][number], string>;
const limitKeys: LimitKey[] = ['wallClockMs', 'idleMs', 'maxOutputBytes', 'maxToolCalls'];
const decimal = /^(?:0|[1-9][0-9]{0,19})$/;

/** Only server-described options with exactly one workflow and explicit default limits can be offered. */
export function launchOptions(runtime: RuntimeSnapshot): LaunchOption[] {
  return runtime.capabilities
    .filter((capability): capability is LaunchOption => capability.launch !== null && capability.limits !== null
      && capability.workflows.length === 1)
    .sort((left, right) => order.indexOf(left.workflows[0]!) - order.indexOf(right.workflows[0]!));
}

function limitProblem(key: LimitKey, value: string, ceiling: string, values: Record<LimitKey, string>): string | null {
  const positive = key !== 'maxToolCalls';
  // JavaScript's end anchor can stop before a final line break; require the whole value.
  if (decimal.exec(value)?.[0] !== value || BigInt(value) > BigInt(ceiling) || (positive && BigInt(value) === 0n)) {
    return textMessage(positive ? copy.positiveLimit : copy.invalidLimit, { value: ceiling });
  }
  if (key === 'idleMs' && decimal.exec(values.wallClockMs)?.[0] === values.wallClockMs && BigInt(value) > BigInt(values.wallClockMs)) {
    return copy.idleExceedsWall;
  }
  return null;
}

function failureMessage(failure: unknown): { text: string; refresh: boolean; renew: boolean } {
  const status = failure instanceof ApiClientError ? failure.status : undefined;
  const code = failure instanceof ApiClientError ? failure.serverCode : undefined;
  const result = (text: string, refresh = false, renew = false) => ({ text: withApiFailureReference(text, failure), refresh, renew });
  if (status === 401 || status === 403) return result(copy.sessionLost);
  if (status === 412) return result(copy.versionConflict, true, true);
  if (status === 409 && code === 'IDEMPOTENCY_CONFLICT') return result(copy.keyConflict, false, true);
  if (status === 409) return result(copy.activeConflict, true, true);
  if (status === 429) return result(copy.atCapacity);
  if (status === 422 && (code === 'INPUT_REVISION_UNAVAILABLE' || code === 'INPUT_REVISION_REQUIRED')) return result(copy.revisionUnavailable, true, true);
  if (status === 422 || status === 400) return result(copy.invalidConfiguration, true, true);
  if (status === 503 && code === 'CAPABILITY_UNAVAILABLE') return result(copy.capabilityUnavailable, true, true);
  // A lost or unknown answer may have been recorded; the unchanged intent resends its original key.
  return result(copy.uncertain);
}

interface Revision { id: string; label: string }

function useRevisions(basePath: string, job: Job, needed: boolean): { revisions: Revision[] | null; failed: boolean } {
  const { client } = usePrivateTransport(basePath);
  const [state, setState] = useState<{ key: string; revisions: Revision[] | null; failed: boolean } | null>(null);
  const key = `${job.jobId}/${job.version}`;
  useEffect(() => {
    if (!needed) return;
    const controller = new AbortController();
    setState({ key, revisions: null, failed: false });
    void client.get('runs', `/jobs/${job.jobId}/runs`, { signal: controller.signal }).then(response => {
      if (controller.signal.aborted) return;
      const revisions: Revision[] = [];
      if (job.acceptedRevisionId) revisions.push({ id: job.acceptedRevisionId, label: textMessage(copy.inputAcceptedRevision, { revision: job.acceptedRevisionId }) });
      for (const run of response.data.items) {
        if (run.jobId !== job.jobId) throw new Error('binding');
        if (run.state === 'completed' && run.resultRevisionId && !revisions.some(item => item.id === run.resultRevisionId)) {
          revisions.push({ id: run.resultRevisionId, label: textMessage(copy.inputCandidateRevision, { revision: run.resultRevisionId, run: run.runId }) });
        }
      }
      setState({ key, revisions, failed: false });
    }).catch(() => { if (!controller.signal.aborted) setState({ key, revisions: null, failed: true }); });
    return () => { controller.abort(); };
  }, [client, job.jobId, job.version, job.acceptedRevisionId, key, needed]);
  return state?.key === key ? state : { revisions: null, failed: false };
}

function HarnessFactList({ harness }: { harness: HarnessFacts }) {
  return <>
    <p>{message(copy.harnessIdentity, { kind: <code>{harness.kind}</code>,
      implementation: harness.implementationId === null ? copy.harnessImplementationUnresolved : <code>{harness.implementationId}</code> })}</p>
    {harness.protocolVersion !== null && <p>{textMessage(copy.harnessProtocol, { version: harness.protocolVersion })}</p>}
    <p>{harness.operations.length === 0 ? copy.harnessNoOperations
      : textMessage(copy.harnessOperations, { operations: harness.operations.map(workflow => workflowLabels[workflow]).join(', ') })}</p>
    <p>{harness.deprecated ? copy.harnessDeprecated : copy.harnessCurrent}</p>
    <p>{copy.harnessNeverSubstituted}</p>
  </>;
}

/** The actionable requirement behind an unavailable option, with where an operator acts on it. */
function Requirement({ option, basePath }: { option: LaunchOption; basePath: string }) {
  if (option.state === 'supported' || option.reasonCode === null) return null;
  const workflow = option.workflows[0]!;
  if (option.reasonCode === 'BUILTIN_HARNESS_NOT_INTEGRATED') {
    const owner = builtinIssues[workflow];
    return <p>{textMessage(copy.requirementHeading, { text: textMessage(copy.requirementBuiltin, { workflow: workflowLabels[workflow] }) })}{' '}
      <a href={issue(79)} rel="noreferrer">{copy.requirementBuiltinTracker}</a>
      {owner !== undefined && <>{' '}<a href={issue(owner)} rel="noreferrer">{textMessage(copy.requirementBuiltinWorkflow, { workflow: workflowLabels[workflow] })}</a></>}</p>;
  }
  const text = requirements[option.reasonCode];
  return text === undefined ? null
    : <p>{textMessage(copy.requirementHeading, { text })} <a href={appPath(basePath, '/runtime')}>{copy.openRuntime}</a></p>;
}

function OptionFacts({ option }: { option: LaunchOption }) {
  const { launch } = option;
  return <>
    <p>{launch.executesBinary ? copy.executesBinary : copy.doesNotExecuteBinary}</p>
    <p>{launch.contactsAgent
      ? textMessage(copy.contactsAgent, { version: option.agentContractVersion ?? '?' })
      : copy.doesNotContactAgent}</p>
    {launch.requiredTools.length > 0 && <p>{textMessage(copy.requiredTools, { tools: launch.requiredTools.map(tool => toolLabels[tool]).join(', ') })}</p>}
    {launch.harness && <HarnessFactList harness={launch.harness} />}
    {launch.mode === 'evidence-only' && <p>{copy.evidenceOnlyLimitations}</p>}
  </>;
}

/**
 * Capability-driven launch form. Every option, default and bound comes from the last authenticated
 * report; the server revalidates all of them. One intent keeps one idempotency key, so a resend
 * after a lost answer replays rather than starting twice.
 */
export function WorkflowLaunch({ job, runtime, basePath, session, onRefresh, onStarted }: {
  job: Job; runtime: RuntimeSnapshot; basePath: string; session: Pick<BrowserSession, 'csrf'>;
  onRefresh: () => void; onStarted: (path: string) => void;
}) {
  const { client } = usePrivateTransport(basePath);
  const options = useMemo(() => launchOptions(runtime), [runtime]);
  const [selectedId, setSelectedId] = useState<string | null>(null);
  const selected = options.find(option => option.id === selectedId && option.state === 'supported') ?? null;
  const [limits, setLimits] = useState<Record<LimitKey, string> | null>(null);
  const [inputRevisionId, setInputRevisionId] = useState<string>('');
  const [pending, setPending] = useState(false);
  const [notice, setNotice] = useState<{ text: string; refresh: boolean; alert: boolean } | null>(null);
  const [intent, setIntent] = useState<{ signature: string; key: string } | null>(null);
  const [startedPath, setStartedPath] = useState<string | null>(null);
  const active = useRef<AbortController | null>(null);
  const jobBusy = job.status === 'queued' || job.status === 'running';
  const { revisions, failed: revisionsFailed } = useRevisions(basePath, job, selected?.launch.input === 'recorded-required'
    || selected?.launch.input === 'accepted-optional');
  useEffect(() => () => { active.current?.abort(); active.current = null; }, []);

  function choose(option: LaunchOption) {
    if (pending) return;
    setSelectedId(option.id); setLimits({ ...option.limits }); setInputRevisionId(''); setNotice(null);
  }
  const values = selected && limits ? limits : null;
  const problems = selected && values ? Object.fromEntries(limitKeys.map(key =>
    [key, limitProblem(key, values[key], selected.limits[key], values)])) as Record<LimitKey, string | null> : null;
  const inputMissing = selected?.launch.input === 'recorded-required' && inputRevisionId === '';
  const body: WorkflowStart | null = selected && values && problems && limitKeys.every(key => problems[key] === null) && !inputMissing ? {
    workflow: selected.workflows[0]!, inputRevisionId: inputRevisionId === '' ? null : inputRevisionId,
    harnessCapabilityId: selected.launch.harnessCapabilityId,
    limits: selected.launch.limitsAdjustable ? { ...values } : { ...selected.limits },
  } : null;
  const signature = body ? JSON.stringify([job.jobId, job.version, body]) : null;

  async function submit(event: Event) {
    event.preventDefault();
    if (!body || !signature || pending || active.current || jobBusy) return;
    const csrfToken = session.csrf();
    if (!csrfToken) { setNotice({ text: copy.sessionLost, refresh: false, alert: true }); return; }
    const key = intent?.signature === signature ? intent.key : crypto.randomUUID().replaceAll('-', '');
    setIntent({ signature, key });
    const controller = new AbortController(); active.current = controller;
    setPending(true); setNotice({ text: copy.starting, refresh: false, alert: false });
    try {
      const response = await client.post('run', `/jobs/${job.jobId}/runs`, 'workflowStartRequest', body, {
        csrfToken, ifMatch: `"${job.version}"`, idempotencyKey: key, signal: controller.signal,
      });
      if (controller.signal.aborted) return;
      const run: Run = response.data;
      if (run.jobId !== job.jobId || run.workflow !== body.workflow) throw new ApiClientError('invalid_response');
      const path = runPath(basePath, job.jobId, run.runId);
      setNotice({ text: textMessage(copy.startedOpening, { run: run.runId }), refresh: false, alert: false });
      setStartedPath(path);
      onStarted(path);
    } catch (failure: unknown) {
      if (controller.signal.aborted) return;
      const result = failureMessage(failure);
      if (result.renew) setIntent(null);
      setNotice({ text: result.text, refresh: result.refresh, alert: true });
    } finally {
      if (active.current === controller) { active.current = null; setPending(false); }
    }
  }

  if (options.length === 0) return <section aria-labelledby="workflow-launch-title">
    <h3 id="workflow-launch-title">{copy.startAWorkflow}</h3>
    <p>{copy.noLaunchOptions}</p>
  </section>;
  return <section aria-labelledby="workflow-launch-title">
    <h3 id="workflow-launch-title">{copy.startAWorkflow}</h3>
    <p>{copy.launchIntroduction}</p>
    {jobBusy && <p role="note">{copy.activeAttempt} {job.latestRunId && <a href={runPath(basePath, job.jobId, job.latestRunId)}>{copy.openActiveAttempt}</a>}</p>}
    <form class="workflow-launch" onSubmit={event => { void submit(event); }} aria-busy={pending}>
      <fieldset disabled={pending}>
        <legend>{copy.workflowOption}</legend>
        {options.map(option => {
          const id = `launch-${option.id}`;
          const ready = option.state === 'supported';
          return <div class="launch-option" key={option.id}>
            <input type="radio" name="workflow-option" id={id} value={option.id} disabled={!ready}
              checked={selected?.id === option.id} aria-describedby={`${id}-facts`} onChange={() => { choose(option); }} />
            <label for={id}>{textMessage(copy.optionLabel, { workflow: workflowLabels[option.workflows[0]!], mode: modeLabel(option.launch) })}</label>
            <div id={`${id}-facts`} class="launch-facts">
              <p>{message(copy.optionState, { state: <code>{option.state}</code> })}</p>
              {!ready && <p>{option.message ? textMessage(copy.optionUnavailable, { reason: option.message }) : copy.optionUnavailableWithoutReason}
                {option.reasonCode && <> <code>{option.reasonCode}</code></>}</p>}
              <Requirement option={option} basePath={basePath} />
              <OptionFacts option={option} />
            </div>
          </div>;
        })}
      </fieldset>
      {!selected ? <p>{copy.selectAnOption}</p> : values && problems && <fieldset disabled={pending}>
        <legend>{copy.settings}</legend>
        <h4>{copy.inputRevision}</h4>
        {selected.launch.input === 'none' ? <p>{copy.inputNone}</p> : <>
          {selected.launch.input === 'recorded-required' && <p id="launch-input-help">{copy.inputRequired}</p>}
          {revisions === null && !revisionsFailed && <p role="status">{copy.loadingRevisions}</p>}
          {revisionsFailed && <p role="alert">{copy.revisionsUnavailable}</p>}
          {revisions !== null && selected.launch.input === 'recorded-required' && revisions.length === 0 && <p>{copy.noRecordedRevisions}</p>}
          {revisions !== null && (revisions.length > 0 || selected.launch.input === 'accepted-optional') && <>
            <label for="launch-input">{copy.inputRevision}</label>
            <select id="launch-input" value={inputRevisionId} required={selected.launch.input === 'recorded-required'}
              aria-describedby={selected.launch.input === 'recorded-required' ? 'launch-input-help' : undefined}
              onChange={event => { setInputRevisionId(event.currentTarget.value); }}>
              {selected.launch.input === 'recorded-required' ? <option value="">{copy.chooseRevision}</option> : <option value="">{copy.inputUploaded}</option>}
              {revisions.filter(revision => selected.launch.input === 'recorded-required' || revision.id === job.acceptedRevisionId)
                .map(revision => <option key={revision.id} value={revision.id}>{revision.label}</option>)}
            </select>
          </>}
        </>}
        <h4>{copy.limits}</h4>
        <p>{selected.launch.limitsAdjustable ? copy.limitsAdjustable : copy.limitsFixed}</p>
        {selected.launch.limitsAdjustable ? limitKeys.map(key => <div class="launch-limit" key={key}>
          <label for={`launch-${key}`}>{copy[key]}</label>
          <input id={`launch-${key}`} type="text" inputMode="numeric" autoComplete="off" value={values[key]}
            aria-invalid={problems[key] ? 'true' : undefined} aria-describedby={`launch-${key}-help`}
            onInput={event => { const next = event.currentTarget.value; setLimits(previous => previous && { ...previous, [key]: next }); }} />
          <p id={`launch-${key}-help`} class={problems[key] ? 'field-error' : undefined}>
            {problems[key] ?? textMessage(copy.atMost, { value: selected.limits[key] })}</p>
        </div>) : <dl class="job-facts">
          {limitKeys.map(key => <Fragment key={key}><dt>{copy[key]}</dt><dd><code>{selected.limits[key]}</code></dd></Fragment>)}
        </dl>}
      </fieldset>}
      {body && <section aria-labelledby="launch-summary-title" class="launch-summary">
        <h4 id="launch-summary-title">{copy.summary}</h4>
        <p>{copy.summaryIntroduction}</p>
        <dl class="job-facts">
          <dt>{copy.summaryWorkflow}</dt><dd><code>{body.workflow}</code></dd>
          <dt>{copy.summaryOption}</dt><dd><code>{selected?.id}</code></dd>
          <dt>{copy.summaryHarness}</dt><dd>{body.harnessCapabilityId ? <code>{body.harnessCapabilityId}</code> : copy.summaryNoHarness}</dd>
          {selected?.launch.harness && <><dt>{copy.summaryHarnessImplementation}</dt><dd>{textMessage(copy.summaryHarnessResolvedAtStart, {
            kind: selected.launch.harness.kind, implementation: selected.launch.harness.implementationId ?? copy.harnessImplementationUnresolved })}</dd></>}
          <dt>{copy.summaryInput}</dt><dd>{body.inputRevisionId ? <code>{body.inputRevisionId}</code> : copy.inputUploaded}</dd>
          <dt>{copy.summaryLimits}</dt><dd>{textMessage(copy.summaryLimitValues, { wall: body.limits.wallClockMs, idle: body.limits.idleMs,
            output: body.limits.maxOutputBytes, tools: body.limits.maxToolCalls })}</dd>
        </dl>
      </section>}
      <button type="submit" disabled={!body || pending || jobBusy}>
        {textMessage(copy.start, { workflow: selected ? workflowLabels[selected.workflows[0]!] : copy.workflowOption })}</button>
    </form>
    <div aria-live="polite">
      {notice && <p role={notice.alert ? 'alert' : 'status'}>{notice.text}</p>}
      {notice?.refresh && <button type="button" onClick={onRefresh}>{copy.refreshJob}</button>}
      {startedPath && <a href={startedPath}>{copy.openStartedAttempt}</a>}
    </div>
  </section>;
}
