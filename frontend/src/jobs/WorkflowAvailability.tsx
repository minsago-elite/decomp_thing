import { Fragment } from 'preact';
import type { Capability, Job, Workflow } from '../api/generated';
import { jobCopy as copy } from '../copy/job';
import type { RuntimeSnapshot } from '../session/session';
import { message } from '../shared/messages';
import { StateMark, capabilityTone } from '../shared/StateMark';
import { reportedCapabilityFacts } from './capabilityFacts';

import { MetadataReceipt } from '../shared/MetadataReceipt';
import type { ReceiptTime } from '../shared/receiptTime';

const workflows = ['explore', 'reconstruct', 'build', 'validate', 'repair'] as const;
const labels = {
  explore: copy.exploration,
  reconstruct: copy.reconstruction,
  build: copy.build,
  validate: copy.validation,
  repair: copy.repair,
} satisfies Record<Workflow, string>;

type JobFacts = Pick<Job, 'acceptedRevisionId'>;

function CapabilityReport({ capability, job }: { capability: Capability; job?: JobFacts | undefined }) {
  return <li>
    <p class="capability-heading">{message(copy.capabilityReport, {
      identity: <code>{capability.id}</code>, state: <StateMark tone={capabilityTone(capability.state)}>{capability.state}</StateMark>,
    })}</p>
    {capability.message && <p>{capability.message}</p>}
    {capability.reasonCode && <p>{message(copy.capabilityReason, {
      reason: <code>{capability.reasonCode}</code>,
    })}</p>}
    <dl class="job-facts">
      {reportedCapabilityFacts(capability).map(fact => <Fragment key={fact.key}>
        <dt>{fact.label}</dt><dd>{fact.value}</dd>
      </Fragment>)}
      {job && capability.launch && <>
        <dt>{copy.launchRequiredTools}</dt>
        <dd>{capability.launch.requiredTools.join(', ') || copy.launchNoRequiredTools}</dd>
        <dt>{copy.launchRecordedInput}</dt>
        <dd>{inputPrerequisite(capability.launch.input, job)}</dd>
      </>}
    </dl>
    {job && !capability.launch && <p>{copy.launchIntentNotReported}</p>}
  </li>;
}

function inputPrerequisite(input: NonNullable<Capability['launch']>['input'], job: JobFacts) {
  const revision = job.acceptedRevisionId;
  switch (input) {
    case 'none': return copy.launchInputNone;
    case 'accepted-optional': return revision
      ? message(copy.launchInputOptionalPresent, { revision: <code>{revision}</code> }) : copy.launchInputOptionalAbsent;
    case 'recorded-required': return revision
      ? message(copy.launchInputRequiredPresent, { revision: <code>{revision}</code> })
      : copy.launchInputRequiredUnknown;
  }
}

/** Display the last authenticated report. It cannot admit work or select a harness. */
export function WorkflowAvailability({ runtime, receipt, job }: { runtime: RuntimeSnapshot; receipt?: ReceiptTime; job?: JobFacts }) {
  const generalCapabilities = runtime.capabilities.filter(capability => capability.workflows.length === 0);
  return <section aria-labelledby="job-workflow-availability-title">
    <h3 id="job-workflow-availability-title">{copy.workflowAvailabilityForThisJob}</h3>
    <p>{message(copy.reportedReadiness, { readiness: <code>{runtime.readiness}</code> })}</p>
    <p>{copy.capabilitiesAreTheLastSessionReport}</p>
    <MetadataReceipt kind="runtime" receipt={receipt} />
    <p>{job ? copy.launchJobRecordAge : copy.jobPrerequisitesNotReported}</p>
    <p>{copy.capabilityLimitsBoundary}</p>
    {generalCapabilities.length > 0 && <section aria-labelledby="job-general-capabilities-title">
      <h4 id="job-general-capabilities-title">{copy.generalCapabilityReports}</h4>
      <p>{copy.capabilitiesWithoutWorkflow}</p>
      <ul class="capability-reports" aria-label={copy.generalCapabilityReports}>
        {generalCapabilities.map(capability => <CapabilityReport key={capability.id} capability={capability} />)}
      </ul>
    </section>}
    <ul class="availability-list" aria-label={copy.workflowAvailability}>
      {workflows.map(workflow => {
        const capabilities = runtime.capabilities.filter(capability => capability.workflows.includes(workflow));
        return <li key={workflow}>
          <h4>{labels[workflow]}</h4>
          <div>
            <p><StateMark tone="blocked">{copy.startUnavailable}</StateMark></p>
            {capabilities.length === 0 ? <p>{copy.noCapabilityForThisWorkflow}</p> : <ul class="capability-reports">
              {capabilities.map(capability => <CapabilityReport key={capability.id} capability={capability} job={job} />)}
            </ul>}
          </div>
        </li>;
      })}
    </ul>
  </section>;
}
