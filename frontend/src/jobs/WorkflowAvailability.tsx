import { Fragment } from 'preact';
import type { Capability, Workflow } from '../api/generated';
import { jobCopy as copy } from '../copy/job';
import type { RuntimeSnapshot } from '../session/session';
import { message } from '../shared/messages';
import { StateMark, capabilityTone } from '../shared/StateMark';
import { launchStartable, reportedCapabilityFacts } from './capabilityFacts';

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

function CapabilityReport({ capability }: { capability: Capability }) {
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
    </dl>
  </li>;
}

/** Display the last authenticated report. It neither admits work nor selects a harness; the start form does. */
export function WorkflowAvailability({ runtime, receipt }: { runtime: RuntimeSnapshot; receipt?: ReceiptTime }) {
  const generalCapabilities = runtime.capabilities.filter(capability => capability.workflows.length === 0);
  return <section aria-labelledby="job-workflow-availability-title">
    <h3 id="job-workflow-availability-title">{copy.workflowAvailabilityForThisJob}</h3>
    <p>{message(copy.reportedReadiness, { readiness: <code>{runtime.readiness}</code> })}</p>
    <p>{copy.capabilitiesAreTheLastSessionReport}</p>
    <MetadataReceipt kind="runtime" receipt={receipt} />
    <p>{copy.jobPrerequisitesNotReported}</p>
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
        const launchable = capabilities.filter(capability => capability.launch != null);
        return <li key={workflow}>
          <h4>{labels[workflow]}</h4>
          <div>
            {launchable.length === 0 ? <p><StateMark tone="blocked">{copy.startUnavailable}</StateMark></p>
              : launchable.some(launchStartable) ? <p><StateMark tone="settled">{copy.startReady}</StateMark></p>
              : <p><StateMark tone="blocked">{copy.startNotReady}</StateMark></p>}
            {capabilities.length === 0 ? <p>{copy.noCapabilityForThisWorkflow}</p> : <ul class="capability-reports">
              {capabilities.map(capability => <CapabilityReport key={capability.id} capability={capability} />)}
            </ul>}
          </div>
        </li>;
      })}
    </ul>
  </section>;
}
