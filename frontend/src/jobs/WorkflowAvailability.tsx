import { Fragment } from 'preact';
import type { Capability, Workflow } from '../api/generated';
import { jobCopy as copy } from '../copy/job';
import type { RuntimeSnapshot } from '../session/session';
import { message } from '../shared/messages';
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

function CapabilityReport({ capability }: { capability: Capability }) {
  return <li>
    <p>{message(copy.capabilityReport, {
      identity: <code>{capability.id}</code>, state: <code>{capability.state}</code>,
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
    <p>{copy.capabilityLimitsBoundary}</p>
  </li>;
}

/** Display the last authenticated report. It cannot admit work or select a harness. */
export function WorkflowAvailability({ runtime, receipt }: { runtime: RuntimeSnapshot; receipt?: ReceiptTime }) {
  const generalCapabilities = runtime.capabilities.filter(capability => capability.workflows.length === 0);
  return <section aria-labelledby="job-workflow-availability-title">
    <h3 id="job-workflow-availability-title">{copy.workflowAvailabilityForThisJob}</h3>
    <p>{message(copy.reportedReadiness, { readiness: <code>{runtime.readiness}</code> })}</p>
    <p>{copy.capabilitiesAreTheLastSessionReport}</p>
    <MetadataReceipt kind="runtime" receipt={receipt} />
    <p>{copy.jobPrerequisitesNotReported}</p>
    {generalCapabilities.length > 0 && <section aria-labelledby="job-general-capabilities-title">
      <h4 id="job-general-capabilities-title">{copy.generalCapabilityReports}</h4>
      <p>{copy.capabilitiesWithoutWorkflow}</p>
      <ul aria-label={copy.generalCapabilityReports}>
        {generalCapabilities.map(capability => <CapabilityReport key={capability.id} capability={capability} />)}
      </ul>
    </section>}
    <ul aria-label={copy.workflowAvailability}>
      {workflows.map(workflow => {
        const capabilities = runtime.capabilities.filter(capability => capability.workflows.includes(workflow));
        return <li key={workflow}>
          <h4>{labels[workflow]}</h4>
          <p><strong>{copy.startUnavailable}</strong></p>
          {capabilities.length === 0 ? <p>{copy.noCapabilityForThisWorkflow}</p> : <ul>
            {capabilities.map(capability => <CapabilityReport key={capability.id} capability={capability} />)}
          </ul>}
        </li>;
      })}
    </ul>
  </section>;
}
