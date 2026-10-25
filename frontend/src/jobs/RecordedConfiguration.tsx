import { Fragment } from 'preact';
import type { Run } from '../api/generated';
import { runViewPath } from '../app/paths';
import { recordedConfigurationCopy as copy } from '../copy/attempt';

const flag = (value: boolean) => value ? copy.yes : copy.no;
const code = (value: string | number | null, missing: string = copy.notApplicable) =>
  value === null ? missing : <code>{value}</code>;

/** The admission record exactly as persisted; it describes this attempt, never the current server. */
export function RecordedConfiguration({ run, basePath }: { run: Run; basePath: string }) {
  const configuration = run.configuration;
  return <section aria-labelledby="recorded-configuration-title">
    <h2 id="recorded-configuration-title">{copy.title}</h2>
    <p>{copy.source}</p>
    {configuration === null ? <p>{copy.notRecorded}</p> : <>
      <dl class="job-facts">
        <dt>{copy.option}</dt><dd><code>{configuration.optionId}</code></dd>
        <dt>{copy.mode}</dt><dd><code>{configuration.mode}</code></dd>
        <dt>{copy.executesBinary}</dt><dd>{flag(configuration.executesBinary)}</dd>
        <dt>{copy.contactsAgent}</dt><dd>{flag(configuration.contactsAgent)}</dd>
        <dt>{copy.requiredTools}</dt><dd>{configuration.requiredTools.length === 0 ? copy.none
          : configuration.requiredTools.map((tool, index) => <Fragment key={tool}>{index > 0 && ', '}<code>{tool}</code></Fragment>)}</dd>
        <dt>{copy.input}</dt><dd><code>{configuration.input}</code></dd>
        <dt>{copy.limitsAdjustable}</dt><dd>{flag(configuration.limitsAdjustable)}</dd>
        <dt>{copy.profile}</dt><dd>{code(configuration.reconstruction?.profileId ?? null)}</dd>
        {configuration.reconstruction && <>
          <dt>{copy.profileDigest}</dt><dd><code>{configuration.reconstruction.profileSha256}</code></dd>
          <dt>{copy.contextBudget}</dt><dd>{configuration.reconstruction.maxContextCharacters === null ? copy.notApplicable
            : <code>{configuration.reconstruction.maxContextCharacters}</code>}</dd>
        </>}
      </dl>
      <h3>{copy.harness}</h3>
      {configuration.harness === null ? <p>{copy.noHarness}</p> : <>
        <dl class="job-facts">
          <dt>{copy.harnessKind}</dt><dd><code>{configuration.harness.kind}</code></dd>
          <dt>{copy.implementation}</dt><dd>{code(configuration.harness.implementationId, copy.unresolved)}</dd>
          <dt>{copy.contract}</dt><dd><code>{configuration.harness.agentContractVersion}</code></dd>
          <dt>{copy.protocol}</dt><dd>{code(configuration.harness.protocolVersion)}</dd>
          <dt>{copy.sdk}</dt><dd>{code(configuration.harness.sdkVersion)}</dd>
          <dt>{copy.configurationDigest}</dt><dd>{code(configuration.harness.configurationSha256)}</dd>
          <dt>{copy.status}</dt><dd>{configuration.harness.deprecated ? copy.deprecated : copy.current}</dd>
        </dl>
        <p>{copy.digestBoundary}</p>
      </>}
      {configuration.validation && <>
        <h3>{copy.validation}</h3>
        <dl class="job-facts">
          <dt>{copy.validationPreset}</dt><dd><code>{configuration.validation.presetId}</code></dd>
          <dt>{copy.validationCorpus}</dt><dd><code>{configuration.validation.corpusSha256}</code></dd>
          <dt>{copy.validationCount}</dt><dd>{configuration.validation.caseCount}</dd>
        </dl>
        <p>{copy.validationBoundary}</p>
      </>}
    </>}
    {(run.workflow === 'validate' || run.workflow === 'repair') && <p>
      <a href={runViewPath(basePath, run.jobId, run.runId, 'evidence')}>{copy.openValidators}</a></p>}
  </section>;
}
