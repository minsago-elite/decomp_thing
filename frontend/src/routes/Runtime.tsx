import { runtimeCopy as copy } from '../copy/runtime';
import { message as displayMessage } from '../shared/messages';
import { formatExactBytes } from '../jobs/metadataFormat';
import { useLayoutEffect, useState } from 'preact/hooks';
import type { BrowserSession } from '../session/session';
import { SchedulerSummary } from '../jobs/SchedulerSummary';
import { ProgressRetentionSummary } from '../jobs/ProgressRetentionSummary';
import type { BuildIdentity } from '../app/buildIdentity';

export default function Runtime({ identity, session = null }: { identity: BuildIdentity; session?: BrowserSession | null }) {
  const [state, setState] = useState(() => session?.snapshot());
  useLayoutEffect(() => {
    setState(session?.snapshot());
    return session?.subscribe(setState);
  }, [session]);
  const snapshot = state?.status === 'authenticated' ? state.runtime : null;
  return (
    <section aria-labelledby="runtime-title">
      <p class="eyebrow">{copy.application}</p>
      <h1 id="runtime-title">{copy.runtimeStatus}</h1>
      <section class="build-identity" aria-labelledby="build-identity-title">
        <h2 id="build-identity-title">{copy.pageBuildIdentity}</h2>
        <p>{copy.theseValuesIdentifyTheApplicationThatServedThisPage}</p>
        <dl>
          <dt>{copy.applicationVersion}</dt>
          <dd>{identity.applicationVersion ?? copy.unavailable}</dd>
          <dt>{copy.uiBuild}</dt>
          <dd>{identity.uiBuildId ? <code>{identity.uiBuildId}</code> : copy.unavailable}</dd>
        </dl>
      </section>
      {snapshot ? <section aria-labelledby="server-runtime-title">
        <h2 id="server-runtime-title">{copy.connectedServer}</h2>
        <p>{copy.reportedWhenTheLocalSessionWasCheckedOpeningThisView}</p>
        {snapshot.uiBuildId !== identity.uiBuildId && <p role="status" class="notice">{copy.theServerReportsADifferentUIBuildReloadTheApplication}</p>}
        <dl>
          <dt>{copy.readiness}</dt><dd>{snapshot.readiness}</dd>
          <dt>{copy.serverBuild}</dt><dd><code>{snapshot.applicationBuildId}</code></dd>
          <dt>{copy.serverInstance}</dt><dd>{snapshot.serverInstanceId ? <code>{snapshot.serverInstanceId}</code> : copy.notReported}</dd>
          <dt>{copy.java}</dt><dd>{snapshot.runtime.javaVersion}</dd>
          <dt>{copy.platform}</dt><dd>{snapshot.runtime.osName} / {snapshot.runtime.architecture}</dd>
          <dt>{copy.git}</dt><dd>{snapshot.runtime.gitVersion ?? copy.notReported}</dd>
          <dt>{copy.maximumUpload}</dt><dd>{snapshot.limits.maxUploadBytes === '0' ? copy.uploadsUnavailable : formatExactBytes(snapshot.limits.maxUploadBytes)}</dd>
        </dl>
        <SchedulerSummary scheduler={snapshot.runtime.scheduler} />
        <ProgressRetentionSummary retention={snapshot.runtime.progressRetention} />
        <h3>{copy.workflowCapabilities}</h3>
        {snapshot.capabilities.length === 0 ? <p>{copy.noCapabilitiesReported}</p> : <ul>
          {snapshot.capabilities.map(capability => <li key={capability.id}>
            <strong>{capability.id}</strong>: {capability.state}
            {capability.message && <p>{capability.message}</p>}
            {capability.reasonCode && <p>{displayMessage(copy.reason, { reason: <code>{capability.reasonCode}</code> })}</p>}
          </li>)}
        </ul>}
      </section> : <div class="notice" aria-labelledby="runtime-availability-title">
        <h2 id="runtime-availability-title">{copy.runtimeInformationIsNotConnected}</h2>
        <p>{copy.connectALocalSessionToSeeReportedToolAvailabilityAnd}</p>
      </div>}
    </section>
  );
}
