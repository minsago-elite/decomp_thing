import { useLayoutEffect, useState } from 'preact/hooks';
import type { BrowserSession } from '../session/session';
import { SchedulerSummary } from '../jobs/SchedulerSummary';
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
      <p class="eyebrow">Application</p>
      <h1 id="runtime-title">Runtime status</h1>
      <section class="build-identity" aria-labelledby="build-identity-title">
        <h2 id="build-identity-title">Page build identity</h2>
        <p>These values identify the application that served this page.</p>
        <dl>
          <dt>Application version</dt>
          <dd>{identity.applicationVersion ?? 'Unavailable'}</dd>
          <dt>UI build</dt>
          <dd>{identity.uiBuildId ? <code>{identity.uiBuildId}</code> : 'Unavailable'}</dd>
        </dl>
      </section>
      {snapshot ? <section aria-labelledby="server-runtime-title">
        <h2 id="server-runtime-title">Connected server</h2>
        <p>Reported when the local session was checked. Opening this view does not run tools or workflows.</p>
        {snapshot.uiBuildId !== identity.uiBuildId && <p role="status" class="notice">
          The server reports a different UI build. Reload the application to load its current views.
        </p>}
        <dl>
          <dt>Readiness</dt><dd>{snapshot.readiness}</dd>
          <dt>Server build</dt><dd><code>{snapshot.applicationBuildId}</code></dd>
          <dt>Java</dt><dd>{snapshot.runtime.javaVersion}</dd>
          <dt>Platform</dt><dd>{snapshot.runtime.osName} / {snapshot.runtime.architecture}</dd>
          <dt>Git</dt><dd>{snapshot.runtime.gitVersion ?? 'Not reported'}</dd>
          <dt>Maximum upload</dt><dd>{snapshot.limits.maxUploadBytes === '0' ? 'Uploads unavailable' : `${snapshot.limits.maxUploadBytes} bytes`}</dd>
        </dl>
        <SchedulerSummary scheduler={snapshot.runtime.scheduler} />
        <h3>Workflow capabilities</h3>
        {snapshot.capabilities.length === 0 ? <p>No capabilities reported.</p> : <ul>
          {snapshot.capabilities.map(capability => <li key={capability.id}>
            <strong>{capability.id}</strong>: {capability.state}
            {capability.message && <p>{capability.message}</p>}
            {capability.reasonCode && <p>Reason: <code>{capability.reasonCode}</code></p>}
          </li>)}
        </ul>}
      </section> : <div class="notice" aria-labelledby="runtime-availability-title">
        <h2 id="runtime-availability-title">Runtime information is not connected</h2>
        <p>Connect a local session to see reported tool availability and workflow capabilities.
          Opening this page does not run a tool or check a provider.</p>
      </div>}
    </section>
  );
}
