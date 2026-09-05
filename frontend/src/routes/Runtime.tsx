import type { BuildIdentity } from '../app/buildIdentity';

export default function Runtime({ identity }: { identity: BuildIdentity }) {
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
      <div class="notice" aria-labelledby="runtime-availability-title">
        <h2 id="runtime-availability-title">Runtime information is not connected</h2>
        <p>
          Tool availability and workflow capabilities will be reported by the server.
          Opening this page does not run a tool or check a provider.
        </p>
      </div>
    </section>
  );
}
