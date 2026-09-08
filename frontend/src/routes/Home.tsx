import type { BrowserSession } from '../session/session';
import { useSession } from '../session/useSession';
import { Upload } from '../jobs/Upload';
import { Dashboard } from '../jobs/Dashboard';
export default function Home({ basePath = '', session = null }: { basePath?: string; session?: BrowserSession | null }) {
  const state = useSession(session);
  return (
    <section aria-labelledby="workspace-title">
      <p class="eyebrow">Reconstruction workspace</p>
      <h1 id="workspace-title">Your work, with its evidence</h1>
      <p class="lead">
        Review reconstructed source, inspect validation evidence, and follow each revision.
      </p>
      {session && <Upload basePath={basePath} session={session} />}
      {state?.status === 'authenticated' ? <Dashboard basePath={basePath} /> : <div class="notice" aria-labelledby="availability-title">
        <h2 id="availability-title">The workbench shell is ready</h2>
        <p>
          Connect a local session to browse uploaded jobs. The public shell does not
          read jobs or start workflows.
        </p>
        <p>Existing command-line workflows remain available.</p>
      </div>}
    </section>
  );
}
