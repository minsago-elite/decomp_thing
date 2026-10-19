import { homeCopy as copy } from '../copy/shell';
import type { BrowserSession } from '../session/session';
import { useSession } from '../session/useSession';
import { Upload } from '../jobs/Upload';
import { Dashboard } from '../jobs/Dashboard';
export default function Home({ basePath = '', session = null }: { basePath?: string; session?: BrowserSession | null }) {
  const state = useSession(session);
  return (
    <section aria-labelledby="workspace-title">
      <p class="eyebrow">{copy.reconstructionWorkspace}</p>
      <h1 id="workspace-title">{copy.yourWorkWithItsEvidence}</h1>
      <p class="lead">{copy.reviewReconstructedSourceInspectValidationEvidenceAndFollowEachRevision}</p>
      {session && <Upload basePath={basePath} session={session} />}
      {state?.status === 'authenticated' ? <Dashboard key={state.generation} basePath={basePath} /> : <div class="notice" aria-labelledby="availability-title">
        <h2 id="availability-title">{copy.theWorkbenchShellIsReady}</h2>
        <p>{copy.connectALocalSessionToBrowseUploadedJobsThePublic}</p>
        <p>{copy.existingCommandLineWorkflowsRemainAvailable}</p>
      </div>}
    </section>
  );
}
