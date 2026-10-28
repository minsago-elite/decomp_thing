import { homeCopy as copy, panelBoundaryCopy } from '../copy/shell';
import { PanelBoundary } from '../shared/PanelBoundary';
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
      {session && <PanelBoundary name={panelBoundaryCopy.names.upload}><Upload basePath={basePath} session={session} /></PanelBoundary>}
      {state?.status === 'authenticated' ? <PanelBoundary name={panelBoundaryCopy.names.dashboard}><Dashboard key={state.generation} basePath={basePath} draftOwner={session} /></PanelBoundary> : <div class="notice" aria-labelledby="availability-title">
        <h2 id="availability-title">{copy.theWorkbenchShellIsReady}</h2>
        <p>{copy.connectALocalSessionToBrowseUploadedJobsThePublic}</p>
        <p>{copy.existingCommandLineWorkflowsRemainAvailable}</p>
      </div>}
    </section>
  );
}
