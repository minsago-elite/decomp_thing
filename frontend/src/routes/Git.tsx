import { gitCopy as copy } from '../copy/git';
import type { BrowserSession } from '../session/session';
import { useSession } from '../session/useSession';
import { jobPath } from '../app/paths';
import { GitWorkspace } from '../git/GitWorkspace';

export default function Git({ jobId, basePath, session }: { jobId: string; basePath: string; session: BrowserSession | null }) {
  const state = useSession(session);
  return <section aria-labelledby="git-route-title">
    <h1 id="git-route-title">{copy.title}</h1>
    <a href={jobPath(basePath, jobId)}>{copy.jobLink}</a>
    {state?.status === 'authenticated' && session && /^[0-9a-f]{32}$/.test(jobId)
      ? <GitWorkspace key={`${state.generation}/${jobId}`} jobId={jobId} basePath={basePath} session={session} capabilities={state.runtime.capabilities} />
      : <p>{copy.connect}</p>}
  </section>;
}
