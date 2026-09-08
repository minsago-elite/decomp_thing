import type { BrowserSession } from '../session/session';
import { Upload } from '../jobs/Upload';

export default function UploadPage({ basePath, session }: { basePath: string; session: BrowserSession | null }) {
  return <section aria-labelledby="upload-page-title">
    <h1 id="upload-page-title">Upload a binary</h1>
    <p>Create a persistent job from a supported ELF file. Uploading does not start analysis or reconstruction.</p>
    {session ? <Upload basePath={basePath} session={session} />
      : <p>Connect a local session to upload a binary.</p>}
  </section>;
}
