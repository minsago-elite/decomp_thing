import { uploadPageCopy as copy } from '../copy/shell';
import type { BrowserSession } from '../session/session';
import { Upload } from '../jobs/Upload';

export default function UploadPage({ basePath, session }: { basePath: string; session: BrowserSession | null }) {
  return <section aria-labelledby="upload-page-title">
    <h1 id="upload-page-title">{copy.uploadABinary}</h1>
    <p>{copy.createAPersistentJobFromASupportedELFFileUploading}</p>
    {session ? <Upload basePath={basePath} session={session} />
      : <p>{copy.connectALocalSessionToUploadABinary}</p>}
  </section>;
}
