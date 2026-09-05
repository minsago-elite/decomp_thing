import { useLayoutEffect, useMemo, useRef, useState } from 'preact/hooks';
import { LocationProvider, Route, Router, useLocation } from 'preact-iso/router';
import Home from '../routes/Home';
import UploadPage from '../routes/UploadPage';
import { NotFound } from '../routes/NotFound';
import { ViewBoundary } from '../shared/ViewBoundary';
import { AssetRecoveryNotice } from '../shared/AssetRecoveryNotice';
import { SessionStatus } from '../session/SessionStatus';
import type { BrowserSession } from '../session/session';
import { lazyRoute } from '../shared/LazyRoute';
import { createAssetRecovery, observeAssetFailures } from './assetRecovery';
import type { AssetRecovery } from './assetRecovery';
import { UNKNOWN_BUILD } from './buildIdentity';
import type { BuildIdentity } from './buildIdentity';
import { appPath } from './paths';
import mark from './mark.svg';

type ShellProps = {
  basePath: string;
  identity: BuildIdentity;
  recovery: AssetRecovery;
  reload: () => void;
  session: BrowserSession | null;
};

function Shell({ basePath, identity, recovery, reload, session }: ShellProps) {
  const Job = useMemo(() => lazyRoute(() => import('../routes/Job'), recovery), [recovery]);
  const Runtime = useMemo(() => lazyRoute(() => import('../routes/Runtime'), recovery), [recovery]);
  const location = useLocation();
  const main = useRef<HTMLElement>(null);
  const [loading, setLoading] = useState(false);
  const homePath = appPath(basePath, '/');
  const runtimePath = appPath(basePath, '/runtime');
  const atHome = location.path === (basePath || '/') || location.path === homePath;
  const uploadPath = appPath(basePath, '/upload');
  const isJob = location.path.startsWith(`${basePath}/jobs/`) && location.path.slice(`${basePath}/jobs/`.length).indexOf('/') < 0;
  const pageTitle = atHome ? 'Jobs' : location.path === uploadPath ? 'Upload a binary'
    : location.path === runtimePath ? 'Runtime status' : isJob ? 'Job overview' : 'Page unavailable';
  useLayoutEffect(() => {
    document.title = `${pageTitle} · Decomp Workbench`;
    main.current?.focus({ preventScroll: recovery.snapshot() !== 'ready' });
  }, [pageTitle, location.path, recovery]);

  function viewReady() {
    setLoading(false);
    main.current?.focus({ preventScroll: recovery.snapshot() !== 'ready' });
  }

  return (
    <>
      <a class="skip-link" href="#main">Skip to content</a>
      <header class="app-header">
        <a class="brand" href={homePath} aria-label="Decomp Workbench home">
          <img src={mark} alt="" width="28" height="28" />
          <span>Decomp <strong>Workbench</strong></span>
        </a>
        <span class="build-label">Early preview</span>
      </header>
      <AssetRecoveryNotice recovery={recovery} identity={identity} reload={reload} />
      {session && <SessionStatus session={session} />}
      <div class="app-layout">
        <nav class="app-nav" aria-label="Main navigation">
          <a href={homePath} aria-current={atHome ? 'page' : undefined}>Workspace</a>
          <a href={uploadPath} aria-current={location.path === uploadPath ? 'page' : undefined}>Upload</a>
          <a href={runtimePath} aria-current={location.path === runtimePath ? 'page' : undefined}>
            Runtime status
          </a>
        </nav>
        <main id="main" ref={main} tabIndex={-1} aria-busy={loading}>
          <p class="sr-only" role="status">{loading ? 'Opening view…' : ''}</p>
          {!atHome && <nav aria-label="Breadcrumbs">
            <ol class="breadcrumbs"><li><a href={homePath}>All jobs</a></li><li aria-current="page">{pageTitle}</li></ol>
          </nav>}
          <ViewBoundary key={location.path}>
            <Router onLoadStart={() => setLoading(true)} onLoadEnd={viewReady} onRouteChange={viewReady}>
              <Route path={homePath} component={Home} basePath={basePath} session={session} />
              <Route path={uploadPath} component={UploadPage} basePath={basePath} session={session} />
              <Route path={runtimePath} component={Runtime} identity={identity} session={session} />
              <Route path={`${basePath}/jobs/:jobId`} component={Job} basePath={basePath} session={session} />
              <Route default component={NotFound} homePath={homePath} />
            </Router>
          </ViewBoundary>
        </main>
      </div>
      <footer class="app-footer">Source and validation evidence stay connected to their revision.</footer>
    </>
  );
}

export function App({ basePath = '', identity = UNKNOWN_BUILD, recovery: suppliedRecovery, reload = () => window.location.reload(), session = null }: {
  basePath?: string;
  identity?: BuildIdentity;
  recovery?: AssetRecovery;
  reload?: () => void;
  session?: BrowserSession | null;
}) {
  const ownedRecovery = useMemo(createAssetRecovery, []);
  const recovery = suppliedRecovery ?? ownedRecovery;
  useLayoutEffect(() => observeAssetFailures(window, recovery), [recovery]);
  return (
    <ViewBoundary>
      <LocationProvider scope={`${basePath}/`}>
        <Shell basePath={basePath} identity={identity} recovery={recovery} reload={reload} session={session} />
      </LocationProvider>
    </ViewBoundary>
  );
}
