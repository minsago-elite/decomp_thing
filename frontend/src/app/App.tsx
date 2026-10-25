import { appCopy as copy } from '../copy/shell';
import { sourceTitleCopy } from '../copy/sourceTitles';
import { message as displayMessage, textMessage } from '../shared/messages';
import { useLayoutEffect, useMemo, useRef, useState } from 'preact/hooks';
import { LocationProvider, Route, Router, useLocation } from 'preact-iso/router';
import { NotFound } from '../routes/NotFound';
import { ViewBoundary } from '../shared/ViewBoundary';
import { AssetRecoveryNotice } from '../shared/AssetRecoveryNotice';
import { PrivateSessionContext } from '../session/PrivateTransport';
import { SessionStatus } from '../session/SessionStatus';
import { useBrowserAvailability } from '../session/useBrowserAvailability';
import type { BrowserSession } from '../session/session';
import { lazyRoute } from '../shared/LazyRoute';
import { createAssetRecovery, observeAssetFailures } from './assetRecovery';
import type { AssetRecovery } from './assetRecovery';
import { UNKNOWN_BUILD } from './buildIdentity';
import type { BuildIdentity } from './buildIdentity';
import { appPath } from './paths';
import { DisplayPreferences } from './DisplayPreferences';
import mark from './mark.svg';

type ShellProps = {
  basePath: string;
  identity: BuildIdentity;
  recovery: AssetRecovery;
  reload: () => void;
  session: BrowserSession | null;
};

/** Browser connectivity is a hint; it never establishes freshness or server-work lifetime. */
function ConnectionNotice() {
  const availability = useBrowserAvailability();
  if (!availability.hasBeenOffline) return null;
  return <aside class="connection-notice notice" role="status" aria-label={copy.connectionStatus}>
    <h2>{availability.online ? copy.refreshLoadedInformation : copy.browserReportsOffline}</h2>
    <p>{availability.online
      ? copy.theBrowserReportsAConnectionAgainPreviouslyLoadedInformationMay
      : copy.previouslyLoadedInformationMayBeOutOfDateReconnectAnd}</p>
    {!availability.online && <p>{copy.serverWorkMayContinueWhileThisPageIsDisconnected}</p>}
  </aside>;
}

function Shell({ basePath, identity, recovery, reload, session }: ShellProps) {
  // Every route, including the workspace landing page, loads on demand so the initial
  // closure stays the shell, session and transport (#622).
  const Home = useMemo(() => lazyRoute(() => import('../routes/Home'), recovery), [recovery]);
  const UploadPage = useMemo(() => lazyRoute(() => import('../routes/UploadPage'), recovery), [recovery]);
  const Job = useMemo(() => lazyRoute(() => import('../routes/Job'), recovery), [recovery]);
  const RunHistory = useMemo(() => lazyRoute(() => import('../routes/RunHistory'), recovery), [recovery]);
  const Run = useMemo(() => lazyRoute(() => import('../routes/Run'), recovery), [recovery]);
  const Runtime = useMemo(() => lazyRoute(() => import('../routes/Runtime'), recovery), [recovery]);
  const Sources = useMemo(() => lazyRoute(() => import('../routes/Sources'), recovery), [recovery]);
  const Git = useMemo(() => lazyRoute(() => import('../routes/Git'), recovery), [recovery]);
  const location = useLocation();
  const main = useRef<HTMLElement>(null);
  const navigation = useRef<HTMLElement>(null);
  const navigationToggle = useRef<HTMLButtonElement>(null);
  const pendingNavigationFocus = useRef<'toggle' | 'link' | null>(null);
  const focusedPath = useRef<string | null>(null);
  // A history traversal keeps the viewport restored by the browser. Route focus
  // still announces its heading, without scrolling that heading into view again.
  const historyFocusPath = useRef<string | null>(null);
  useLayoutEffect(() => {
    const traversed = () => {
      historyFocusPath.current = window.location.pathname.replace(/\/+$/g, '') || '/';
    };
    window.addEventListener('popstate', traversed, true);
    return () => window.removeEventListener('popstate', traversed, true);
  }, []);
  const [loading, setLoading] = useState(false);
  const [narrowNavigation, setNarrowNavigation] = useState(() => window.matchMedia?.('(width < 48rem)').matches ?? false);
  const [navigationOpen, setNavigationOpen] = useState(false);
  const homePath = appPath(basePath, '/');
  const runtimePath = appPath(basePath, '/runtime');
  const atHome = location.path === (basePath || '/') || location.path === homePath;
  const uploadPath = appPath(basePath, '/upload');
  const isJob = location.path.startsWith(`${basePath}/jobs/`) && location.path.slice(`${basePath}/jobs/`.length).indexOf('/') < 0;
  const isRun = location.path.startsWith(`${basePath}/jobs/`) && /\/runs\/[^/]+$/.test(location.path);
  const isRunActivity = location.path.startsWith(`${basePath}/jobs/`) && /\/runs\/[^/]+\/activity$/.test(location.path);
  const isRunEvidence = location.path.startsWith(`${basePath}/jobs/`) && /\/runs\/[^/]+\/evidence$/.test(location.path);
  const isHistory = location.path.startsWith(`${basePath}/jobs/`) && /^[^/]+\/runs$/.test(location.path.slice(`${basePath}/jobs/`.length));
  const isGit = location.path.startsWith(`${basePath}/jobs/`) && /^[^/]+\/git$/.test(location.path.slice(`${basePath}/jobs/`.length));
  const isSourceDirectory = new RegExp(`^${basePath}/jobs/[^/]+/runs/[^/]+/revisions/[^/]+/sources/[^/]+$`).test(location.path);
  const isSourceFile = new RegExp(`^${basePath}/jobs/[^/]+/runs/[^/]+/revisions/[^/]+/source-files/[^/]+$`).test(location.path);
  const pageTitle = atHome ? copy.jobs : location.path === uploadPath ? copy.uploadABinary
    : location.path === runtimePath ? copy.runtimeStatus : isJob ? copy.jobOverview
      : isRunActivity ? copy.attemptActivity : isRunEvidence ? copy.attemptEvidence
        : isRun ? copy.workflowAttempt : isHistory ? copy.attemptHistory : isGit ? copy.sourceRepository
      : isSourceDirectory ? sourceTitleCopy.title : isSourceFile ? sourceTitleCopy.fileTitle : copy.pageUnavailable;

  function focusRouteHeading(url: string) {
    const path = new URL(url, window.location.origin).pathname.replace(/\/+$/g, '') || '/';
    const currentPath = window.location.pathname.replace(/\/+$/g, '') || '/';
    const routePath = location.path.replace(/\/+$/g, '') || '/';
    if (path !== routePath || path !== currentPath) return;
    if (focusedPath.current === path) {
      historyFocusPath.current = null;
      return;
    }
    const heading = main.current?.querySelector('h1');
    if (!heading) return; // A lazy route will call viewReady after its heading commits.
    if (!heading.hasAttribute('tabindex')) heading.setAttribute('tabindex', '-1');
    heading.focus({ preventScroll: historyFocusPath.current === path || recovery.snapshot() !== 'ready' });
    historyFocusPath.current = null;
    focusedPath.current = path;
  }

  useLayoutEffect(() => {
    document.title = textMessage(copy.documentTitle, { page: pageTitle });
    setNavigationOpen(false);
    focusRouteHeading(location.url);
  }, [pageTitle, location.path]);

  useLayoutEffect(() => {
    const media = window.matchMedia?.('(width < 48rem)');
    if (!media) return;
    const update = () => {
      const active = document.activeElement;
      if (media.matches && navigation.current?.contains(active)) pendingNavigationFocus.current = 'toggle';
      else if (!media.matches && active === navigationToggle.current) pendingNavigationFocus.current = 'link';
      setNavigationOpen(false);
      setNarrowNavigation(media.matches);
    };
    media.addEventListener('change', update);
    update();
    return () => media.removeEventListener('change', update);
  }, []);

  useLayoutEffect(() => {
    const pending = pendingNavigationFocus.current;
    pendingNavigationFocus.current = null;
    if (pending === 'toggle') navigationToggle.current?.focus({ preventScroll: true });
    if (pending === 'link') {
      const link = navigation.current?.querySelector<HTMLAnchorElement>('a[aria-current="page"]')
        ?? navigation.current?.querySelector<HTMLAnchorElement>('a[href]');
      link?.focus({ preventScroll: true });
    }
  }, [narrowNavigation]);

  function viewReady(url: string) {
    setLoading(false);
    focusRouteHeading(url);
  }

  return (
    <>
      <a class="skip-link" href="#main" onClick={() => main.current?.focus()}>{copy.skipToContent}</a>
      <header class="app-header">
        <a class="brand" href={homePath} aria-label={copy.decompWorkbenchHome}>
          <img src={mark} alt="" width="28" height="28" />
          <span>{displayMessage(copy.brand, { wordmark: <strong>{copy.workbench}</strong> })}</span>
        </a>
        <span class="build-label">{copy.earlyPreview}</span>
        <DisplayPreferences />
        {session && <SessionStatus session={session} placement="header" />}
      </header>
      <AssetRecoveryNotice recovery={recovery} identity={identity} reload={reload} />
      <ConnectionNotice />
      {session && <SessionStatus session={session} placement="page" />}
      <div class="app-layout">
        <nav class="app-nav" aria-label={copy.mainNavigation} ref={navigation} onKeyDown={event => {
          if (narrowNavigation && navigationOpen && event.key === 'Escape') {
            event.preventDefault();
            setNavigationOpen(false);
            navigationToggle.current?.focus();
          }
        }}>
          <button class="navigation-toggle" type="button" ref={navigationToggle} hidden={!narrowNavigation}
            aria-controls="main-navigation-links" aria-expanded={navigationOpen}
            onClick={() => setNavigationOpen(current => !current)}>{copy.navigation}</button>
          <div id="main-navigation-links" hidden={narrowNavigation && !navigationOpen} onClick={event => {
            if (narrowNavigation && navigationOpen && !event.defaultPrevented && !event.ctrlKey && !event.metaKey && !event.shiftKey
              && !event.altKey && event.button === 0 && event.target instanceof Element
              && event.target.closest('a[href]')) {
              setNavigationOpen(false);
              navigationToggle.current?.focus();
            }
          }}>
            <a href={homePath} aria-current={atHome ? 'page' : undefined}>{copy.workspace}</a>
            <a href={uploadPath} aria-current={location.path === uploadPath ? 'page' : undefined}>{copy.upload}</a>
            <a href={runtimePath} aria-current={location.path === runtimePath ? 'page' : undefined}>{copy.runtimeStatus}</a>
          </div>
        </nav>
        <main id="main" ref={main} tabIndex={-1} aria-busy={loading}>
          <p class="sr-only" role="status">{loading ? copy.openingView : ''}</p>
          {!atHome && <nav aria-label={copy.breadcrumbs}>
            <ol class="breadcrumbs"><li><a href={homePath}>{copy.allJobs}</a></li><li aria-current="page">{pageTitle}</li></ol>
          </nav>}
          <ViewBoundary key={location.path}>
            <Router onLoadStart={() => setLoading(true)} onLoadEnd={viewReady} onRouteChange={viewReady}>
              <Route path={homePath} component={Home} basePath={basePath} session={session} />
              <Route path={uploadPath} component={UploadPage} basePath={basePath} session={session} />
              <Route path={runtimePath} component={Runtime} identity={identity} session={session} />
              <Route path={`${basePath}/jobs/:jobId/runs/:runId/revisions/:revisionId/sources/:directoryId`} component={Sources} resource="directory" basePath={basePath} session={session} />
              <Route path={`${basePath}/jobs/:jobId/runs/:runId/revisions/:revisionId/source-files/:fileId`} component={Sources} resource="file" basePath={basePath} session={session} />
              <Route path={`${basePath}/jobs/:jobId/runs`} component={RunHistory} basePath={basePath} session={session} />
              <Route path={`${basePath}/jobs/:jobId/git`} component={Git} basePath={basePath} session={session} />
              <Route path={`${basePath}/jobs/:jobId/runs/:runId/activity`} component={Run} view="activity" basePath={basePath} session={session} />
              <Route path={`${basePath}/jobs/:jobId/runs/:runId/evidence`} component={Run} view="evidence" basePath={basePath} session={session} />
              <Route path={`${basePath}/jobs/:jobId/runs/:runId`} component={Run} basePath={basePath} session={session} />
              <Route path={`${basePath}/jobs/:jobId`} component={Job} basePath={basePath} session={session} />
              <Route default component={NotFound} homePath={homePath} />
            </Router>
          </ViewBoundary>
        </main>
      </div>
      <footer class="app-footer">{copy.sourceAndValidationEvidenceStayConnectedToTheirRevision}</footer>
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
        <PrivateSessionContext.Provider value={session}>
          <Shell basePath={basePath} identity={identity} recovery={recovery} reload={reload} session={session} />
        </PrivateSessionContext.Provider>
      </LocationProvider>
    </ViewBoundary>
  );
}
