// View-scoped interface copy; protocol values and DOM identities stay in their components.

export const appCopy = {
  "documentTitle": "{page} · Decomp Workbench",
  "serverWorkMayContinueWhileThisPageIsDisconnected": "Server work may continue while this page is disconnected.",
  "skipToContent": "Skip to content",
  "workbench": "Workbench",
  "earlyPreview": "Early preview",
  "navigation": "Navigation",
  "workspace": "Workspace",
  "upload": "Upload",
  "runtimeStatus": "Runtime status",
  "allJobs": "All jobs",
  "sourceAndValidationEvidenceStayConnectedToTheirRevision": "Source and validation evidence stay connected to their revision.",
  "refreshLoadedInformation": "Refresh loaded information",
  "browserReportsOffline": "Browser reports offline",
  "theBrowserReportsAConnectionAgainPreviouslyLoadedInformationMay": "The browser reports a connection again. Previously loaded information may still be out of date. Refresh this view to check its current state.",
  "previouslyLoadedInformationMayBeOutOfDateReconnectAnd": "Previously loaded information may be out of date. Reconnect and refresh this view before relying on its status.",
  "jobs": "Jobs",
  "uploadABinary": "Upload a binary",
  "jobOverview": "Job overview",
  "workflowAttempt": "Workflow attempt",
  "attemptHistory": "Attempt history",
  "pageUnavailable": "Page unavailable",
  "openingView": "Opening view…",
  "connectionStatus": "Connection status",
  "decompWorkbenchHome": "Decomp Workbench home",
  "mainNavigation": "Main navigation",
  "breadcrumbs": "Breadcrumbs",
  "brand": "Decomp {wordmark}"
} as const;

export const displayPreferencesCopy = {
  "displayPreferences": "Display preferences",
  "theme": "Theme",
  "system": "System",
  "light": "Light",
  "dark": "Dark",
  "reducedMotion": "Reduced motion",
  "alwaysReduce": "Always reduce",
  "systemFollowsYourDeviceSettingsChangesAreSavedInThis": "System follows your device settings. Changes are saved in this browser when storage is available.",
  "resetDisplayPreferences": "Reset display preferences",
  "displayPreferencesSavedInThisBrowser": "Display preferences saved in this browser.",
  "changesApplyToThisTabButCouldNotBeSaved": "Changes apply to this tab, but could not be saved in this browser."
} as const;

export const sessionStatusCopy = {
  "reference": " Reference ID: {reference}.",
  "localSessionConnected": "Local session connected.",
  "applicationInstanceChanged": "Application instance changed. It may have restarted or been replaced. Previously loaded private views were cleared.",
  "signOut": "Sign out",
  "checkSession": "Check session",
  "anotherTabReportedASessionChangePrivateDataWasCleared": "Another tab reported a session change. Private data was cleared. Check the session to reconnect.",
  "youSignedOutOfThisBrowserPublicPagesRemainAvailable": "You signed out of this browser. Public pages remain available.",
  "yourLocalSessionExpiredOpenAFreshSignInLink": "Your local session expired. Open a fresh sign-in link from the application terminal.",
  "thisSignInLinkExpiredOpenAFreshLinkFrom": "This sign-in link expired. Open a fresh link from the application terminal.",
  "thisSignInLinkIsNoLongerAvailableOpenA": "This sign-in link is no longer available. Open a fresh link from the application terminal.",
  "thisSignInLinkIsIncompleteOrInvalidOpenA": "This sign-in link is incomplete or invalid. Open a fresh link from the application terminal.",
  "toAccessPrivateWorkOpenTheSignInLinkPrinted": "To access private work, open the sign-in link printed by your local application.",
  "signOutCouldNotBeConfirmedCheckTheSessionBefore": "Sign-out could not be confirmed. Check the session before trying again.",
  "theBrowserAddressAndApplicationConfigurationDoNotMatchOpen": "The browser address and application configuration do not match. Open the configured local address.",
  "theSignInLinkCouldNotBeClearedFromThis": "The sign-in link could not be cleared from this tab. Close it and open a fresh local link in a supported browser.",
  "theLocalSessionCouldNotBeCheckedConfirmTheApplication": "The local session could not be checked. Confirm the application is running, then check the session.",
  "thisPageAndTheLocalServerUseIncompatibleAPIFormats": "This page and the local server use incompatible API formats. Copy any unsaved input, then use your browser’s Reload action to load a matching version.",
  "checkingLocalSession": "Checking local session…",
  "signingOut": "Signing out…",
  "localSession": "Local session"
} as const;

export const assetRecoveryNoticeCopy = {
  "build": "Open UI build: {build}",
  "theApplicationMayHaveUpdated": "The application may have updated",
  "anApplicationFileCouldNotBeLoadedTheServerMay": "An application file could not be loaded. The server may have updated, or the connection may have been interrupted. Copy any unsaved input before reloading.",
  "useYourBrowserSReloadActionToRequestTheCurrent": "Use your browser’s Reload action to request the current version.",
  "reloading": "Reloading…",
  "reloadApplication": "Reload application"
} as const;

export const lazyRouteCopy = {
  "thisViewIsUnavailable": "This view is unavailable",
  "useTheApplicationNoticeAboveToReloadTheCurrentVersion": "Use the application notice above to reload the current version."
} as const;

export const viewBoundaryCopy = {
  "thisViewCouldNotBeOpened": "This view could not be opened",
  "yourWorkRemainsOnTheServerTryOpeningTheView": "Your work remains on the server. Try opening the view again.",
  "tryAgain": "Try again"
} as const;

export const homeCopy = {
  "reconstructionWorkspace": "Reconstruction workspace",
  "yourWorkWithItsEvidence": "Your work, with its evidence",
  "reviewReconstructedSourceInspectValidationEvidenceAndFollowEachRevision": "Review reconstructed source, inspect validation evidence, and follow each revision.",
  "theWorkbenchShellIsReady": "The workbench shell is ready",
  "connectALocalSessionToBrowseUploadedJobsThePublic": "Connect a local session to browse uploaded jobs. The public shell does not read jobs or start workflows.",
  "existingCommandLineWorkflowsRemainAvailable": "Existing command-line workflows remain available."
} as const;

export const notFoundCopy = {
  "pageUnavailable": "Page unavailable",
  "thisPageCouldNotBeFound": "This page could not be found",
  "theLinkMayBeIncompleteOrThisViewMayNot": "The link may be incomplete, or this view may not be available.",
  "returnToTheWorkspace": "Return to the workspace"
} as const;

export const uploadPageCopy = {
  "uploadABinary": "Upload a binary",
  "createAPersistentJobFromASupportedELFFileUploading": "Create a persistent job from a supported ELF file. Uploading does not start analysis or reconstruction.",
  "connectALocalSessionToUploadABinary": "Connect a local session to upload a binary."
} as const;

export const mainCopy = {
  "startupFailed": "The workbench could not start",
  "startupGuidance": "Check the application configuration and reload this page."
} as const;
