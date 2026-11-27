/**
 * Feature detection for optional browser capabilities (#631). A missing capability selects a
 * documented fallback (docs/web-browser-support.md); it never becomes a failure state, and the
 * user agent string is never consulted.
 */
export type BrowserCapabilities = Readonly<{
  /** fetch() exposes a readable response body, so the event stream can be consumed live. */
  fetchStreaming: boolean;
  /** An asynchronous clipboard write is available in this (secure) context. */
  clipboardWrite: boolean;
}>;

type Scope = {
  ReadableStream?: unknown; Response?: unknown; TextDecoder?: unknown;
  isSecureContext?: boolean; navigator?: { clipboard?: { writeText?: unknown } };
};

export function browserCapabilities(scope: Scope = globalThis): BrowserCapabilities {
  return {
    fetchStreaming: typeof scope.ReadableStream === 'function' && typeof scope.TextDecoder === 'function'
      && typeof scope.Response === 'function' && 'body' in (scope.Response as { prototype: object }).prototype,
    clipboardWrite: scope.isSecureContext !== false && typeof scope.navigator?.clipboard?.writeText === 'function',
  };
}
