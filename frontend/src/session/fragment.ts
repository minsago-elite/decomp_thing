export type BootstrapFragment =
  | { kind: 'absent' }
  | { kind: 'token'; token: string }
  | { kind: 'invalid' }
  | { kind: 'removal-failed' };

/** Remove the one-time credential before constructing a request or rendering it. */
export function takeBootstrapFragment(
  location: Pick<Location, 'hash' | 'pathname' | 'search'>,
  history: Pick<History, 'replaceState' | 'state'>,
): BootstrapFragment {
  const fragment = location.hash;
  if (!fragment.startsWith('#bootstrap') && !fragment.includes('&bootstrap')) return { kind: 'absent' };
  try {
    history.replaceState(history.state, '', `${location.pathname}${location.search}`);
  } catch {
    return { kind: 'removal-failed' };
  }
  const match = /^#bootstrap=([A-Za-z0-9_-]{32,256})$/.exec(fragment);
  return match?.[1] ? { kind: 'token', token: match[1] } : { kind: 'invalid' };
}
