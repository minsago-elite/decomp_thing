/** A server-supplied deployment prefix, never an arbitrary URL. */
export function normalizeBasePath(value: string): string {
  if (value === '' || value === '/') return '';
  if (!/^\/(?:[A-Za-z0-9_-]+\/)*[A-Za-z0-9_-]+\/?$/.test(value)) {
    throw new Error('The application base path is invalid.');
  }
  return value.replace(/\/$/, '');
}

export function appPath(basePath: string, route: '/' | '/runtime'): string {
  return `${basePath}${route}`;
}
