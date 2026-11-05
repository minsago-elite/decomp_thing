/** Share the same module promise between navigation and the app's lazy route boundary. */
export function loadStructureRoute() {
  return import('./Structure');
}
