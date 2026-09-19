export type BuildIdentity = Readonly<{
  uiBuildId: string | null;
  applicationVersion: string | null;
}>;

export const UNKNOWN_BUILD: BuildIdentity = { uiBuildId: null, applicationVersion: null };

/** Values are supplied by the verified packaged shell, never by browser environment variables. */
export function readBuildIdentity(document: Document): BuildIdentity {
  function read(name: string, pattern: RegExp): string | null {
    const values = document.querySelectorAll<HTMLMetaElement>(`meta[name="${name}"]`);
    if (values.length !== 1) return null;
    const value = values[0]?.content;
    return value && value.trim() === value && pattern.test(value) ? value : null;
  }
  return {
    uiBuildId: read('decomp-ui-build', /^[0-9a-f]{64}$/),
    applicationVersion: read('decomp-application-version', /^[A-Za-z0-9][A-Za-z0-9.+-]{0,63}$/),
  };
}
