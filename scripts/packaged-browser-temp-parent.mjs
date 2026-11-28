import { promises as fs } from 'node:fs';
import { isAbsolute, join, relative, sep } from 'node:path';

const PARENT_REFUSED = '--browser-temp-parent must resolve to an existing directory inside the repository';
const TEMP_ESCAPED = 'Browser temporary directory (--browser-temp-parent) must remain inside the repository';

/** True when `path` is `root` or below it; both must already be resolved real paths. */
export function insideRoot(root, path) {
  const rest = relative(root, path);
  return rest === '' || (!isAbsolute(rest) && rest !== '..' && !rest.startsWith(`..${sep}`));
}

/**
 * Resolves the Chrome temporary parent through every symbolic link and refuses it unless the real
 * directory lies inside the real repository root. Nothing is created here, so a refused parent leaves
 * no directory behind.
 */
export async function resolveBrowserTempParent(repo, parent, { realpath = fs.realpath, stat = fs.stat } = {}) {
  if (typeof parent !== 'string' || !isAbsolute(parent)) throw new Error('--browser-temp-parent must be an absolute directory');
  const root = await realpath(repo);
  let resolved;
  try { resolved = await realpath(parent); }
  catch { throw new Error(PARENT_REFUSED); }
  if (!insideRoot(root, resolved)) throw new Error(PARENT_REFUSED);
  if (!(await stat(resolved)).isDirectory()) throw new Error(PARENT_REFUSED);
  return Object.freeze({ root, parent: resolved });
}

/**
 * Creates the owned `.ct-` directory under a parent from resolveBrowserTempParent. If the created path no
 * longer resolves to itself inside the repository (the parent was swapped after validation), it is removed
 * and refused. Returns the directory and its path relative to the real repository root for Chrome's TMPDIR.
 */
export async function createBrowserTemp({ root, parent }, { mkdtemp = fs.mkdtemp, realpath = fs.realpath, rm = fs.rm } = {}) {
  const directory = await mkdtemp(join(parent, '.ct-'));
  let resolved = null;
  try { resolved = await realpath(directory); } catch { resolved = null; }
  if (resolved !== directory || !insideRoot(root, directory)) {
    await rm(directory, { recursive: true, force: true });
    throw new Error(TEMP_ESCAPED);
  }
  return Object.freeze({ directory, forProcess: relative(root, directory) });
}
