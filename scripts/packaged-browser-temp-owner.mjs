import assert from 'node:assert/strict';
import { constants, promises as fs } from 'node:fs';
import { randomUUID } from 'node:crypto';
import { basename, dirname, isAbsolute, join, relative, resolve, sep } from 'node:path';

export const SOURCE_TREE_BROWSER_TEMP_OWNER = 'DECOMP_PACKAGED_SOURCE_TREE_BROWSER_TEMP_OWNER';
const markerName = '.decomp-browser-temp-owner';
const identity = info => ({ device: String(info.dev), inode: String(info.ino) });
async function ownedBuildRoot(repo, buildRoot) {
  const canonicalRepo = await fs.realpath(repo);
  assert.equal(await fs.realpath(join(canonicalRepo, 'build')), buildRoot, 'Browser temp owner build root changed');
  const inside = relative(canonicalRepo, buildRoot);
  assert.ok(inside && inside !== '..' && !inside.startsWith(`..${sep}`) && !isAbsolute(inside),
    'Browser temp owner build root must remain inside the repository');
  const info = await fs.lstat(buildRoot, { bigint: true });
  assert.ok(info.isDirectory() && !info.isSymbolicLink(), 'Browser temp build root is not a real directory');
  return info;
}

/** Parent-held allocation receipt: no cleanup path is accepted from the child report alone. */
export async function allocateSourceTreeBrowserTemp(repo, buildRoot) {
  const parent = await ownedBuildRoot(repo, buildRoot);
  const directory = await fs.mkdtemp(join(buildRoot, '.ct-'));
  const info = await fs.lstat(directory, { bigint: true });
  const token = randomUUID();
  await fs.writeFile(join(directory, markerName), token, { flag: 'wx', mode: 0o600 });
  return Object.freeze({ directory, token, ...identity(info),
    buildDevice: String(parent.dev), buildInode: String(parent.ino) });
}

export async function requireSourceTreeBrowserTemp(repo, buildRoot, owner, reportedDirectory) {
  assert.ok(owner && typeof owner.directory === 'string' && typeof owner.token === 'string', 'Missing browser temp allocation receipt');
  assert.match(owner.token, /^[a-f0-9-]{36}$/u, 'Invalid browser temp owner token');
  assert.equal(reportedDirectory, owner.directory, 'Browser temp directory belongs to another launch');
  assert.equal(dirname(owner.directory), buildRoot, 'Browser temp directory escaped its allocated build root');
  assert.equal(resolve(owner.directory), owner.directory, 'Browser temp allocation path is not canonical');
  assert.match(basename(owner.directory), /^\.ct-[A-Za-z0-9]+$/u, 'Browser temp directory lacks its allocated short name');
  const parent = await ownedBuildRoot(repo, buildRoot);
  assert.equal(String(parent.dev), owner.buildDevice, 'Browser temp build device changed');
  assert.equal(String(parent.ino), owner.buildInode, 'Browser temp build inode changed');
  const info = await fs.lstat(owner.directory, { bigint: true });
  assert.ok(info.isDirectory() && !info.isSymbolicLink(), 'Browser temp allocation is not a real directory');
  assert.equal(await fs.realpath(owner.directory), owner.directory, 'Browser temp allocation path changed');
  assert.equal(String(info.dev), owner.device, 'Browser temp allocation device changed');
  assert.equal(String(info.ino), owner.inode, 'Browser temp allocation inode changed');
  const marker = await fs.open(join(owner.directory, markerName), constants.O_RDONLY | constants.O_NOFOLLOW | constants.O_NONBLOCK);
  try {
    assert.ok((await marker.stat()).isFile(), 'Browser temp owner marker is not a regular file');
    const buffer = Buffer.alloc(257);
    const { bytesRead } = await marker.read(buffer, 0, buffer.length, 0);
    assert.ok(bytesRead <= 256, 'Browser temp owner marker exceeds its bound');
    assert.equal(buffer.toString('utf8', 0, bytesRead), owner.token, 'Browser temp allocation owner changed');
  } finally { await marker.close(); }
  return owner.directory;
}

/** Invoke only after the owning process-tree receipt confirms teardown. */
export async function removeSourceTreeBrowserTemp(repo, buildRoot, owner, reportedDirectory) {
  const directory = await requireSourceTreeBrowserTemp(repo, buildRoot, owner, reportedDirectory);
  await fs.rm(directory, { recursive: true });
}
