// Controls for --browser-temp-parent containment (R6). Every directory this file creates is under build/.
import assert from 'node:assert/strict';
import { promises as fs, readFileSync } from 'node:fs';
import { dirname, join, resolve } from 'node:path';
import test from 'node:test';
import { fileURLToPath } from 'node:url';
import { createBrowserTemp, insideRoot, resolveBrowserTempParent } from './packaged-browser-temp-parent.mjs';

const repo = resolve(dirname(fileURLToPath(import.meta.url)), '..');
const outside = dirname(await fs.realpath(repo));

async function scratch(t) {
  await fs.mkdir(join(repo, 'build'), { recursive: true });
  const directory = await fs.mkdtemp(join(repo, 'build', 'browser-temp-parent-test-'));
  t.after(() => fs.rm(directory, { recursive: true, force: true }));
  return directory;
}

const ownedEntries = async (directory) => (await fs.readdir(directory)).filter(name => name.startsWith('.ct-'));

test('the repository default and an in-repository directory are accepted with a repository-relative TMPDIR', async (t) => {
  const root = await fs.realpath(repo);
  assert.deepEqual(await resolveBrowserTempParent(repo, repo), { root, parent: root });
  const directory = await scratch(t);
  const parent = await resolveBrowserTempParent(repo, directory);
  assert.equal(parent.parent, await fs.realpath(directory));
  const created = await createBrowserTemp(parent);
  assert.equal(dirname(created.directory), parent.parent);
  assert.match(created.forProcess, /^build\/browser-temp-parent-test-[^/]+\/\.ct-[^/]+$/);
  assert.equal(resolve(root, created.forProcess), created.directory);
  assert.ok((await fs.stat(created.directory)).isDirectory());
});

test('an in-repository symbolic link to a directory outside the repository is refused before anything is created', async (t) => {
  const directory = await scratch(t);
  const link = join(directory, 'escape');
  await fs.symlink(outside, link);
  const before = await ownedEntries(outside);
  await assert.rejects(resolveBrowserTempParent(repo, link), /must resolve to an existing directory inside the repository/);
  assert.deepEqual(await ownedEntries(outside), before, 'a refused parent must not gain an owned directory');
});

test('a parent component is resolved physically, not lexically', async (t) => {
  const directory = await scratch(t);
  await fs.symlink(outside, join(directory, 'up'));
  // Lexically `${directory}/up/..` is the in-repository scratch directory; physically it is outside's parent.
  await assert.rejects(resolveBrowserTempParent(repo, `${directory}/up/..`), /inside the repository/);
  // A link that leaves and re-enters the repository resolves inside it and is accepted at its real path.
  const root = await fs.realpath(repo);
  const reentered = await resolveBrowserTempParent(repo, join(directory, 'up', root.slice(outside.length + 1), 'build'));
  assert.equal(reentered.parent, join(root, 'build'));
});

test('outside, relative, missing and non-directory parents are refused without creating anything', async (t) => {
  const directory = await scratch(t);
  await fs.writeFile(join(directory, 'file'), '');
  const before = await ownedEntries(outside);
  for (const [parent, message] of [
    [outside, /inside the repository/],
    ['build', /must be an absolute directory/],
    [undefined, /must be an absolute directory/],
    [join(directory, 'missing'), /existing directory inside the repository/],
    [join(directory, 'file'), /existing directory inside the repository/],
  ]) {
    await assert.rejects(resolveBrowserTempParent(repo, parent), message, String(parent));
  }
  assert.deepEqual(await fs.readdir(directory), ['file']);
  assert.deepEqual(await ownedEntries(outside), before);
});

test('lexical containment alone does not admit a prefix sibling or a parent reference', () => {
  assert.equal(insideRoot('/work/repo', '/work/repo'), true);
  assert.equal(insideRoot('/work/repo', '/work/repo/build/.ct-1'), true);
  assert.equal(insideRoot('/work/repo', '/work/repository'), false);
  assert.equal(insideRoot('/work/repo', '/work'), false);
  assert.equal(insideRoot('/work/repo', '/work/repo/../other'), false);
  assert.equal(insideRoot('/work/repo', '/work/repo/..evil'), true, 'a child whose name starts with dots is still inside');
});

test('a parent swapped after validation has its created directory removed and refused', async (t) => {
  const directory = await scratch(t);
  const parent = await resolveBrowserTempParent(repo, directory);
  const removed = [];
  const escaped = join(outside, 'swapped-target');
  await assert.rejects(createBrowserTemp(parent, {
    realpath: async () => escaped,
    rm: async (path, options) => { removed.push([path, options]); await fs.rm(path, options); },
  }), /must remain inside the repository/);
  assert.equal(removed.length, 1);
  assert.equal(dirname(removed[0][0]), parent.parent);
  assert.deepEqual(removed[0][1], { recursive: true, force: true });
  assert.deepEqual(await ownedEntries(directory), []);
});

test('the driver validates the parent at startup and creates Chrome TMPDIR only through the helper', () => {
  const driver = readFileSync(join(repo, 'scripts/check-packaged-web-browser.mjs'), 'utf8');
  assert.match(driver, /^import \{ resolveBrowserTempParent, createBrowserTemp \} from '\.\/packaged-browser-temp-parent\.mjs';$/m);
  const validated = driver.indexOf("const browserTempParent = await resolveBrowserTempParent(repo, values['browser-temp-parent']);");
  const created = driver.indexOf('const ownedBrowserTemp = await createBrowserTemp(browserTempParent);');
  const browserLaunch = driver.indexOf('browser = startOwned(chromeBinary');
  assert.ok(validated > 0 && created > validated && browserLaunch > created);
  assert.ok(driver.indexOf('try {\n') > validated, 'the parent is refused before the owned run starts');
  assert.doesNotMatch(driver, /mkdtemp\(join\(values\['browser-temp-parent'\]/);
  assert.match(driver.slice(created, browserLaunch), /browserTmp = ownedBrowserTemp\.directory;\n {2}const browserTmpForProcess = ownedBrowserTemp\.forProcess;/);
});
