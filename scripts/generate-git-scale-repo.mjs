#!/usr/bin/env node
import { spawn } from 'node:child_process';
import { lstat, mkdir, realpath, writeFile } from 'node:fs/promises';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const here = path.dirname(fileURLToPath(import.meta.url));
const repoRoot = path.resolve(here, '../../..');
const COMMIT_COUNT = 10_000;
const identity = 'Scale Fixture <scale-fixture@example.invalid>';
const epoch = 1_700_000_000;

function git(args, cwd, { input, maxOutput = 1_000_000, maxInput = 32 * 1024 * 1024, timeoutMs = 120_000 } = {}) {
  if (input && input.length > maxInput) return Promise.reject(new Error('git input exceeded limit'));
  return new Promise((resolve, reject) => {
    const child = spawn('git', args, { cwd, env: { PATH: process.env.PATH, HOME: '/nonexistent', GIT_CONFIG_NOSYSTEM: '1', GIT_CONFIG_GLOBAL: '/dev/null', GIT_TERMINAL_PROMPT: '0' }, stdio: ['pipe', 'pipe', 'pipe'] });
    let out = Buffer.alloc(0), err = Buffer.alloc(0);
    let settled = false;
    const finish = (failure, value) => {
      if (settled) return;
      settled = true;
      clearTimeout(timer);
      if (failure) reject(failure); else resolve(value);
    };
    const timer = setTimeout(() => {
      child.kill('SIGKILL');
      finish(new Error(`git ${args[0]} exceeded its ${timeoutMs}ms deadline`));
    }, timeoutMs);
    timer.unref();
    for (const [stream, target] of [[child.stdout, 'out'], [child.stderr, 'err']]) stream.on('data', chunk => {
      const current = target === 'out' ? out : err;
      if (current.length + chunk.length > maxOutput) { child.kill('SIGKILL'); finish(new Error('git output exceeded limit')); return; }
      if (target === 'out') out = Buffer.concat([out, chunk]); else err = Buffer.concat([err, chunk]);
    });
    child.on('error', failure => finish(failure));
    child.on('close', code => code === 0 ? finish(null, out.toString('utf8')) : finish(new Error(`git ${args[0]} failed (${code}): ${err.toString('utf8').slice(0, 2000)}`)));
    child.stdin.on('error', failure => { if (failure.code !== 'EPIPE') finish(failure); });
    if (input) child.stdin.end(input); else child.stdin.end();
  });
}

async function main() {
  const arg = process.argv[2];
  if (!arg || process.argv.length !== 3) throw new Error('usage: node scripts/generate-git-scale-repo.mjs <new-output-directory-under-build>');
  const buildDir = await realpath(path.join(repoRoot, 'build'));
  const output = path.resolve(arg);
  if (!output.startsWith(buildDir + path.sep)) throw new Error('output directory must be beneath this repository build/');
  const requestedParent = path.dirname(output);
  const actualParent = await realpath(requestedParent);
  if (actualParent !== requestedParent || !actualParent.startsWith(buildDir + path.sep)) {
    throw new Error('output parent must be a real directory beneath this repository build/');
  }
  try { await lstat(output); throw new Error(`output already exists: ${output}`); } catch (e) { if (e.code !== 'ENOENT') throw e; }
  await mkdir(output, { recursive: false });
  const bare = path.join(output, 'history.git');
  await git(['init', '--bare', '--quiet', '--initial-branch=main', bare], repoRoot);
  const chunks = [];
  let mark = 1;
  const text = Buffer.from(('Deterministic UTF-8 scale patch — café, 東京, λ.\n').repeat(4000));
  const binary = Buffer.alloc(3 * 1024 * 1024);
  for (let i = 0; i < binary.length; i++) binary[i] = (i * 31 + 17) & 255;
  const special = new Map([[100, Array.from({length: 2000}, (_,i)=>`boundary/2000/file-${String(i).padStart(4,'0')}.txt`)], [200, Array.from({length: 2001}, (_,i)=>`boundary/2001/file-${String(i).padStart(4,'0')}.txt`)]]);
  const pathSets = {};
  let parent = null;
  // fast-import data is byte-counted UTF-8. Convert each payload to UTF-8 bytes before framing;
  // all commit timestamps are fixed UTC seconds, incremented once per commit.
  for (let n = 1; n <= COMMIT_COUNT; n++) {
    const subject = n === COMMIT_COUNT
      ? `scale commit ${String(n).padStart(5,'0')} ${'界'.repeat(220)}`
      : `scale commit ${String(n).padStart(5,'0')}`;
    let block = `commit refs/heads/main\nmark :${mark++}\nauthor ${identity} ${epoch+n} +0000\ncommitter ${identity} ${epoch+n} +0000\ndata ${Buffer.byteLength(subject)}\n${subject}\n`;
    if (parent) block += `from ${parent}\n`;
    const paths = [];
    const add = (name, bytes, mode = '100644') => {
      const bmark = mark++;
      chunks.push(Buffer.from(`blob\nmark :${bmark}\ndata ${bytes.length}\n`)); chunks.push(bytes, Buffer.from('\n'));
      block += `M ${mode} :${bmark} ${name}\n`; paths.push(name);
    };
    if (n === 1) { add('README.txt', Buffer.from('Deterministic Git history fixture.\n')); add('large/patch.txt', text); add('large/payload.bin', binary); }
    if (special.has(n)) for (const name of special.get(n)) add(name, Buffer.from(`change ${n}\n`));
    if (paths.length) pathSets[n] = paths;
    chunks.push(Buffer.from(block + '\n'));
    parent = `:${mark - (paths.length ? paths.length + 1 : 1)}`;
  }
  chunks.push(Buffer.from('done\n'));
  // Stream the complete deterministic stream via stdin; fast-import itself writes only inside history.git.
  await git(['--git-dir', bare, 'fast-import', '--quiet'], repoRoot, { input: Buffer.concat(chunks), maxOutput: 100_000 });
  const tip = (await git(['--git-dir', bare, 'rev-parse', 'refs/heads/main'], repoRoot)).trim();
  const commits = (await git(['--git-dir', bare, 'rev-list', '--count', 'refs/heads/main'], repoRoot)).trim();
  const largeIds = {};
  for (const file of ['large/patch.txt', 'large/payload.bin']) largeIds[file] = (await git(['--git-dir', bare, 'rev-parse', `refs/heads/main:${file}`], repoRoot)).trim();
  const commitIds = (await git(['--git-dir', bare, 'rev-list', '--reverse', 'refs/heads/main'], repoRoot)).trim().split('\n');
  if (commitIds.length !== COMMIT_COUNT) throw new Error('generated history has an unexpected commit count');
  const manifest = { format: 1, branch: 'refs/heads/main', commitCount: Number(commits), tip, firstCommit: commitIds[0], commitIds, pathSets, largeFiles: { 'large/patch.txt': { blob: largeIds['large/patch.txt'], bytes: text.length }, 'large/payload.bin': { blob: largeIds['large/payload.bin'], bytes: binary.length } } };
  await writeFile(path.join(output, 'manifest.json'), `${JSON.stringify(manifest, null, 2)}\n`, { flag: 'wx' });
  console.log(JSON.stringify({ output, ...manifest }));
}
main().catch(e => { console.error(e.message); process.exitCode = 1; });
