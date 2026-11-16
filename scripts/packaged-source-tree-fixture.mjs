import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { promises as fs } from 'node:fs';
import { dirname, isAbsolute, join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { parseArgs } from 'node:util';

const profileId = 'generated-c-make-v1';
const sourceFiles = 25_000;
const runId = 'run_source_d0';
const revisionId = 'revision_source_d0';
const generator = 'd0-source-tree-fixture-v1';

const declarations = [
  ['build-definition', 'Makefile', 'utf8-text', ['archive-payload', 'build-definition', 'build-input', 'editable', 'viewable']],
  ['confidence-evidence', 'reports/confidence.json', 'utf8-text', ['archive-payload', 'evidence', 'viewable']],
  ['entrypoint-implementation', 'src/main.c', 'utf8-text', ['archive-payload', 'build-input', 'editable', 'entrypoint-implementation', 'viewable']],
  ['module-agent-execution-evidence', 'reports/agent-executions/{module}.json', 'utf8-text', ['archive-payload', 'evidence', 'viewable']],
  ['module-evidence', 'reports/modules/{module}.json', 'utf8-text', ['archive-payload', 'evidence', 'viewable']],
  ['module-implementation', 'src/modules/{module}.c', 'utf8-text', ['archive-payload', 'build-input', 'editable', 'module-implementation', 'viewable']],
  ['module-interface', 'include/modules/{module}.h', 'utf8-text', ['archive-payload', 'build-input', 'editable', 'public-interface', 'viewable']],
  ['module-plan-evidence', 'reports/module_plan.json', 'utf8-text', ['archive-payload', 'evidence', 'viewable']],
  ['module-private-interface', 'src/modules/{module}_internal.h', 'utf8-text', ['archive-payload', 'build-input', 'editable', 'private-interface', 'viewable']],
  ['program-model-evidence', 'reports/program_model.json', 'utf8-text', ['archive-payload', 'evidence', 'viewable']],
  ['shared-interface', 'include/decomp_types.h', 'utf8-text', ['archive-payload', 'build-input', 'editable', 'public-interface', 'viewable']],
  ['toolchain-evidence', 'reports/toolchain.json', 'utf8-text', ['archive-payload', 'evidence', 'viewable']],
  ['unresolved-evidence', 'UNRESOLVED.md', 'utf8-text', ['archive-payload', 'evidence', 'viewable']],
].map(([id, pathTemplate, contentKind, roles]) => ({ id, pathTemplate, contentKind, roles }));

const profileCanonical = {
  schemaVersion: 1,
  id: profileId,
  layout: { schemaVersion: 1, files: declarations.map(({ id, pathTemplate, contentKind, roles }) => ({ id, pathTemplate, contentKind, roles })) },
  budgets: {
    archiveMaximumEntries: 100_000,
    archiveMaximumFileBytes: 134_217_728,
    archiveMaximumTotalBytes: 1_073_741_824,
    buildMaximumOutputBytes: 33_554_432,
    buildWallClockMillis: 600_000,
    exportMaximumResidentBytes: 4_294_967_296,
    exportWallClockMillis: 600_000,
    maximumFunctionsPerModule: 24,
    plannerMaximumDependencyEdges: 2_000_000,
    plannerMaximumEntities: 250_000,
    plannerMaximumWorkUnits: 50_000_000,
    reconstructionMaximumContextCharacters: 120_000,
  },
  adapterConfiguration: {
    'build-executable': ['make'],
    'build-system': ['gnu-make'],
    'compiler-driver': ['cc'],
    'compiler-flags': ['-std=c11', '-g', '-Wall', '-Wextra', '-Werror', '-Iinclude'],
    'entry-symbol-candidates': ['main', 'decomp_engine_main', 'entry', 'recovered__start'],
    'source-language': ['c11'],
  },
};
const profileSha256 = sha256(Buffer.from(JSON.stringify(profileCanonical)));

function sha256(bytes) { return createHash('sha256').update(bytes).digest('hex'); }

function elfHeader() {
  const bytes = Buffer.alloc(64);
  bytes.set([0x7f, 0x45, 0x4c, 0x46, 2, 1, 1]);
  bytes.writeUInt16LE(2, 16); bytes.writeUInt16LE(62, 18); bytes.writeUInt32LE(1, 20); bytes.writeUInt16LE(64, 52);
  return bytes;
}

function sourceRevision(files) {
  const canonical = files.filter((file) => file.roles.includes('build-input')).map((file) =>
    `${file.path.length}:${file.path}:${file.bytes}:${file.sha256}\n`).join('');
  return sha256(Buffer.from(canonical, 'utf8'));
}

function revisionSourceDirectoryId(jobId, runId, revisionId, sourceSha256, files, directoryPath) {
  const prefix = `${directoryPath}/`;
  let low = 0;
  let high = files.length;
  while (low < high) {
    const middle = (low + high) >>> 1;
    if (files[middle].path < prefix) low = middle + 1;
    else high = middle;
  }
  assert.ok(low < files.length && files[low].path.startsWith(prefix), 'fixture modules directory must contain source files');
  const depth = directoryPath.split('/').length;
  const digest = sha256(Buffer.from(['revision-source-directory-v1', jobId, runId, revisionId,
    sourceSha256, directoryPath, String(low), String(depth)].join('\0'), 'utf8'));
  return `dir_${low}_${depth}_${digest}`;
}

function manifestFile(path, sha, roles, acceptedImplementation = null) {
  return { path, sha256: sha, generator, promptSha256: null, acceptedImplementation,
    contentKind: 'utf8-text', roles: [...roles].sort(), entityIds: [] };
}

async function writeBatch(directory, entries) {
  for (let offset = 0; offset < entries.length; offset += 256) {
    await Promise.all(entries.slice(offset, offset + 256).map(async ([relative, content]) => {
      const path = join(directory, ...relative.split('/'));
      await fs.mkdir(dirname(path), { recursive: true, mode: 0o700 });
      await fs.writeFile(path, content, { flag: 'wx', mode: 0o600 });
    }));
  }
}

export async function seedSourceTreeFixture(root, fileCount = sourceFiles) {
  assert.ok(Number.isSafeInteger(fileCount) && fileCount >= 2 && fileCount <= sourceFiles + 1,
    'source fixture file count must include Makefile and stay within one file over the D0 ceiling');
  const absoluteRoot = resolve(root);
  await fs.mkdir(absoluteRoot, { recursive: true, mode: 0o700 });
  const jobId = sha256(Buffer.from('job:d0-source-tree-fixture-v1')).slice(0, 32);
  const jobDirectory = join(absoluteRoot, jobId);
  await fs.mkdir(jobDirectory, { mode: 0o700 });

  const binary = elfHeader();
  const binarySha256 = sha256(binary);
  // Keep this fixture inside the job-retention window when browser CI runs it.
  // Source bytes, manifest records and revision identity remain deterministic.
  const createdAt = new Date(Date.now() - 300_000).toISOString();
  const filename = 'synthetic-source-tree.elf';
  const job = {
    id: jobId,
    filename,
    status: 'uploaded',
    created_at: createdAt,
    updated_at: createdAt,
    size_bytes: binary.length,
    binary_path: join(jobDirectory, 'input.elf'),
    metadata: {
      format: 'ELF64', endianness: 'little', elf_version: 1, os_abi: 'System V', object_type: 'executable',
      machine: 'x86-64', entry_point: 0, elf_header_size: 64, program_header_count: 0,
      section_header_count: 0, section_name_table_index: 0,
    },
  };
  const jobBytes = Buffer.from(JSON.stringify(job));
  await fs.writeFile(join(jobDirectory, 'input.elf'), binary, { flag: 'wx', mode: 0o600 });
  await fs.writeFile(join(jobDirectory, 'job.json'), jobBytes, { flag: 'wx', mode: 0o600 });

  const sourceRoot = join(jobDirectory, 'reports', 'runs', runId, 'source-tree');
  const entries = [
    ['Makefile', Buffer.from('# Inert D0 source-tree fixture; no compiler or build is invoked.\n')],
  ];
  for (let index = 0; index < fileCount - 1; index++) {
    const module = `m_${String(index).padStart(5, '0')}`;
    entries.push([`src/modules/${module}.c`, Buffer.from(`/* Inert D0 source fixture ${String(index).padStart(5, '0')}. */\n`)]);
  }
  await writeBatch(sourceRoot, entries);

  const files = [];
  for (const [path, content] of entries) {
    const sha = sha256(content);
    const roles = path === 'Makefile'
      ? ['archive-payload', 'build-definition', 'build-input', 'editable', 'viewable']
      : ['archive-payload', 'build-input', 'editable', 'module-implementation', 'viewable'];
    files.push({ path, bytes: content.length, sha256: sha, roles,
      manifest: manifestFile(path, sha, roles, path === 'Makefile' ? null : false) });
  }
  files.sort((left, right) => left.path < right.path ? -1 : left.path > right.path ? 1 : 0);
  const sourceSha256 = sourceRevision(files);
  const modulesDirectoryId = revisionSourceDirectoryId(jobId, runId, revisionId, sourceSha256, files, 'src/modules');
  const manifest = {
    schemaVersion: 3,
    profileId,
    profileSha256,
    inputSha256: binarySha256,
    files: files.map((file) => file.manifest),
    unresolvedEntityIds: [],
    unresolvedImplementationIds: [],
  };
  const descriptor = {
    schemaVersion: 3,
    sourceRevisionSha256: sourceSha256,
    sourceInputs: files.filter((file) => file.roles.includes('build-input')).map(({ path, bytes, sha256: sha }) => ({ path, bytes, sha256: sha })),
  };
  const reportsDirectory = join(sourceRoot, 'reports');
  await fs.mkdir(reportsDirectory, { recursive: true, mode: 0o700 });
  await fs.writeFile(join(sourceRoot, 'source_tree_manifest.json'), JSON.stringify(manifest, null, 2) + '\n', { flag: 'wx', mode: 0o600 });
  await fs.writeFile(join(reportsDirectory, 'build_contract.json'), JSON.stringify(descriptor, null, 2) + '\n', { flag: 'wx', mode: 0o600 });

  const state = {
    schemaVersion: 1,
    jobId,
    version: 'version_source_d0',
    legacy: { originalJobSha256: sha256(jobBytes), status: 'uploaded', recoveredInterrupted: false },
    attempts: [{
      runId, jobId, workflow: 'reconstruct', state: 'completed', version: 'attempt_version_source_d0',
      createdAt, startedAt: createdAt, endedAt: createdAt, previousRunId: null, inputRevisionId: null,
      harnessCapabilityId: null,
      limits: { wallClockMs: '600000', idleMs: '600000', maxOutputBytes: '33554432', maxToolCalls: '0' },
      terminalReason: 'COMPLETED', usage: null, candidate: { revisionId, sourceSha256 }, acceptedRevision: null,
    }],
    acceptedRevision: null,
  };
  await fs.writeFile(join(jobDirectory, 'workflow-state.json'), JSON.stringify(state), { flag: 'wx', mode: 0o600 });

  return { jobId, runId, revisionId, modulesDirectoryId, fileCount, sourceSha256, binarySha256, profileId, profileSha256,
    manifestPath: `reports/runs/${runId}/source-tree/source_tree_manifest.json`,
    descriptorPath: `reports/runs/${runId}/source-tree/reports/build_contract.json` };
}

if (process.argv[1] && resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  const { values } = parseArgs({ options: {
    root: { type: 'string' },
    files: { type: 'string', default: String(sourceFiles) },
  } });
  assert.ok(values.root && isAbsolute(values.root), 'pass --root /absolute/job-store');
  assert.ok(Number.isSafeInteger(Number(values.files)), '--files must be an integer');
  assert.equal(profileSha256.length, 64);
  const result = await seedSourceTreeFixture(values.root, Number(values.files));
  console.log(JSON.stringify(result));
}
