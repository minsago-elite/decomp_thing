// @vitest-environment node
import { createHash } from 'node:crypto';
import { readFile } from 'node:fs/promises';
import type { EmittedFile, NormalizedOutputOptions, OutputBundle, PluginContext } from 'rolldown';
import { expect, test } from 'vitest';
import { bundleComposition } from '../vite.config';

test('build hook anchors page and worker owners plus exact lockfile bytes in a content-addressed asset', async () => {
  const plugin = bundleComposition([{ chunk: 'assets/worker.js', owner: 'application', feature: 'sources' }]);
  const hook = plugin.generateBundle;
  const generate = typeof hook === 'function' ? hook : hook?.handler;
  if (!generate) throw new Error('Missing build ownership hook');
  const emitted: EmittedFile[] = [];
  const context = { emitFile(file: EmittedFile) { emitted.push(file); return 'anchor'; } } as unknown as PluginContext;
  const bundle = {
    'assets/page.js': { type: 'chunk', fileName: 'assets/page.js', modules: {
      '/project/frontend/src/main.tsx': { renderedLength: 5 },
      '/project/frontend/node_modules/preact/index.js': { renderedLength: 8 },
      '/project/frontend/node_modules/preact/hooks.js': { renderedLength: 3 },
      '/project/frontend/node_modules/unused/index.js': { renderedLength: 0 },
    } },
  } as unknown as OutputBundle;
  await generate.call(context, {} as NormalizedOutputOptions, bundle, false);
  expect(emitted).toHaveLength(1);
  const asset = emitted[0];
  if (asset?.type !== 'asset' || typeof asset.source !== 'string') throw new Error('Missing ownership asset');
  const lockfile = await readFile(new URL('../package-lock.json', import.meta.url));
  expect(JSON.parse(asset.source)).toEqual({ schemaVersion: 1,
    chunkOwners: { 'assets/page.js': ['application', 'preact'], 'assets/worker.js': ['application'] },
    lockfileSha256: createHash('sha256').update(lockfile).digest('hex') });
  expect(asset.fileName).toBe(`assets/bundle-ownership-${createHash('sha256').update(asset.source).digest('hex')}.json`);
  expect(asset.source).not.toContain('/project');
});
