import { mkdir, writeFile } from 'node:fs/promises';
import { fileURLToPath } from 'node:url';
import preact from '@preact/preset-vite';
import { defineConfig } from 'vite';
import type { Plugin, UserConfig } from 'vite';

const outputRoot = fileURLToPath(new URL('../build/frontend/', import.meta.url));
const displayBootstrapSource = fileURLToPath(new URL('./src/app/display-preferences-bootstrap.js', import.meta.url));
const displayBootstrapName = 'display-preferences-bootstrap';
interface ModuleOwner { chunk: string; owner: string }

function productionModuleOwner(id: string, renderedLength: number): string {
  const normalized = id.replaceAll('\\', '/');
  if (renderedLength > 0 && (
    /\/(?:tests|__tests__|fixtures|dev)\//.test(normalized) ||
    /\/preact\/(?:compat|debug|devtools)\//.test(normalized)
  )) throw new Error('Production bundle includes a test, fixture, debug or compatibility module.');
  return normalized.match(/\/node_modules\/((?:@[^/]+\/)?[^/]+)/)?.[1] ?? 'application';
}

/** Worker sub-builds share the production admission and owner inventory with the page build. */
function workerComposition(records: ModuleOwner[]): Plugin {
  return {
    name: 'decomp-worker-composition',
    apply: 'build',
    generateBundle(_options, bundle) {
      for (const entry of Object.values(bundle)) {
        if (entry.type !== 'chunk') continue;
        for (const [id, module] of Object.entries(entry.modules)) {
          const owner = productionModuleOwner(id, module.renderedLength);
          if (module.renderedLength > 0) records.push({ chunk: entry.fileName, owner });
        }
      }
    },
  };
}

/** Keep the display-only prelude a classic script, before CSS and the deferred module in both hosts. */
function displayPreferenceBootstrap(): Plugin {
  let base = '/';
  return {
    name: 'decomp-display-preferences-bootstrap',
    configResolved(config) { base = config.base; },
    transformIndexHtml: {
      order: 'post',
      handler(_html, context) {
        let file = 'src/app/display-preferences-bootstrap.js';
        if (context.bundle) {
          const matches = Object.values(context.bundle).filter(entry =>
            entry.type === 'chunk' && entry.facadeModuleId === displayBootstrapSource);
          const chunk = matches[0];
          if (matches.length !== 1 || !chunk || chunk.type !== 'chunk' || !chunk.isEntry || chunk.name !== displayBootstrapName
            || chunk.imports.length || chunk.dynamicImports.length || chunk.exports.length) {
            throw new Error('Display preference bootstrap must be one standalone entry without imports or exports.');
          }
          file = chunk.fileName;
        }
        return [{ tag: 'script', attrs: { src: `${base}${file}` }, injectTo: 'head-prepend' }];
      },
    },
  };
}

/** Build metadata stays outside the served output and contains no host paths. */
function bundleComposition(workerModules: ModuleOwner[]): Plugin {
  return {
    name: 'decomp-bundle-composition',
    apply: 'build',
    async writeBundle(_options, bundle) {
      const modules = Object.values(bundle)
        .filter((entry) => entry.type === 'chunk')
        .flatMap((entry) => Object.entries(entry.modules).map(([id, module]) => {
          return {
            chunk: entry.fileName,
            owner: productionModuleOwner(id, module.renderedLength),
            renderedBytes: module.renderedLength,
          };
        }))
        .filter((entry) => entry.renderedBytes > 0)
        .map(({ chunk, owner }) => ({ chunk, owner }))
        .concat(workerModules)
        .sort((left, right) => `${left.chunk}/${left.owner}`.localeCompare(`${right.chunk}/${right.owner}`));
      await mkdir(outputRoot, { recursive: true });
      await writeFile(`${outputRoot}bundle-composition.json`, JSON.stringify(modules, null, 2) + '\n');
    },
  };
}

export default defineConfig(async ({ command, mode, isPreview }): Promise<UserConfig> => {
  const workerModules: ModuleOwner[] = [];
  const dev = command === 'serve' && !isPreview;
  if (!dev && ['backend', 'fixtures'].includes(mode)) {
    throw new Error('Backend and fixture modes are development-only; use the ordinary production build.');
  }
  const development = dev ? await import('./dev/configuration.ts').then(({ developmentConfiguration, developmentSettings }) => {
    const settings = developmentSettings(mode, process.env);
    return { settings, ...developmentConfiguration(settings) };
  }) : null;
  return {
    plugins: [preact({ reactAliasesEnabled: false }), displayPreferenceBootstrap(), bundleComposition(workerModules), ...(development ? [development.plugin] : [])],
    worker: { format: 'es', plugins: () => [workerComposition(workerModules)] },
    base: development?.settings.basePath ?? './',
    publicDir: false,
    envPrefix: [],
    build: {
      outDir: `${outputRoot}dist`,
      emptyOutDir: true,
      assetsDir: 'assets',
      assetsInlineLimit: 0,
      manifest: true,
      sourcemap: false,
      target: 'es2022',
      rolldownOptions: {
        input: {
          index: fileURLToPath(new URL('./index.html', import.meta.url)),
          [displayBootstrapName]: displayBootstrapSource,
        },
      },
    },
    server: development?.server ?? { host: '127.0.0.1', strictPort: true },
    preview: { host: '127.0.0.1', strictPort: true },
  };
});
