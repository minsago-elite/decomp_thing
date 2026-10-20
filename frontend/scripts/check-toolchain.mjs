import { readFileSync } from 'node:fs';

const expected = JSON.parse(readFileSync(new URL('../package.json', import.meta.url), 'utf8'));
const npmVersion = process.env.npm_config_user_agent?.match(/^npm\/([^ ]+)/)?.[1];
if (process.versions.node !== expected.engines.node || npmVersion !== expected.engines.npm) {
  throw new Error(
    `Frontend requires Node ${expected.engines.node} and npm ${expected.engines.npm}; ` +
      `found Node ${process.versions.node} and npm ${npmVersion ?? 'unknown'}. ` +
      'From the repository root, provision once into an absent directory with ' +
      '`mkdir -p build && export NPM_CONFIG_CACHE="$PWD/build/npm-download-cache" && ' +
      'bash scripts/install-frontend-node.sh "$PWD/build/frontend-node"`. ' +
      'Then select it with `export PATH="$PWD/build/frontend-node/bin:$PATH"` and use npm. ' +
      'For an existing installation, select its bin directory and repository-local npm cache; see frontend/README.md.',
  );
}
