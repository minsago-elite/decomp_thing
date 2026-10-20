import { readFileSync } from 'node:fs';

const expected = JSON.parse(readFileSync(new URL('../package.json', import.meta.url), 'utf8'));
const npmVersion = process.env.npm_config_user_agent?.match(/^npm\/([^ ]+)/)?.[1];
if (process.versions.node !== expected.engines.node || npmVersion !== expected.engines.npm) {
  throw new Error(
    `Frontend requires Node ${expected.engines.node} and npm ${expected.engines.npm}; ` +
      `found Node ${process.versions.node} and npm ${npmVersion ?? 'unknown'}. ` +
      'If a verified pinned installation already exists, select its bin directory. ' +
      'Otherwise, from the repository root, provision into a fresh repository-local directory with ' +
      '`mkdir -p build && export NPM_CONFIG_CACHE="$PWD/build/npm-download-cache" && ' +
      `frontend_node_parent="$(mktemp -d "$PWD/build/frontend-node-${expected.engines.node}-npm-${expected.engines.npm}.XXXXXX")" && ` +
      'bash scripts/install-frontend-node.sh "$frontend_node_parent/node" && ' +
      'export PATH="$frontend_node_parent/node/bin:$PATH"` and use npm. ' +
      'This leaves any stale installation in place and supplies an absent destination to the installer. ' +
      'Keep the actual installation path for future shells; see frontend/README.md.',
  );
}
