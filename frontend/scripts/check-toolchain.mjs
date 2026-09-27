import { readFileSync } from 'node:fs';

const expected = JSON.parse(readFileSync(new URL('../package.json', import.meta.url), 'utf8'));
const npmVersion = process.env.npm_config_user_agent?.match(/^npm\/([^ ]+)/)?.[1];
if (process.versions.node !== expected.engines.node || npmVersion !== expected.engines.npm) {
  throw new Error(
    `Frontend requires Node ${expected.engines.node} and npm ${expected.engines.npm}; ` +
      `found Node ${process.versions.node} and npm ${npmVersion ?? 'unknown'}. ` +
      'Use the pinned Node distribution and run commands through npm; see frontend/README.md.',
  );
}
