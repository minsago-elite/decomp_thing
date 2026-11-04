// Verifies every retained build/packaged-browser-*/ report with the strict
// bounded loader (issue #1882). Evidence-format integrity only, not authentication.
// Exits 1 if any retained directory has a missing, corrupt, stale or unresolved piece.
import { isAbsolute, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { parseArgs } from 'node:util';
import { verifyRetainedReports } from './packaged-browser-report.mjs';

let parent, requiredModes;
try {
  const { values, positionals } = parseArgs({ options: { 'require-modes': { type: 'string' } }, allowPositionals: true });
  parent = positionals[0] ?? join(fileURLToPath(new URL('..', import.meta.url)), 'build');
  requiredModes = values['require-modes'] === undefined ? [] : values['require-modes'].split(',');
  if (positionals.length > 1 || !isAbsolute(parent) || requiredModes.some(mode => !/^[a-z][a-z0-9-]*$/.test(mode)) || new Set(requiredModes).size !== requiredModes.length)
    throw new Error('Invalid parent or required modes');
} catch {
  console.error('Usage: node scripts/verify-packaged-browser-reports.mjs [/absolute/parent] [--require-modes mode1,mode2,...]');
  process.exit(2);
}
const results = await verifyRetainedReports(parent, { requiredModes });
for (const r of results) console.log(`${r.ok ? 'verified' : 'INVALID '} ${r.directory}${r.ok ? ` status=${r.status}` : `: ${r.error}`}`);
if (results.length === 0) console.log(`No retained packaged-browser report directories under ${parent}`);
if (results.some(r => !r.ok)) process.exitCode = 1;
