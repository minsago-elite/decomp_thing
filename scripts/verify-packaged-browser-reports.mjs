// Verifies every retained build/packaged-browser-*/ report with the strict
// bounded loader (issue #1882). Evidence-format integrity only, not authentication.
// Exits 1 if any retained directory has a missing, corrupt, stale or unresolved piece.
import { isAbsolute, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { verifyRetainedReports } from './packaged-browser-report.mjs';

const parent = process.argv[2] ?? join(fileURLToPath(new URL('..', import.meta.url)), 'build');
if (!isAbsolute(parent)) { console.error('Usage: node scripts/verify-packaged-browser-reports.mjs [/absolute/parent]'); process.exit(2); }
const results = await verifyRetainedReports(parent);
for (const r of results) console.log(`${r.ok ? 'verified' : 'INVALID '} ${r.directory}${r.ok ? ` status=${r.status}` : `: ${r.error}`}`);
if (results.length === 0) console.log(`No retained packaged-browser report directories under ${parent}`);
if (results.some(r => !r.ok)) process.exitCode = 1;
