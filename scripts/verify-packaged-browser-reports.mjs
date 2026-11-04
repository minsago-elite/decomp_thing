// Verifies every retained build/packaged-browser-*/ report with the strict
// bounded loader (issue #1882). Evidence-format integrity only, not authentication.
// Exits 1 if any retained directory has a missing, corrupt, stale or unresolved piece.
// Separately, every integrity-verified passed session report must pass the availability-notice
// semantic gate (#1894/#1895): status=passed alone is not accepted as notice coverage.
// That gate also bounded-reads each fixed notice-*.png beside the report and requires its size and sha256
// to equal the recorded values; the PNGs are not part of the format-integrity manifest.
// With --require-responsive-audit, every passed audit report must also pass the #619 responsive gate
// (fixed-name, PNG-validated clips). Opt-in so reports retained before #619 coverage keep their format verdict.
import { isAbsolute, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { parseArgs } from 'node:util';
import { loadReport, verifyRetainedReports } from './packaged-browser-report.mjs';
import { applySessionNoticeGate } from './packaged-browser-a11y-notices.mjs';
import { applyAuditResponsiveGate } from './packaged-browser-responsive.mjs';

let parent, requiredModes, requireResponsive;
try {
  const { values, positionals } = parseArgs({ options: { 'require-modes': { type: 'string' }, 'require-responsive-audit': { type: 'boolean' } }, allowPositionals: true });
  parent = positionals[0] ?? join(fileURLToPath(new URL('..', import.meta.url)), 'build');
  requireResponsive = values['require-responsive-audit'] === true;
  requiredModes = values['require-modes'] === undefined ? [] : values['require-modes'].split(',');
  if (positionals.length > 1 || !isAbsolute(parent) || requiredModes.some(mode => !/^[a-z][a-z0-9-]*$/.test(mode)) || new Set(requiredModes).size !== requiredModes.length)
    throw new Error('Invalid parent or required modes');
} catch {
  console.error('Usage: node scripts/verify-packaged-browser-reports.mjs [/absolute/parent] [--require-modes mode1,mode2,...] [--require-responsive-audit]');
  process.exit(2);
}
const noticed = await applySessionNoticeGate(await verifyRetainedReports(parent, { requiredModes }), directory => loadReport(directory));
const results = requireResponsive ? await applyAuditResponsiveGate(noticed, directory => loadReport(directory)) : noticed;
for (const r of results) console.log(`${r.ok ? 'verified' : 'INVALID '} ${r.directory}${r.ok ? ` status=${r.status}${r.gate ? ` notice-gate=${r.gate}` : ''}${r.responsiveGate ? ` responsive-gate=${r.responsiveGate}` : ''}` : `: ${r.error}`}`);
if (results.length === 0) console.log(`No retained packaged-browser report directories under ${parent}`);
if (results.some(r => !r.ok)) process.exitCode = 1;
