// Verifies every retained build/packaged-browser-*/ report with the strict
// bounded loader (issue #1882). Evidence-format integrity only, not authentication.
// Exits 1 if any retained directory has a missing, corrupt, stale or unresolved piece.
// Separately, every integrity-verified passed session report must pass the availability-notice
// semantic gate (#1894/#1895): status=passed alone is not accepted as notice coverage.
// That gate also bounded-reads each fixed notice-*.png beside the report and requires its size and sha256
// to equal the recorded values; the PNGs are not part of the format-integrity manifest.
// Passed session reports must then also pass the #1896 connection-notice gate (offline/reconnected evidence
// and its four fixed connection-*.png files, cross-checked the same way); a missing section fails closed.
// With --require-responsive-audit, every passed audit report must also pass the #619 responsive gate
// (fixed-name, PNG-validated clips). Opt-in so reports retained before #619 coverage keep their format verdict.
// With --require-real-zoom, every passed audit report must also carry passing auditRealZoom evidence (1x calibration,
// genuine 200%/400% page zoom, counted methods, cleanup records, Chrome identity) and its retained PNGs must match.
// With --require-read-states, every passed audit report must also carry the bounded #628 read-state slice, closed late
// target cleanup and its complete fixed-name PNG set; the verifier recomputes the slice and PNG hashes on readback.
import { readFileSync } from 'node:fs';
import { isAbsolute, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { parseArgs } from 'node:util';
import { loadReport, verifyRetainedReports } from './packaged-browser-report.mjs';
import { applySessionNoticeGate } from './packaged-browser-a11y-notices.mjs';
import { applyConnectionNoticeGate } from './packaged-browser-connection-notice.mjs';
import { applyAuditResponsiveGate } from './packaged-browser-responsive.mjs';
import { applyRealZoomGate } from './packaged-browser-real-zoom.mjs';
import { applyAuditReadStatesGate } from './packaged-browser-read-states-gate.mjs';

let parent, requiredModes, requireResponsive, requireRealZoom, requireReadStates;
try {
  const { values, positionals } = parseArgs({ options: { 'require-modes': { type: 'string' }, 'require-responsive-audit': { type: 'boolean' }, 'require-real-zoom': { type: 'boolean' }, 'require-read-states': { type: 'boolean' } }, allowPositionals: true });
  parent = positionals[0] ?? join(fileURLToPath(new URL('..', import.meta.url)), 'build');
  requireResponsive = values['require-responsive-audit'] === true;
  requireRealZoom = values['require-real-zoom'] === true;
  requireReadStates = values['require-read-states'] === true;
  requiredModes = values['require-modes'] === undefined ? [] : values['require-modes'].split(',');
  if (positionals.length > 1 || !isAbsolute(parent) || requiredModes.some(mode => !/^[a-z][a-z0-9-]*$/.test(mode)) || new Set(requiredModes).size !== requiredModes.length)
    throw new Error('Invalid parent or required modes');
} catch {
  console.error('Usage: node scripts/verify-packaged-browser-reports.mjs [/absolute/parent] [--require-modes mode1,mode2,...] [--require-responsive-audit] [--require-real-zoom] [--require-read-states]');
  process.exit(2);
}
const noticed = await applyConnectionNoticeGate(await applySessionNoticeGate(await verifyRetainedReports(parent, { requiredModes }), directory => loadReport(directory)), directory => loadReport(directory));
const responsive = requireResponsive ? await applyAuditResponsiveGate(noticed, directory => loadReport(directory)) : noticed;
const zoomed = requireRealZoom ? await applyRealZoomGate(responsive, directory => loadReport(directory)) : responsive;
const sequences = requireReadStates ? JSON.parse(readFileSync(join(fileURLToPath(new URL('..', import.meta.url)), 'scripts/packaged-browser-read-state-sequences.json'), 'utf8')) : undefined;
const results = requireReadStates ? await applyAuditReadStatesGate(zoomed, directory => loadReport(directory), { sequences }) : zoomed;
for (const r of results) console.log(`${r.ok ? 'verified' : 'INVALID '} ${r.directory}${r.ok ? ` status=${r.status}${r.gate ? ` notice-gate=${r.gate}` : ''}${r.connectionGate ? ` connection-gate=${r.connectionGate}` : ''}${r.responsiveGate ? ` responsive-gate=${r.responsiveGate}` : ''}${r.realZoomGate ? ` real-zoom-gate=${r.realZoomGate}` : ''}${r.readStatesGate ? ` read-states-gate=${r.readStatesGate}` : ''}` : `: ${r.error}`}`);
if (results.length === 0) console.log(`No retained packaged-browser report directories under ${parent}`);
if (results.some(r => !r.ok)) process.exitCode = 1;
