// Verifier-side semantic and retained-artifact gate for #628's bounded packaged audit slice.
// This always re-assesses the report and PNG files; it never trusts the driver's stored gate verdict.
import { assessReadStatesReport, FIXED_PNG_NAMES, verifyRetainedPng } from './packaged-browser-read-states.mjs';

const cap = (value) => String(value ?? '').slice(0, 200);

export async function applyAuditReadStatesGate(results, load, { sequences } = {}) {
  for (const result of results) {
    if (!result.ok || result.mode !== 'audit' || result.status !== 'passed') continue;
    let failures = [];
    try {
      const report = await load(result.directory);
      const section = report.auditReadStates;
      failures.push(...assessReadStatesReport(section, { sequences }));

      const parent = report.auditReadStatesParent;
      if (parent?.schema !== 'packaged-read-states-parent/v1') failures.push('parent evidence schema missing');
      if (!Array.isArray(parent?.lateSink) || parent.lateSink.length !== 0) failures.push('parent late sink is not empty');
      const lateCleanup = parent?.lateTargetCleanup;
      if (!Array.isArray(lateCleanup) || lateCleanup.some((entry) => entry?.outcome !== 'closed'
        || typeof entry.targetId !== 'string' || entry.targetId.length === 0)
        || (Array.isArray(lateCleanup) && new Set(lateCleanup.map((entry) => entry?.targetId)).size !== lateCleanup.length))
        failures.push('late target cleanup is missing, unresolved or unbound');
      if (!Array.isArray(parent?.assessment) || parent.assessment.length !== 0) failures.push('parent evidence assessment is not empty');
      if (report.auditReadStatesGate?.passed !== true || !Array.isArray(report.auditReadStatesGate?.failures) || report.auditReadStatesGate.failures.length !== 0)
        failures.push('driver read-state gate record is missing or failed');

      const screenshots = (section?.cases ?? []).map((entry) => entry?.screenshot).filter(Boolean);
      const names = screenshots.map((entry) => entry.name).sort();
      const expected = [...FIXED_PNG_NAMES].sort();
      if (names.length !== expected.length || names.some((name, index) => name !== expected[index])) {
        failures.push('retained screenshot set does not match the fixed read-state names');
      } else {
        for (const screenshot of screenshots) {
          try { await verifyRetainedPng(result.directory, screenshot); }
          catch (error) { failures.push(cap(error?.message ?? error)); }
        }
      }
    } catch (error) { failures.push(`report reload or read-state assessment failed: ${cap(error?.message ?? error)}`); }

    result.readStatesGate = failures.length ? 'failed' : 'passed';
    if (failures.length) {
      result.ok = false;
      result.error = `integrity verified; #628 packaged read-state gate failed: ${failures.slice(0, 6).join('; ')}${failures.length > 6 ? ` (+${failures.length - 6} more)` : ''}`;
    }
  }
  return results;
}
