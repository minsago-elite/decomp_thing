// Artifact-only redaction. Product canary checks must continue to inspect raw observations.
export function createArtifactSanitizer(sensitiveValues) {
  const safeDiagnostic = (value) => {
    let safe = String(value).replaceAll(/#bootstrap=[A-Za-z0-9_-]+/g, '#bootstrap=[redacted]');
    for (const sensitive of sensitiveValues) if (sensitive) safe = safe.replaceAll(sensitive, '[redacted]');
    return safe;
  };
  const safeEvidence = (value) => {
    if (Array.isArray(value)) return value.map(safeEvidence);
    if (value && typeof value === 'object') return Object.fromEntries(Object.entries(value).map(([key, item]) => [safeDiagnostic(key), safeEvidence(item)]));
    return typeof value === 'string' ? safeDiagnostic(value) : value;
  };
  return { safeDiagnostic, safeEvidence };
}

// Fail closed on unavailable DOM or credential text, even on successful journey captures.
// Editable values are inspected before hiding controls, since value properties need not be in HTML.
export function screenshotGuardExpression(sensitiveValues) {
  return `(() => {
    if (location.hash !== '' || !document.body || !document.documentElement) return false;
    const fields = [...document.querySelectorAll('input, textarea, [contenteditable]')];
    const surfaces = [document.documentElement.outerHTML, document.body.innerText, ...fields.map(element => element.value ?? element.textContent ?? '')];
    if (${JSON.stringify(sensitiveValues)}.filter(Boolean).some(value => surfaces.some(text => text.includes(value)))) return false;
    fields.forEach(element => { element.style.visibility = 'hidden'; });
    return true;
  })()`;
}
