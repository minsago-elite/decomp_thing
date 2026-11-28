/** Build a browser-side timer for an in-app route commit and focused heading. */
export function routeFeedbackExpression({ href, headingId, headingText, timeoutMs = 10_000 }) {
  if (typeof href !== 'string' || typeof headingId !== 'string' || typeof headingText !== 'string'
      || !Number.isSafeInteger(timeoutMs) || timeoutMs < 1) throw new TypeError('invalid route feedback measurement');
  const target = new URL(href, 'http://soak.invalid');
  const config = JSON.stringify({ href, path: target.pathname, search: target.search, headingId, headingText, timeoutMs });
  return `(async () => {
    const expected = ${config};
    const started = performance.now();
    const link = [...document.querySelectorAll('a')].find(item => item.getAttribute('href') === expected.href);
    if (!link) return { found: false, address: location.pathname + location.search };
    link.click();
    const address = location.pathname + location.search;
    if (address !== expected.path + expected.search) return { found: true, address, settled: false, elapsedMs: performance.now() - started };
    const settled = await new Promise(resolve => {
      let frame = 0;
      let timer = 0;
      let finished = false;
      const finish = value => {
        if (finished) return;
        finished = true;
        cancelAnimationFrame(frame);
        clearTimeout(timer);
        resolve(value);
      };
      const check = () => {
        if (location.pathname === expected.path && location.search === expected.search) {
          const heading = document.getElementById(expected.headingId);
          if (heading && heading.closest('main') && heading.textContent.trim() === expected.headingText
              && document.activeElement === heading) {
            finish(true);
            return;
          }
        }
        frame = requestAnimationFrame(check);
      };
      timer = setTimeout(() => finish(false), expected.timeoutMs);
      frame = requestAnimationFrame(check);
    });
    return { found: true, address, settled, elapsedMs: performance.now() - started,
      settledAddress: location.pathname + location.search };
  })()`;
}
