// A standalone classic script: read display-only state before styles or modules can paint.
(() => {
  let theme = 'system';
  let motion = 'system';
  try {
    const raw = window.localStorage.getItem('decomp.display-preferences.v1');
    if (raw !== null && raw.length <= 256) {
      const value = JSON.parse(raw);
      if (typeof value === 'object' && value !== null && !Array.isArray(value)
        && Object.keys(value).sort().join(',') === 'motion,theme,version' && value.version === 1
        && ['system', 'light', 'dark'].includes(value.theme) && ['system', 'reduce'].includes(value.motion)) {
        theme = value.theme;
        motion = value.motion;
      }
    }
  } catch { /* Unavailable or malformed storage uses system settings without rewriting it. */ }
  document.documentElement.setAttribute('data-theme', theme);
  document.documentElement.setAttribute('data-motion', motion);
})();
