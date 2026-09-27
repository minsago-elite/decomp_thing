import assert from 'node:assert/strict';

function luminance(color) {
  const match = /^rgb\((\d+), (\d+), (\d+)\)$/.exec(color);
  assert.ok(match, `Contrast measurement requires opaque sRGB, received ${color}`);
  const channels = match.slice(1).map(value => Number(value) / 255)
    .map(value => value <= 0.04045 ? value / 12.92 : ((value + 0.055) / 1.055) ** 2.4);
  return channels.reduce((sum, value, index) => sum + value * [0.2126, 0.7152, 0.0722][index], 0);
}
function contrast(a, b) {
  const values = [luminance(a), luminance(b)].sort((x, y) => x - y);
  return (values[1] + 0.05) / (values[0] + 0.05);
}

// Scoped to this opaque light-theme form; fail rather than infer alpha compositing.
export async function qualifyFilterContrast({ tab, cdp, evaluate }) {
  await evaluate(tab, `document.querySelector('[name="search"]').focus()`);
  const measurements = [];
  for (const name of ['search', 'status', 'createdAfter', 'createdBefore', 'sort', 'limit']) {
    const style = await evaluate(tab, `(() => {
      const field = document.activeElement;
      const style = getComputedStyle(field);
      let parent = field.parentElement;
      while (parent && getComputedStyle(parent).backgroundColor === 'rgba(0, 0, 0, 0)') parent = parent.parentElement;
      return { name: field.name, border: style.borderTopColor, borderStyle: style.borderTopStyle,
        borderWidth: parseFloat(style.borderTopWidth), background: style.backgroundColor,
        adjacent: parent ? getComputedStyle(parent).backgroundColor : null,
        focusVisible: field.matches(':focus-visible'), outline: style.outlineColor,
        outlineStyle: style.outlineStyle, outlineWidth: parseFloat(style.outlineWidth) };
    })()`);
    assert.equal(style.name, name, 'Native Tab order must reach each filter exactly once');
    assert.ok(style.borderStyle !== 'none' && style.borderWidth >= 1);
    assert.ok(style.focusVisible && style.outlineStyle !== 'none' && style.outlineWidth >= 2);
    const borderContrast = contrast(style.border, style.adjacent);
    const focusContrast = contrast(style.outline, style.adjacent);
    assert.ok(borderContrast >= 3, `${name} border contrast ${borderContrast} is below 3:1`);
    assert.ok(focusContrast >= 3, `${name} focus contrast ${focusContrast} is below 3:1`);
    measurements.push({ ...style, borderContrast, focusContrast });
    await cdp.call('Input.dispatchKeyEvent', { type: 'keyDown', key: 'Tab', code: 'Tab', windowsVirtualKeyCode: 9 }, tab.sessionId);
    await cdp.call('Input.dispatchKeyEvent', { type: 'keyUp', key: 'Tab', code: 'Tab', windowsVirtualKeyCode: 9 }, tab.sessionId);
  }
  return measurements;
}
