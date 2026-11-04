// @vitest-environment jsdom
import { readFileSync, readdirSync, statSync } from 'node:fs';
import { join, resolve } from 'node:path';
import { afterEach, beforeEach, expect, it } from 'vitest';

// Reflow contract for #619. jsdom has no layout engine, so these checks assert the computed cascade
// of the real stylesheet (not its text) and the DOM structure of scroll regions. Rendered geometry
// (1440x900, 390x844, 320/640 CSS px) is retained separately in build/orchestration/responsive-619-browser/.
const root = process.cwd();
const css = readFileSync(resolve(root, 'src/styles/app.css'), 'utf8');
let style: HTMLStyleElement;

beforeEach(() => {
  style = document.createElement('style');
  style.textContent = css;
  document.head.append(style);
});
afterEach(() => { style.remove(); document.body.replaceChildren(); });

function mount(html: string): HTMLElement {
  const host = document.createElement('div');
  host.innerHTML = html;
  document.body.append(host);
  return host;
}
const computed = (element: Element | null) => {
  expect(element).not.toBeNull();
  return getComputedStyle(element as Element);
};
// jsdom's getComputedStyle does not cascade `overflow`; resolve it from the CSSOM with selector
// matching and specificity (source order breaks ties), ignoring media rules that do not apply.
function specificity(selector: string): number {
  const ids = (selector.match(/#[\w-]+/g) ?? []).length;
  const classes = (selector.match(/\.[\w-]+|\[[^\]]+\]|:(?!:)[\w-]+/g) ?? []).length;
  const types = (selector.replace(/#[\w-]+|\.[\w-]+|\[[^\]]+\]|::?[\w-]+(\([^)]*\))?/g, ' ').match(/[a-z][\w-]*/gi) ?? []).length;
  return ids * 10000 + classes * 100 + types;
}
function overflowX(element: Element | null): string {
  expect(element).not.toBeNull();
  let best = { weight: -1, value: 'visible' };
  let order = 0;
  for (const rule of Array.from(style.sheet?.cssRules ?? [])) {
    order++;
    if (!(rule instanceof CSSStyleRule)) continue;
    const value = rule.style.getPropertyValue('overflow-x') || rule.style.getPropertyValue('overflow').split(/\s+/)[0];
    if (!value) continue;
    for (const selector of rule.selectorText.split(',').map(part => part.trim())) {
      if (!(element as Element).matches(selector)) continue;
      const weight = specificity(selector) * 10000 + order;
      if (weight > best.weight) best = { weight, value };
    }
  }
  return best.value;
}
const px = (value: string) => { expect(value).toMatch(/^\d+(\.\d+)?px$/); return Number.parseFloat(value); };

it('keeps action, heading and label text whole-word while identifiers in code may break anywhere', () => {
  // Rendered 390px evidence: `overflow-wrap: anywhere` let flex/table items shrink until short
  // words split mid-word ("Inspect cases" at 78px); break-word keeps min-content at whole words.
  const host = mount(`<main><h1>t</h1><h2>t</h2><h3>t</h3><h4>t</h4><h5>t</h5><h6>t</h6>
    <details><summary>s</summary></details><label>l</label><fieldset><legend>g</legend></fieldset>
    <div class="job-actions"><button type="button">Inspect cases</button><a class="button-link" href="#x">Go</a></div>
    <p><code>0123456789abcdef0123456789abcdef</code></p></main>`);
  for (const selector of ['h1', 'h2', 'h3', 'h4', 'h5', 'h6', 'summary', 'label', 'legend', 'button', '.button-link']) {
    expect(computed(host.querySelector(selector)).overflowWrap, selector).toBe('break-word');
  }
  expect(computed(host.querySelector('button')).maxWidth).toBe('100%');
  expect(computed(host.querySelector('code')).overflowWrap).toBe('anywhere');
});

it('meets the 44px control target (docs/web-navigation.md) through the cascade, including header overrides', () => {
  const host = mount(`<header class="app-header"><button type="button">Display preferences</button></header>
    <main><nav class="job-actions"><a href="#o">Overview</a></nav><button type="button">Plain</button></main>`);
  // 2.75rem = 44px at the default 16px root size; a later more specific rule must not lower it.
  for (const selector of ['.app-header button', 'main > button', '.job-actions > a']) {
    expect(px(computed(host.querySelector(selector)).minHeight), selector).toBeGreaterThanOrEqual(44);
  }
});

it('scrolls preformatted text only in focusable regions; source rows and excerpts wrap instead', () => {
  const host = mount(`<main>
    <pre class="byte-preview" tabindex="0" aria-label="Hexadecimal prefix">00 ff</pre>
    <div class="source-row"><pre>line</pre></div>
    <ol class="source-search-results"><li><pre>excerpt</pre></li></ol></main>`);
  const preview = computed(host.querySelector('.byte-preview'));
  expect(overflowX(host.querySelector('.byte-preview'))).toBe('auto');
  expect(preview.maxWidth).toBe('100%');
  for (const selector of ['.source-row pre', '.source-search-results pre']) {
    const value = computed(host.querySelector(selector));
    expect(overflowX(host.querySelector(selector)), selector).not.toMatch(/auto|scroll/);
    expect(value.whiteSpace, selector).toBe('pre-wrap');
  }
});

it('keeps dense table words whole inside a scrolling region and gives byte previews a readable width', () => {
  const host = mount(`<main><section class="retained-cases"><div class="retained-case-table" role="region" tabindex="0" aria-label="Cases">
    <table><caption>Cases</caption><tbody><tr><th scope="row">Recorded outcome</th>
    <td><pre class="byte-preview" tabindex="0" aria-label="p">00</pre></td></tr></tbody></table></div></section></main>`);
  expect(overflowX(host.querySelector('.retained-case-table'))).toBe('auto');
  expect(computed(host.querySelector('.retained-case-table table')).overflowWrap).toBe('break-word');
  expect(computed(host.querySelector('th')).overflowWrap).toBe('break-word');
  expect(px(computed(host.querySelector('.retained-case-table .byte-preview')).minWidth)).toBeGreaterThanOrEqual(256);
});

function sources(dir: string): string[] {
  return readdirSync(dir).flatMap(name => {
    const path = join(dir, name);
    return statSync(path).isDirectory() ? sources(path) : path.endsWith('.tsx') ? [path] : [];
  });
}

it('places every view table directly in a labelled, focusable region wrapper (inventory)', () => {
  // Attribute order and formatting are irrelevant; the nearest element opened before <table> must be the wrapper.
  const failures: string[] = [];
  for (const file of sources(resolve(root, 'src'))) {
    const text = readFileSync(file, 'utf8');
    for (const match of text.matchAll(/<table[\s>]/g)) {
      const opening = [...text.slice(0, match.index).matchAll(/<div\b[^>]*>/g)].at(-1)?.[0] ?? '';
      const between = text.slice(text.lastIndexOf(opening, match.index), match.index);
      const wrapper = /class="retained-case-table"/.test(opening) && /role="region"/.test(opening)
        && /tabIndex=\{0\}/.test(opening) && /aria-label(?:ledby)?=/.test(opening) && !between.includes('</div>');
      if (!wrapper) failures.push(`${file.slice(root.length)}@${match.index}`);
    }
  }
  expect(failures).toEqual([]);
});
