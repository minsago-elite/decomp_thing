import { readdirSync, readFileSync, statSync } from 'node:fs';
import { join, relative, resolve } from 'node:path';
import ts from 'typescript';
import { expect, it } from 'vitest';
import { displayLocale, formatExactBytes, formatExactCount, formatExactTimestamp, pluralForm } from '../src/copy/format';
import { receiptAge } from '../src/copy/receiptAge';

// Interface words live in src/copy/* and values become text in src/copy/format.ts (#621), so a
// locale can be added by replacing catalogs without rewriting components. This gate parses every
// component and fails on human-facing text written inline.
const root = resolve(process.cwd(), 'src');
const textAttributes = new Set(['aria-label', 'aria-description', 'aria-roledescription', 'aria-valuetext', 'title', 'placeholder', 'alt', 'label']);
// Technical strings that read like words but are identifiers, selectors or keyword tables.
const technical = new Set(['Escape']);
// The API layer produces diagnostics and protocol values only; it renders no interface text.
const exempt = (path: string) => path.startsWith('copy/') || path.startsWith('api/') || path === 'sources/highlight.ts';

function sources(directory: string, found: string[] = []): string[] {
  for (const name of readdirSync(directory)) {
    const path = join(directory, name);
    if (statSync(path).isDirectory()) sources(path, found);
    else if (/\.tsx?$/.test(name) && !name.endsWith('.d.ts')) found.push(path);
  }
  return found;
}

function attributeName(node: ts.Node): string | null {
  for (let current: ts.Node | undefined = node.parent; current; current = current.parent) {
    if (ts.isJsxAttribute(current)) return current.name.getText();
    if (ts.isJsxElement(current) || ts.isJsxSelfClosingElement(current) || ts.isFunctionLike(current)) return null;
  }
  return null;
}

function technicalCall(node: ts.Node): boolean {
  const parent = node.parent;
  if (!parent || !(ts.isCallExpression(parent) || ts.isNewExpression(parent))) return false;
  const callee = parent.expression.getText();
  return /Error$|querySelector|matchMedia|matches|closest|getAttribute|setAttribute|addEventListener|removeEventListener|Worker/.test(callee);
}

function inlineCopy(): string[] {
  const findings: string[] = [];
  for (const file of sources(root)) {
    const path = relative(root, file).replaceAll('\\', '/');
    if (exempt(path)) continue;
    const source = ts.createSourceFile(file, readFileSync(file, 'utf8'), ts.ScriptTarget.Latest, true,
      file.endsWith('.tsx') ? ts.ScriptKind.TSX : ts.ScriptKind.TS);
    const report = (node: ts.Node, kind: string, text: string) =>
      findings.push(`${path}:${source.getLineAndCharacterOfPosition(node.getStart()).line + 1} ${kind} ${JSON.stringify(text.trim()).slice(0, 80)}`);
    const visit = (node: ts.Node) => {
      // Letters, or punctuation that composes sentences around values, belong in a catalog template.
      if (ts.isJsxText(node) && (/\p{L}/u.test(node.text) || /[:;,.!?]/.test(node.text))) report(node, 'jsx-text', node.text);
      if (ts.isStringLiteral(node) || ts.isNoSubstitutionTemplateLiteral(node)) {
        const attribute = attributeName(node);
        const text = node.text;
        const compared = ts.isBinaryExpression(node.parent) && [ts.SyntaxKind.EqualsEqualsEqualsToken, ts.SyntaxKind.ExclamationEqualsEqualsToken]
          .includes(node.parent.operatorToken.kind);
        if (attribute !== null && !textAttributes.has(attribute)) { /* IDs, roles, classes and other DOM tokens. */ }
        else if (attribute !== null) { if (!compared && /\p{L}/u.test(text)) report(node, 'attribute', text); }
        else if ( !ts.isImportDeclaration(node.parent) && !ts.isExportDeclaration(node.parent)
          && !technicalCall(node) && !technical.has(text) && /\p{L}{2,}[,.;:]?\s+\p{L}{2,}/u.test(text)) report(node, 'prose', text);
      }
      if (ts.isTemplateExpression(node) && (attributeName(node) === null || textAttributes.has(attributeName(node)!))) {
        const parts = [node.head.text, ...node.templateSpans.map(span => span.literal.text)];
        if (parts.some(part => /\p{L}{2,}\s+\p{L}{2,}/u.test(part)) || (attributeName(node) !== null && parts.some(part => /[:,.]\s/.test(part))))
          report(node, 'template', parts.join('…'));
      }
      ts.forEachChild(node, visit);
    };
    visit(source);
  }
  return findings;
}

it('keeps human-facing interface text in the copy catalogs instead of components', () => {
  expect(inlineCopy()).toEqual([]);
});

it('formats exact values through one locale-ready layer without rounding or dropping timezone context', () => {
  expect(displayLocale).toBe('en');
  expect(formatExactCount('18446744073709551615')).toBe('18446744073709551615');
  expect(formatExactBytes('9007199254740993')).toBe('9007199254740993 bytes');
  expect(formatExactTimestamp('2026-09-05T00:00:00.000000001Z')).toBe('2026-09-05 00:00:00.000000001 UTC');
  expect(formatExactTimestamp('2026-09-05T09:00:00+09:00')).toBe('2026-09-05 09:00:00+09:00');
  expect(pluralForm(1, { one: 'one', other: 'other' })).toBe('one');
  expect(pluralForm(2, { one: 'one', other: 'other' })).toBe('other');
  expect([65, 125, 3700, 7300, 90000, 200000].map(receiptAge)).toEqual([
    'about 1 minute ago', 'about 2 minutes ago', 'about 1 hour ago', 'about 2 hours ago', 'about 1 day ago', 'about 2 days ago',
  ]);
});
