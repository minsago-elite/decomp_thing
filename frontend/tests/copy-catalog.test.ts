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

// Follow only expressions whose value reaches JSX. Strings used to select a branch, index a
// record or call a protocol/formatting helper are not themselves rendered copy.
function renderedValue(node: ts.Node): boolean {
  let current = node;
  while (current.parent) {
    const parent = current.parent;
    if (ts.isJsxExpression(parent)) return true;
    if (ts.isParenthesizedExpression(parent) || ts.isAsExpression(parent)
      || ts.isSatisfiesExpression(parent) || ts.isNonNullExpression(parent) || ts.isArrayLiteralExpression(parent)
      || (ts.isConditionalExpression(parent) && current !== parent.condition)
      || (ts.isBinaryExpression(parent) && (
        [ts.SyntaxKind.PlusToken, ts.SyntaxKind.BarBarToken, ts.SyntaxKind.QuestionQuestionToken].includes(parent.operatorToken.kind)
        || (parent.operatorToken.kind === ts.SyntaxKind.AmpersandAmpersandToken && current === parent.right)
      ))) current = parent;
    else return false;
  }
  return false;
}

const copyFragment = (text: string) => /\p{L}|[:;,.!?]/u.test(text);

function inlineSourceCopy(source: ts.SourceFile, path: string): string[] {
  const findings: string[] = [];
  const report = (node: ts.Node, kind: string, text: string) =>
    findings.push(`${path}:${source.getLineAndCharacterOfPosition(node.getStart()).line + 1} ${kind} ${JSON.stringify(text.trim()).slice(0, 80)}`);
  const visit = (node: ts.Node) => {
    // Letters, or punctuation that composes sentences around values, belong in a catalog template.
    if (ts.isJsxText(node) && copyFragment(node.text)) report(node, 'jsx-text', node.text);
    if (ts.isStringLiteral(node) || ts.isNoSubstitutionTemplateLiteral(node)) {
      const attribute = attributeName(node);
      const text = node.text;
      const compared = ts.isBinaryExpression(node.parent) && [ts.SyntaxKind.EqualsEqualsEqualsToken, ts.SyntaxKind.ExclamationEqualsEqualsToken]
        .includes(node.parent.operatorToken.kind);
      if (attribute !== null && !textAttributes.has(attribute)) { /* IDs, roles, classes and other DOM tokens. */ }
      else if (attribute !== null) { if (!compared && copyFragment(text)) report(node, 'attribute', text); }
      else if (renderedValue(node) && copyFragment(text)) report(node, 'jsx-expression', text);
      else if (!ts.isImportDeclaration(node.parent) && !ts.isExportDeclaration(node.parent)
        && !technicalCall(node) && !technical.has(text) && /\p{L}{2,}[,.;:]?\s+\p{L}{2,}/u.test(text)) report(node, 'prose', text);
    }
    if (ts.isTemplateExpression(node) && (attributeName(node) === null || textAttributes.has(attributeName(node)!))) {
      const parts = [node.head.text, ...node.templateSpans.map(span => span.literal.text)];
      if (((renderedValue(node) || attributeName(node) !== null) && parts.some(copyFragment))
        || parts.some(part => /\p{L}{2,}\s+\p{L}{2,}/u.test(part)))
        report(node, 'template', parts.join('…'));
    }
    ts.forEachChild(node, visit);
  };
  visit(source);
  return findings;
}

function inlineCopy(): string[] {
  return sources(root).flatMap(file => {
    const path = relative(root, file).replaceAll('\\', '/');
    if (exempt(path)) return [];
    const source = ts.createSourceFile(file, readFileSync(file, 'utf8'), ts.ScriptTarget.Latest, true,
      file.endsWith('.tsx') ? ts.ScriptKind.TSX : ts.ScriptKind.TS);
    return inlineSourceCopy(source, path);
  });
}

function fixtureCopy(code: string): string[] {
  const source = ts.createSourceFile('fixture.tsx', code, ts.ScriptTarget.Latest, true, ts.ScriptKind.TSX);
  return inlineSourceCopy(source, 'fixture.tsx');
}

it.each([
  '<p>Save</p>',
  '<p>{label}: {value}</p>',
  "<p>{label}{': '}{value}</p>",
  '<p>{"Save"}</p>',
  '<p>{`Save`}</p>',
  '<p>{`Recorded ${code}.`}</p>',
  '<p>{`${code}.`}</p>',
  '<button aria-label={`Inspect ${id}`} />',
  '<button aria-label="Inspect" />',
  '<button aria-label={"Inspect"} />',
  '<button title={`Recorded ${code}.`} />',
  '<input placeholder={`Find ${id}`} />',
  '<img alt={`Preview ${id}`} />',
  '<p>{ready ? "Save" : copy.wait}</p>',
  '<p>{ready && "Save"}</p>',
  '<p>{value ?? "Unknown"}</p>',
  '<p>{value || "Unknown"}</p>',
  '<p>{("Save" as string)}</p>',
  '<p>{"Recorded " + code}</p>',
  '<p>{["Save", value]}</p>',
])('rejects rendered inline copy: %s', code => {
  expect(fixtureCopy(code)).not.toEqual([]);
});

it.each([
  '<p>{copy.save}</p>',
  '<p>{" "}{value}</p>',
  '<code>{code}</code>',
  '<p>{status === "failed" ? copy.failed : copy.ready}</p>',
  '<p>{"failed" === status && copy.failed}</p>',
  '<p>{copy.status["failed"]}</p>',
  '<p>{formatExactTimestamp("2026-09-05T00:00:00Z")}</p>',
  '<p>{textMessage(copy.recorded, { code })}</p>',
  '<p>{`${code}${id}`}</p>',
  '<button aria-label={status === "failed" ? copy.failed : copy.ready} />',
  '<button aria-label={textMessage(copy.inspect, { id })} />',
  '<button className="inspect-button" role="button" data-testid="inspect" />',
  '<button id={`inspect-${id}`} aria-controls={`panel-${id}`} />',
  'const selector = document.querySelector("button.inspect");',
  'const escaped = event.key === "Escape";',
  'const protocol = "failed";',
])('allows catalog references and technical strings: %s', code => {
  expect(fixtureCopy(code)).toEqual([]);
});

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
