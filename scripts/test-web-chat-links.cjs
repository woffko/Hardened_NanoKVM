#!/usr/bin/env node
'use strict';
// Links in the assistant chat (WEB-02): the assistant reads the controlled
// computer's screen, so its answers can carry text from there. A link is
// followed only when it names another site in full. A relative address, or one
// that names this device, would open a page of this interface with parameters
// of that text's choosing. The real module is transpiled with the web tree's
// TypeScript. Not a browser or React test.
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const vm = require('node:vm');
const ROOT = path.resolve(__dirname, '..');
const ts = require(require.resolve('typescript', { paths: [path.join(ROOT, 'web')] }));

const file = 'web/src/pages/desktop/picoclaw/link.ts';
const output = ts.transpileModule(fs.readFileSync(path.join(ROOT, file), 'utf8'), {
  compilerOptions: { target: ts.ScriptTarget.ES2022, module: ts.ModuleKind.CommonJS },
  reportDiagnostics: true,
});
assert(!output.diagnostics?.some((entry) => entry.category === ts.DiagnosticCategory.Error),
  `${file} must transpile`);
const module_ = { exports: {} };
vm.runInNewContext(output.outputText, { module: module_, exports: module_.exports, URL });
const { isExternalLink } = module_.exports;

const OWN = '192.0.2.10';
const followed = [
  'https://example.org/',
  'http://example.org/page?x=1#top',
  'HTTPS://Example.ORG/path',
  'https://192.0.2.11/',
  'https://192.0.2.10:8443/',
];
const refused = [
  // In-app and relative addresses.
  '/#terminal?port=/dev/ttyS0&baud=115200',
  '#terminal?port=/dev/ttyS0',
  '?x=1',
  'terminal',
  '//example.org/',
  // This device, named in full.
  'https://192.0.2.10/#terminal?port=/dev/ttyS0',
  'http://192.0.2.10/',
  // Other schemes.
  'javascript:alert(1)',
  'data:text/html,x',
  'file:///etc/passwd',
  'mailto:someone@example.org',
  'ws://example.org/',
  // Not addresses.
  '',
  ' https://example.org/',
  'https://',
  'https:example.org',
];
let failed = 0;
function check(name, work) {
  try {
    work();
    console.log(`PASS ${name}`);
  } catch (error) {
    failed += 1;
    console.log(`FAIL ${name}: ${error.message}`);
  }
}
check('a link that names another site in full is followed', () => {
  for (const url of followed) assert.equal(isExternalLink(url, OWN), true, url);
});
check('a relative, in-app, same-device or non-web link is not followed', () => {
  for (const url of refused) assert.equal(isExternalLink(url, OWN), false, JSON.stringify(url));
  assert.equal(isExternalLink('https://KVM.example/', 'kvm.example'), false, 'the host compare is case-blind');
});
check('the chat uses the rule and shows a refused link as text', () => {
  const source = fs.readFileSync(
    path.join(ROOT, 'web/src/pages/desktop/picoclaw/markdown-content.tsx'), 'utf8');
  assert(source.includes('isExternalLink(url, window.location.host)'), 'the chat does not use the rule');
  assert(!source.includes('new URL(url, window.location.origin)'), 'the chat resolves relative links again');
  assert(source.includes("disallowedElements={['img']}"), 'the chat renders images');
  assert(/href \?\s*\(/.test(source) && source.includes('<span>{children}</span>'),
    'a refused link keeps an empty address');
});
console.log(`web chat links: ${3 - failed} passed, ${failed} failed`);
process.exit(failed ? 1 : 0);
