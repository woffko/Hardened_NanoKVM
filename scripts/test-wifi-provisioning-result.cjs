#!/usr/bin/env node
'use strict';

const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const vm = require('node:vm');
const { spawnSync } = require('node:child_process');

const ROOT = path.resolve(__dirname, '..');
const FILE = 'web/src/pages/wifi/index.tsx';
const options = {};
for (let index = 2; index < process.argv.length; index += 2) {
  const name = process.argv[index];
  assert(['--baseline-ref', '--typescript-module'].includes(name) && process.argv[index + 1],
    'usage: node scripts/test-wifi-provisioning-result.cjs [--baseline-ref COMMIT] [--typescript-module PATH]');
  assert(!options[name], 'duplicate test option');
  options[name] = process.argv[index + 1];
}
const ts = options['--typescript-module']
  ? require(path.resolve(options['--typescript-module']))
  : require(require.resolve('typescript', { paths: [path.join(ROOT, 'web')] }));

function readSource() {
  const baseline = options['--baseline-ref'];
  if (!baseline) return fs.readFileSync(path.join(ROOT, FILE), 'utf8');
  assert(/^[a-f0-9]{7,40}$/.test(baseline), 'baseline must be a commit hash');
  const result = spawnSync('git', ['show', `${baseline}:${FILE}`], {
    cwd: ROOT, encoding: 'utf8', maxBuffer: 1024 * 1024,
  });
  assert.equal(result.status, 0, 'baseline source must be readable');
  return result.stdout;
}

// Execute the actual nested handler, not a second implementation of its switch.
// This isolates response handling; it is not a React/browser/network/device test.
function handlerSource() {
  const file = ts.createSourceFile(FILE, readSource(), ts.ScriptTarget.Latest, true, ts.ScriptKind.TSX);
  assert.equal(file.parseDiagnostics.length, 0, 'component must parse');
  const handlers = [];
  for (const statement of file.statements) {
    if (!ts.isVariableStatement(statement)) continue;
    for (const declaration of statement.declarationList.declarations) {
      if (!ts.isIdentifier(declaration.name) || declaration.name.text !== 'Wifi' ||
          !declaration.initializer || !ts.isArrowFunction(declaration.initializer) ||
          !ts.isBlock(declaration.initializer.body)) continue;
      for (const member of declaration.initializer.body.statements) {
        if (ts.isFunctionDeclaration(member) && member.name?.text === 'connect') handlers.push(member);
      }
    }
  }
  assert.equal(handlers.length, 1, 'exact Wifi.connect handler must exist');
  const output = ts.transpileModule(handlers[0].getText(file), {
    compilerOptions: { target: ts.ScriptTarget.ES2022, module: ts.ModuleKind.CommonJS },
    reportDiagnostics: true,
  });
  assert(!output.diagnostics?.some((entry) => entry.category === ts.DiagnosticCategory.Error),
    'handler transpilation must succeed');
  return `${output.outputText}\nconnect;`;
}

async function exercise(source, scenario) {
  const states = [];
  const calls = [];
  let finish;
  let reject;
  const response = new Promise((resolve, fail) => { finish = resolve; reject = fail; });
  const context = vm.createContext({
    state: scenario.busy ? 'loading' : '',
    apPassword: 'synthetic-ap-key',
    setState(value) { states.push(value); },
    api: {
      connectWifiNoAuth(...args) { calls.push(args); return response; },
    },
    console: { log() {}, error() {} },
  });
  const connect = new vm.Script(source, { filename: FILE }).runInContext(context, { timeout: 1000 });
  const values = scenario.values || { ssid: 'synthetic-ssid', password: 'synthetic-sta-password' };
  const pending = connect(values);
  if (scenario.skip) {
    await pending;
    assert.equal(calls.length, 0, 'invalid/busy form must not submit');
    assert.deepEqual(states, [], 'invalid/busy form must retain its state');
    return;
  }
  assert.deepEqual(states, ['loading'], 'pending response must not report success');
  assert.equal(calls.length, 1, 'exactly one request must be submitted');
  assert.deepEqual(calls[0], [values.ssid, values.password, 'synthetic-ap-key'],
    'SSID, STA password and AP authorization must be preserved');
  if (scenario.reject) reject(new Error('synthetic request failure'));
  else finish(scenario.response);
  await pending;
  assert.deepEqual(states, ['loading', scenario.expected], 'terminal state must match response');
}

async function main() {
  const source = handlerSource();
  const scenarios = [
    { name: 'accepted', response: { code: 0 }, expected: 'success' },
    { name: 'invalid-mode', response: { code: -1 }, expected: 'denied' },
    { name: 'unauthorized', response: { code: -4 }, expected: 'denied' },
    { name: 'known-error-2', response: { code: -2 }, expected: 'failed' },
    { name: 'known-error-3', response: { code: -3 }, expected: 'failed' },
    { name: 'unknown-negative', response: { code: -5 }, expected: 'failed' },
    { name: 'unknown-positive', response: { code: 1 }, expected: 'failed' },
    { name: 'missing-code', response: {}, expected: 'failed' },
    { name: 'null-response', response: null, expected: 'failed' },
    { name: 'undefined-response', response: undefined, expected: 'failed' },
    { name: 'string-zero', response: { code: '0' }, expected: 'failed' },
    { name: 'null-code', response: { code: null }, expected: 'failed' },
    { name: 'non-number', response: { code: NaN }, expected: 'failed' },
    { name: 'request-rejected', reject: true, expected: 'failed' },
    { name: 'empty-ssid', values: { ssid: '', password: 'synthetic-password' }, skip: true },
    { name: 'empty-password', values: { ssid: 'synthetic-ssid', password: '' }, skip: true },
    { name: 'busy', busy: true, skip: true },
  ];
  let passed = 0;
  let failed = 0;
  for (const scenario of scenarios) {
    try {
      await exercise(source, scenario);
      process.stdout.write(`PASS ${scenario.name}\n`);
      passed += 1;
    } catch {
      process.stdout.write(`FAIL ${scenario.name}\n`);
      failed += 1;
    }
  }
  process.stdout.write(`Wi-Fi provisioning response: ${passed} passed, ${failed} failed\n`);
  if (failed) process.exitCode = 1;
}

main().catch(() => { process.stderr.write('isolated Wi-Fi response fixture failed\n'); process.exitCode = 1; });
