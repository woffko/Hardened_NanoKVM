#!/usr/bin/env node
'use strict';
// Update reconnect (WP-20): after an accepted application install the page
// waits for the backend to go away and to answer again, within a bound,
// instead of reloading 12 s later whatever happened, and a failed install
// stays on screen. The real module is transpiled with the web tree's
// TypeScript; the clock and the probe are fakes. Not a browser test.
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const vm = require('node:vm');
const ROOT = path.resolve(__dirname, '..');
const ts = require(require.resolve('typescript', { paths: [path.join(ROOT, 'web')] }));

function load(file, requireMap) {
  const source = fs.readFileSync(path.join(ROOT, file), 'utf8');
  const output = ts.transpileModule(source, {
    compilerOptions: { target: ts.ScriptTarget.ES2022, module: ts.ModuleKind.CommonJS },
    reportDiagnostics: true,
  });
  assert(!output.diagnostics?.some((entry) => entry.category === ts.DiagnosticCategory.Error),
    `${file} must transpile`);
  const module = { exports: {} };
  const context = {
    module, exports: module.exports, console: { log() {}, error() {} },
    window: { setTimeout }, Date,
    require: (name) => {
      if (name in requireMap) return requireMap[name];
      throw new Error(`unexpected import ${name} from ${file}`);
    },
  };
  vm.runInNewContext(output.outputText, context, { filename: file });
  return module.exports;
}

const job = load('web/src/pages/desktop/menu/settings/update/job.ts', {
  '@/api/application.ts': {},
  '@/lib/localstorage.ts': { getAppUpdateJob() {}, removeAppUpdateJob() {}, setAppUpdateJob() {} },
});
const offlinePackage = load('web/src/pages/desktop/menu/settings/update/package.ts', {});
const reconnect = load('web/src/lib/reconnect.ts', { '@/lib/service.ts': { getBaseUrl: () => 'http://test' } });
const OPTIONS = { interval: 2000, restartGrace: 15000, deadline: 120000 };

function fakeClock() {
  let now = 0;
  return { now: () => now, sleep: async (ms) => { now += ms; }, get time() { return now; } };
}

// A probe that answers the sequence, repeating its last element, and refuses
// to answer for ever: a wait that never ends fails the case instead of hanging.
function sequence(results, cap = 200) {
  let calls = 0;
  return {
    probe: async () => {
      if (calls >= cap) throw new Error('probe cap reached: the wait never ended');
      return results[Math.min(calls++, results.length - 1)];
    },
    get calls() { return calls; },
  };
}

let passed = 0;
let failed = 0;
async function test(name, work) {
  try { await work(); passed++; process.stdout.write(`PASS ${name}\n`); }
  catch (error) { failed++; process.stderr.write(`FAIL ${name}: ${error.message}\n`); }
}

(async () => {
  await test('the page waits for the old backend to go and the new one to answer', async () => {
    const clock = fakeClock();
    const s = sequence(['ok', 'ok', 'unreachable', 'unreachable', 'server-error', 'ok']);
    const seen = [];
    const outcome = await reconnect.waitForBackendRestart(s.probe, OPTIONS, clock, (r, e) => seen.push([r, e]));
    assert.equal(outcome, 'back');
    assert.equal(s.calls, 6, 'the first answers come from the old backend and are not enough');
    assert.equal(clock.time, 10000);
    assert.deepEqual(seen.map((x) => x[1]), [0, 2000, 4000, 6000, 8000, 10000]);
  });

  await test('a restart quicker than one probe is accepted once the grace has passed', async () => {
    const clock = fakeClock();
    const s = sequence(['ok']);
    assert.equal(await reconnect.waitForBackendRestart(s.probe, OPTIONS, clock), 'back');
    assert.equal(clock.time, 16000, 'back only after restartGrace, not at the first answer');
    assert.equal(s.calls, 9);
  });

  await test('a backend that never comes back ends in a timeout, not a hang', async () => {
    const clock = fakeClock();
    const s = sequence(['ok', 'unreachable']);
    assert.equal(await reconnect.waitForBackendRestart(s.probe, OPTIONS, clock), 'timeout');
    assert.equal(clock.time, 120000);
    assert.equal(s.calls, 61);
  });

  await test('a revoked session counts as the backend being back', async () => {
    const clock = fakeClock();
    const s = sequence(['ok', 'unreachable', 'unauthorized']);
    assert.equal(await reconnect.waitForBackendRestart(s.probe, OPTIONS, clock), 'back');
    assert.equal(s.calls, 3);
  });

  await test('probeHealth classifies the answers and never throws', async () => {
    const answer = (status, ok, body) => async () => ({ status, ok, json: async () => body });
    assert.equal(await reconnect.probeHealth(answer(200, true, { data: { status: 'ok' } }), 'http://x'), 'ok');
    assert.equal(await reconnect.probeHealth(answer(200, true, { data: { status: 'degraded' } }), 'http://x'), 'server-error');
    assert.equal(await reconnect.probeHealth(answer(503, false, {}), 'http://x'), 'server-error');
    assert.equal(await reconnect.probeHealth(answer(401, false, {}), 'http://x'), 'unauthorized');
    assert.equal(await reconnect.probeHealth(async () => { throw new TypeError('Failed to fetch'); }, 'http://x'), 'unreachable');
    assert.equal(await reconnect.probeHealth(async () => ({ status: 200, ok: true, json: async () => { throw new SyntaxError('x'); } }), 'http://x'), 'server-error');
  });

  await test('neither update path reloads on a timer any more', () => {
    for (const file of ['web/src/pages/desktop/menu/settings/update/offline.tsx', 'web/src/pages/desktop/menu/settings/update/index.tsx']) {
      const source = fs.readFileSync(path.join(ROOT, file), 'utf8');
      assert(!/setTimeout\([\s\S]*?location\.reload/.test(source), `${file} still reloads on a timer`);
      assert(source.includes('waitForBackendRestart('), `${file} does not wait for the restart`);
    }
    const offline = fs.readFileSync(path.join(ROOT, 'web/src/pages/desktop/menu/settings/update/offline.tsx'), 'utf8');
    assert(/status === 'updating' \|\| status === 'restarting'\) \{\s*return;/.test(offline),
      'a second upload must be refused while the page waits for the restart');
  });

  await test('an offline update needs the three files of one release', () => {
    const files = (...names) => names.map((name) => ({ name }));
    const release = ['latest.json.sig', 'hardened-nanokvm-kvmapp-2.1.0.tar.gz', 'latest.json'];
    const picked = offlinePackage.pickOfflinePackage(files(...release));
    assert.equal(picked.file.name, release[1]);
    assert.equal(picked.metadata.name, release[2]);
    assert.equal(picked.signature.name, release[0]);
    assert.equal(offlinePackage.pickOfflinePackage(files(release[1])), null);
    assert.equal(offlinePackage.pickOfflinePackage(files(release[1], release[2])), null);
    assert.equal(offlinePackage.pickOfflinePackage(files(release[1], release[0])), null);
    assert.equal(offlinePackage.pickOfflinePackage(files('other.tar.gz', release[2], release[0])), null);
    assert.equal(offlinePackage.pickOfflinePackage(files(...release, 'extra.txt')), null);
    const form = fs.readFileSync(path.join(ROOT, 'web/src/pages/desktop/menu/settings/update/offline.tsx'), 'utf8');
    for (const part of ['metadata', 'signature', 'file']) {
      assert(form.includes(`formData.append('${part}', selected.${part})`), `the form does not send ${part}`);
    }
  });

  await test('only a committed update reloads; every other ending stays on the page', () => {
    assert.equal(job.appUpdateMessage('committed', 'failed'), null);
    assert.equal(job.appUpdateMessage('rolled-back', 'failed'), 'failed');
    assert.equal(job.appUpdateMessage('unknown', 'failed'), 'settings.update.outcomeUnknown');
    for (const file of ['web/src/pages/desktop/menu/settings/update/offline.tsx', 'web/src/pages/desktop/menu/settings/update/index.tsx']) {
      const source = fs.readFileSync(path.join(ROOT, file), 'utf8');
      const noReply = source.slice(source.indexOf('.catch(async () => {'));
      assert(!noReply.slice(0, noReply.indexOf('});')).includes('location.reload'),
        `${file} reloads when it never got a reply`);
      assert(source.includes('appUpdateMessage('), `${file} decides the reload by itself`);
    }
  });

  process.stdout.write(`web update reconnect: ${passed} passed, ${failed} failed\n`);
  process.exit(failed ? 1 : 0);
})();
