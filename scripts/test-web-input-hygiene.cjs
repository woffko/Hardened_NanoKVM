#!/usr/bin/env node
'use strict';
// Web input hygiene (L-B11): the HID WebSocket client retries with a bounded
// backoff and never leaves a connecting socket behind, the keymap holds only
// keyboard-page usages, IME composition is sent once when it ends, and a
// small wheel delta is a notch whichever way it goes. The real TypeScript
// modules are transpiled with the web tree's compiler and run with stubs for
// the socket library and the timers. Not a browser, React or device test.
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const vm = require('node:vm');
const ROOT = path.resolve(__dirname, '..');
const ts = require(require.resolve('typescript', { paths: [path.join(ROOT, 'web')] }));

function load(file, requireMap, globals = {}) {
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
    require: (name) => {
      if (name in requireMap) return requireMap[name];
      throw new Error(`unexpected import ${name} from ${file}`);
    },
    ...globals,
  };
  vm.runInNewContext(output.outputText, context, { filename: file });
  return module.exports;
}

let passed = 0;
let failed = 0;
function test(name, work) {
  try { work(); passed++; process.stdout.write(`PASS ${name}\n`); }
  catch (error) { failed++; process.stderr.write(`FAIL ${name}: ${error.message}\n`); }
}

test('the keymap sends only keyboard-page usages', () => {
  const keymap = load('web/src/lib/keymap.ts', {});
  const source = fs.readFileSync(path.join(ROOT, 'web/src/lib/keymap.ts'), 'utf8');
  const names = [...source.matchAll(/^\s+([A-Za-z0-9]+):\s*0x[0-9a-fA-F]+/gm)].map((m) => m[1]);
  assert(names.length > 100, 'the map must still hold the keyboard');
  for (const name of names) {
    if (keymap.isModifier(name)) continue;
    const code = keymap.getKeycode(name);
    assert(code !== undefined && code >= 0x04 && code <= 0xe7, `${name} = ${code}`);
  }
  for (const consumer of ['BrowserSearch', 'MediaPlayPause', 'LaunchMail', 'Sleep', 'MediaFastForward']) {
    assert.equal(keymap.getKeycode(consumer), undefined, `${consumer} must stay unmapped`);
  }
  assert.equal(keymap.getKeycode('KeyA'), 0x04);
});

test('a small wheel delta is a notch in its own direction', () => {
  const { wheelStep } = load('web/src/lib/wheel.ts', {});
  assert.equal(wheelStep(0.3, 1), 1);
  assert.equal(wheelStep(-0.3, 1), -1);
  assert.equal(wheelStep(100, 1), 1);
  assert.equal(wheelStep(-100, -1), 1);
  assert.equal(wheelStep(0.3, -1), -1);
  assert.equal(wheelStep(0, 1), 0);
  assert.equal(wheelStep(NaN, 1), 0);
});

test('an IME composition is sent once, when it ends', () => {
  const { CompositionGate } = load('web/src/lib/composition.ts', {});
  const gate = new CompositionGate();
  assert.equal(gate.input('x', false), 'x', 'plain input passes');
  assert.equal(gate.input('', false), null, 'nothing to send');
  assert.equal(gate.input('д', true), null, 'a composing event waits');
  gate.start();
  assert.equal(gate.input('до', false), null, 'inside a composition every fragment waits');
  assert.equal(gate.end('дом'), 'дом', 'the final text goes once');
  assert.equal(gate.input('y', false), 'y', 'plain input passes again');
  assert.equal(gate.end(''), null);
});

function socketLibrary() {
  const sockets = [];
  class FakeSocket {
    static CONNECTING = 0;
    static OPEN = 1;
    static CLOSING = 2;
    static CLOSED = 3;
    constructor(url) {
      this.url = url;
      this.readyState = FakeSocket.CONNECTING;
      this.closed = false;
      this.sent = [];
      sockets.push(this);
    }
    close() { this.closed = true; this.readyState = FakeSocket.CLOSED; }
    send(data) { this.sent.push(data); }
  }
  return { sockets, library: { w3cwebsocket: FakeSocket } };
}

function timers() {
  const scheduled = [];
  return {
    scheduled,
    globals: {
      setTimeout: (callback, delay) => { scheduled.push({ callback, delay, kind: 'timeout' }); return scheduled.length; },
      clearTimeout: (id) => { if (scheduled[id - 1]) scheduled[id - 1].cleared = true; },
      setInterval: (callback, delay) => { scheduled.push({ callback, delay, kind: 'interval' }); return scheduled.length; },
      clearInterval: (id) => { if (scheduled[id - 1]) scheduled[id - 1].cleared = true; },
    },
  };
}

test('reconnect delays grow from the interval and stop at the cap', () => {
  const { reconnectDelay } = load('web/src/lib/websocket.ts',
    { websocket: socketLibrary().library, '@/lib/service.ts': { getBaseUrl: () => 'ws://test' } },
    timers().globals);
  assert.equal(reconnectDelay(100, 1), 100);
  assert.equal(reconnectDelay(100, 2), 150);
  assert.equal(reconnectDelay(100, 3), 225);
  assert.equal(reconnectDelay(3000, 20), 30000);
});

test('the HID socket retries with backoff and closes a connecting socket before the next one', () => {
  const { sockets, library } = socketLibrary();
  const clock = timers();
  const { WsClient } = load('web/src/lib/websocket.ts',
    { websocket: library, '@/lib/service.ts': { getBaseUrl: () => 'ws://test' } }, clock.globals);
  const client = new WsClient({ reconnectInterval: 100, maxReconnectAttempts: 3 });
  client.connect();
  assert.equal(sockets.length, 1);
  const reconnects = () => clock.scheduled.filter((t) => t.kind === 'timeout' && !t.cleared);
  const delays = [];
  for (let attempt = 0; attempt < 3; attempt++) {
    sockets[sockets.length - 1].onclose();
    const pending = reconnects();
    assert.equal(pending.length, attempt + 1, 'one reconnect per close');
    delays.push(pending[pending.length - 1].delay);
    pending[pending.length - 1].callback();
    assert.equal(sockets.length, attempt + 2, 'a new socket per reconnect');
    assert(sockets[attempt].closed, `socket ${attempt} was still connecting and must be closed`);
  }
  assert.deepEqual(delays, [100, 150, 225]);
  sockets[sockets.length - 1].onclose();
  assert.equal(reconnects().length, 3, 'the fourth close schedules nothing: the bound was reached');
  // A stale socket's events do not drive the client.
  sockets[0].onclose();
  sockets[0].onopen();
  assert.equal(reconnects().length, 3);
  assert.equal(clock.scheduled.filter((t) => t.kind === 'interval' && !t.cleared).length, 0,
    'a stale open must not start a heartbeat');
  // connect() again starts over, and an open socket resets the attempts.
  client.connect();
  const current = sockets[sockets.length - 1];
  current.readyState = 1;
  current.onopen();
  assert.equal(clock.scheduled.filter((t) => t.kind === 'interval' && !t.cleared).length, 1, 'one heartbeat');
  current.onclose();
  assert.equal(reconnects()[reconnects().length - 1].delay, 100, 'attempts restart after an open');
  // close() closes a socket that is still connecting.
  client.close();
  const last = sockets[sockets.length - 1];
  assert(last.closed, 'a connecting socket is closed by close()');
  assert.equal(client.isConnected, false);
  last.onclose();
  assert.equal(reconnects().filter((t) => !t.cleared).length, reconnects().length, 'no reconnect after close()');
});

test('the default client keeps retrying past one failure', () => {
  const { sockets, library } = socketLibrary();
  const clock = timers();
  const { WsClient } = load('web/src/lib/websocket.ts',
    { websocket: library, '@/lib/service.ts': { getBaseUrl: () => 'ws://test' } }, clock.globals);
  const client = new WsClient({ reconnectInterval: 10 });
  client.connect();
  for (let attempt = 0; attempt < 3; attempt++) {
    sockets[sockets.length - 1].onclose();
    const pending = clock.scheduled.filter((t) => t.kind === 'timeout' && !t.cleared);
    assert.equal(pending.length, attempt + 1, `the default bound must allow reconnect ${attempt + 1}`);
    pending[pending.length - 1].callback();
  }
  assert.equal(sockets.length, 4);
});

process.stdout.write(`web input hygiene: ${passed} passed, ${failed} failed\n`);
process.exit(failed ? 1 : 0);
