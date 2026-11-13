#!/usr/bin/env node
'use strict';

const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const vm = require('node:vm');
const { EventEmitter } = require('node:events');
const { spawnSync } = require('node:child_process');

const ROOT = path.resolve(__dirname, '..');
const args = process.argv.slice(2);
assert(args.length === 0 || (args.length === 2 && args[0] === '--baseline-ref'),
  'usage: node scripts/test-device-test-error-hygiene.cjs [--baseline-ref COMMIT]');
const FILES = [
  'scripts/soak-kernel-dmesg-restriction-reboots.cjs',
  'scripts/verify-kernel-dmesg-restriction-host.cjs',
];
// Deliberately synthetic. Never load a real credential or contact a device.
const SECRET = 'SYNTHETIC-error-hygiene-credential-9b2e';
const TARGET = '192.0.2.123';
const TOOL = '/synthetic/sshpass-bin';
const DEFAULT_TOOL = path.join(ROOT, 'build/host-deps/sshpass/usr/bin/sshpass');
const RESULT = '/synthetic/results';
const MARKER = 'SUCCESS: Phase 3 dmesg restriction device gate passed';

function sourceFor(file) {
  if (!args[1]) return fs.readFileSync(path.join(ROOT, file), 'utf8');
  const result = spawnSync('git', ['show', `${args[1]}:${file}`], {
    cwd: ROOT, encoding: 'utf8', maxBuffer: 1024 * 1024,
  });
  assert.equal(result.status, 0, 'baseline source must be readable');
  return result.stdout;
}

async function exercise(file, source, scenario) {
  const writes = [];
  const calls = [];
  const reads = [];
  let stdinReads = 0;
  let boots = 0;
  const environment = {
    TARGET_IP: TARGET,
    REBOOT_CYCLES: '1',
    DEVICE_TEST_RESULT_DIR: RESULT,
    SSHPASS: SECRET,
    ...(['missing-default', 'success-default'].includes(scenario) ? {} : {
      SSHPASS_BIN: scenario === 'missing-override' ? SECRET : TOOL,
    }),
  };
  const processStub = {
    env: new Proxy(environment, {
      get(object, key) { reads.push(key); return object[key]; },
    }),
    argv: ['node', file, '--confirm-device', TARGET],
    stdout: { write(data) { writes.push(String(data)); } },
    stdin: {
      setEncoding() {},
      async *[Symbol.asyncIterator]() { stdinReads += 1; yield `${SECRET}\n`; },
    },
    exitCode: undefined,
  };
  if (scenario === 'no-confirm') processStub.argv = ['node', file];
  const fakeFs = {
    existsSync(name) {
      if (scenario === 'filesystem-error') throw new Error(`raw filesystem detail ${SECRET}`);
      if (name === RESULT) return false;
      if (name === TOOL || name === DEFAULT_TOOL || name === SECRET) {
        return !scenario.startsWith('missing-');
      }
      return true;
    },
    mkdirSync() {},
    writeFileSync(name, data) { writes.push(String(data)); },
    appendFileSync(name, data) { writes.push(String(data)); },
    readFileSync() { return Buffer.from('# synthetic device verifier\n'); },
  };
  function spawn(command, argv, options) {
    const fd3 = [];
    const stdin = [];
    calls.push({ command, argv, options, fd3, stdin });
    const child = new EventEmitter();
    child.stdout = new EventEmitter();
    child.stderr = new EventEmitter();
    child.stdin = { end(data) { if (data !== undefined) stdin.push(Buffer.from(data)); } };
    child.stdio = [child.stdin, child.stdout, child.stderr,
      { end(data) { fd3.push(Buffer.from(data)); } }];
    queueMicrotask(() => {
      if (scenario === 'spawn-error') {
        child.emit('error', new Error(`raw spawn detail ${SECRET}`));
        return;
      }
      if (scenario === 'child-error' ||
          (scenario === 'ssh-error' && !command.startsWith('/usr/bin/'))) {
        child.stderr.emit('data', Buffer.from(`raw child detail ${SECRET}`));
        child.emit('close', 7);
        return;
      }
      let output;
      if (command === '/usr/bin/ssh-keyscan') output = 'synthetic host key\n';
      else if (command === '/usr/bin/ssh-keygen') output = 'synthetic public fingerprint\n';
      else if (scenario === 'invalid-device-output') output = SECRET;
      else if (argv.includes('/proc/sys/kernel/random/boot_id')) {
        boots += 1;
        output = `${boots === 1 ? '11111111' : '22222222'}-1111-1111-1111-111111111111\n`;
      } else if (argv.at(-1) === '-s') output = `${MARKER}\n`;
      else output = '';
      child.stdout.emit('data', Buffer.from(output));
      child.emit('close', 0);
    });
    return child;
  }
  const context = vm.createContext({
    __dirname: path.dirname(path.join(ROOT, file)),
    Buffer, process: processStub, queueMicrotask,
    Date, AbortSignal,
    setTimeout(callback) { queueMicrotask(callback); },
    fetch: async () => ({
      ok: true, status: 200,
      json: async () => ({ code: 0, data: { status: 'ok' } }),
    }),
    require(name) {
      if (name === 'fs') return fakeFs;
      if (name === 'path') return path;
      if (name === 'child_process') return { spawn };
      if (name === './lib/device-test-errors.cjs') {
        return require(path.join(ROOT, 'scripts/lib/device-test-errors.cjs'));
      }
      throw new Error('unexpected module in isolated fixture');
    },
  });
  await new vm.Script(source, { filename: file }).runInContext(context, { timeout: 1000 });
  return { writes: writes.join(''), calls, reads, stdinReads, exitCode: processStub.exitCode };
}

async function main() {
  let failed = 0;
  let passed = 0;
  for (const file of FILES) {
    const source = sourceFor(file);
    for (const scenario of ['missing-default', 'missing-override', 'filesystem-error',
      'spawn-error', 'child-error', 'ssh-error', 'invalid-device-output',
      'no-confirm', 'success', 'success-default']) {
      try {
        const result = await exercise(file, source, scenario);
        assert(!result.writes.includes(SECRET), 'credential must not reach diagnostics');
        assert(!result.reads.includes('SSHPASS'), 'legacy password environment must not be read');
        assert.equal(result.exitCode, scenario.startsWith('success') ? undefined : 1,
          'failure and success status must remain truthful');
        if (scenario.startsWith('missing-') || scenario === 'no-confirm') {
          assert.equal(result.calls.length, 0, 'preflight failure must not contact a device');
          assert.equal(result.stdinReads, 0, 'preflight failure must not consume credential');
        }
        for (const call of result.calls) {
          assert(!JSON.stringify([call.command, call.argv, call.options.env]).includes(SECRET),
            'credential must not enter argv or environment');
          if (call.fd3.length) {
            assert.equal(Buffer.concat(call.fd3).toString(), `${SECRET}\n`,
              'password transport must remain fd3');
          }
        }
        if (scenario.startsWith('success') || scenario === 'ssh-error') {
          const ssh = result.calls.filter(call => !call.command.startsWith('/usr/bin/'));
          assert(ssh.length > 0, 'fixture must reach SSH path');
          const expected = scenario === 'success-default' ? DEFAULT_TOOL : TOOL;
          assert(ssh.every(call => call.command === expected), 'executable selection must work');
          assert(ssh.every(call => call.argv[0] === '-d' && call.argv[1] === '3'),
            'SSH must read the private descriptor');
          assert(ssh.every(call => call.argv.includes('StrictHostKeyChecking=yes')),
            'host-key checks must remain enabled');
        }
        if (scenario.startsWith('success')) {
          assert(result.writes.includes('SUCCESS:'), 'success report retained');
        }
        process.stdout.write(`PASS ${path.basename(file)} ${scenario}\n`);
        passed += 1;
      } catch {
        // Do not dump source errors or fixture values through the regression reporter.
        process.stdout.write(`FAIL ${path.basename(file)} ${scenario}\n`);
        failed += 1;
      }
    }
  }
  process.stdout.write(`device-test error hygiene: ${passed} passed, ${failed} failed\n`);
  if (failed) process.exitCode = 1;
}

main().catch(() => { process.stderr.write('isolated regression fixture failed\n'); process.exitCode = 1; });
