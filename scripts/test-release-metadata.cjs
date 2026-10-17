#!/usr/bin/env node
'use strict';

const assert = require('node:assert/strict');
const crypto = require('node:crypto');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const { spawnSync } = require('node:child_process');
const root = path.resolve(__dirname, '..');
const args = process.argv.slice(2);
assert(args.length === 0 || (args.length === 2 && args[0] === '--baseline-ref'),
  'usage: node scripts/test-release-metadata.cjs [--baseline-ref COMMIT]');
const work = fs.mkdtempSync(path.join(os.tmpdir(), 'nanokvm-metadata-test-'));
let failures = 0;
const env = { ...process.env };
for (const key of ['APP_UPDATE_SIGNING_KEY', 'SYSTEM_UPDATE_SIGNING_KEY',
  'APP_UPDATE_SIGNATURE_ALGORITHM', 'APP_UPDATE_SIGNATURE_KEY_ID',
  'SYSTEM_UPDATE_SIGNATURE_ALGORITHM', 'SYSTEM_UPDATE_SIGNATURE_KEY_ID',
  'SECURITY_PATCH_LEVEL', 'SYSTEM_UPDATE_REQUIRED_APP_VERSION']) env[key] = '';
Object.assign(env, { SYSTEM_UPDATE_FORMAT: '1', TARGET: 'sg2002-licheervnano-sd', CHANNEL: 'preview' });

function invoke(command, argv, overrides = {}) {
  const result = spawnSync(command, argv, {
    cwd: root, env: { ...env, ...overrides }, encoding: 'utf8', timeout: 10000,
  });
  if (result.error) throw result.error;
  return result;
}

function check(label, action) {
  try {
    action();
    console.log(`PASS ${label}`);
  } catch (error) {
    failures++;
    console.error(`FAIL ${label}: ${error.message}`);
  }
}

try {
  const scripts = path.join(work, 'scripts');
  fs.mkdirSync(scripts);
  fs.symlinkSync(path.join(root, 'scripts/lib'), path.join(scripts, 'lib'));
  for (const kind of ['app', 'system']) {
    const name = kind === 'app' ? 'create-update-metadata.sh' : 'create-system-update-metadata.sh';
    const script = path.join(scripts, name);
    if (args[1]) {
      const source = invoke('git', ['show', `${args[1]}:scripts/${name}`]);
      assert.equal(source.status, 0, source.stderr);
      fs.writeFileSync(script, source.stdout);
    } else fs.copyFileSync(path.join(root, 'scripts', name), script);
    const version = kind === 'app' ? '2.0.43' : '0.3.0-raw.13';
    const archive = path.join(work, kind === 'app'
      ? 'hardened-nanokvm-kvmapp-2.0.43.tar.gz' : 'hardened-nanokvm-system-0.3.0-raw.13.tar.gz');
    const payload = Buffer.from('Synthetic archive bytes for metadata generation tests.\n');
    fs.writeFileSync(archive, payload);
    let sequence = 0;
    function output() { return path.join(work, `${kind}-${sequence++}.json`); }
    function generate(destination, overrides = {}) {
      return invoke('sh', [script, version, 'hardened-system-0.3.0-raw.13', archive, destination], overrides);
    }
    check(`${kind}: valid metadata hashes the exact input`, () => {
      const destination = output();
      const result = generate(destination);
      assert.equal(result.status, 0, result.stderr);
      const metadata = JSON.parse(fs.readFileSync(destination));
      assert.equal(metadata.sha512, crypto.createHash('sha512').update(payload).digest('base64'));
      assert.equal(metadata.size, payload.length);
      if (kind === 'system') assert.equal(metadata.sha256,
        crypto.createHash('sha256').update(payload).digest('hex'));
      assert(fs.readFileSync(destination + '.sha256', 'utf8').startsWith(
        crypto.createHash('sha256').update(fs.readFileSync(destination)).digest('hex')));
    });
    check(`${kind}: empty archive rejects without a candidate`, () => {
      fs.truncateSync(archive);
      const destination = output();
      const result = generate(destination);
      assert.notEqual(result.status, 0, 'empty archive accepted');
      assert(!fs.existsSync(destination), 'failed generation published metadata');
      fs.writeFileSync(archive, payload);
    });
    // Restore even after a failed assertion in the previous baseline scenario.
    fs.writeFileSync(archive, payload);
    for (const [tool, body, label] of [
      ['openssl', 'exit 7', 'failed hash command'],
      ['openssl', 'exit 0', 'empty successful hash output'],
      ['sha256sum', 'exit 7', 'failed checksum command'],
      ['sha256sum', 'exit 0', 'empty successful checksum output'],
    ]) {
      const bin = fs.mkdtempSync(path.join(work, 'bin-'));
      fs.writeFileSync(path.join(bin, tool), `#!/bin/sh\n${body}\n`, { mode: 0o755 });
      check(`${kind}: ${label} rejects without a candidate`, () => {
        const destination = output();
        const result = generate(destination, { PATH: `${bin}:${process.env.PATH}` });
        assert.notEqual(result.status, 0, 'broken hash tool accepted');
        assert(!fs.existsSync(destination), 'failed generation published metadata');
      });
    }
    check(`${kind}: signing failure does not publish metadata`, () => {
      const destination = output();
      const invalidKey = path.join(work, 'invalid-signing-input');
      fs.writeFileSync(invalidKey, 'synthetic invalid input, not a private key\n');
      const result = generate(destination, {
        [kind === 'app' ? 'APP_UPDATE_SIGNING_KEY' : 'SYSTEM_UPDATE_SIGNING_KEY']: invalidKey,
      });
      assert.notEqual(result.status, 0);
      assert(!fs.existsSync(destination), 'signing failure published metadata');
    });
    check(`${kind}: existing metadata is never overwritten`, () => {
      const destination = output();
      fs.writeFileSync(destination, 'previous artifact\n');
      const result = generate(destination);
      assert.notEqual(result.status, 0, 'existing output overwritten');
      assert.equal(fs.readFileSync(destination, 'utf8'), 'previous artifact\n');
    });
    check(`${kind}: concurrent output lock rejects`, () => {
      const destination = output();
      fs.mkdirSync(destination + '.lock');
      const result = generate(destination);
      assert.notEqual(result.status, 0, 'concurrent output lock ignored');
      assert(!fs.existsSync(destination), 'locked generation published metadata');
    });
  }
} finally {
  fs.rmSync(work, { recursive: true, force: true });
}
if (failures) process.exitCode = 1;
else console.log('Release metadata regression tests passed');
