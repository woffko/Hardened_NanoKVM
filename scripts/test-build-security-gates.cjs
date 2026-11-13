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
  'usage: node scripts/test-build-security-gates.cjs [--baseline-ref COMMIT]');
const baseline = args[1];
const work = fs.mkdtempSync(path.join(os.tmpdir(), 'nanokvm-security-gates-'));
let failures = 0;

function run(command, argv, env = {}) {
  const result = spawnSync(command, argv, {
    cwd: root, env: { ...process.env, ...env }, encoding: 'utf8', timeout: 15000,
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

function scriptSource(name) {
  if (!baseline) return fs.readFileSync(path.join(root, 'scripts', name));
  const result = run('git', ['show', `${baseline}:scripts/${name}`]);
  assert.equal(result.status, 0, result.stderr);
  return result.stdout;
}

try {
  const fixture = path.join(work, 'project');
  const scripts = path.join(fixture, 'scripts');
  fs.mkdirSync(scripts, { recursive: true });
  fs.cpSync(path.join(root, 'kvmapp'), path.join(fixture, 'kvmapp'), { recursive: true });
  for (const name of ['buildroot-external', 'support', 'server-rust', 'docs']) {
    fs.symlinkSync(path.join(root, name), path.join(fixture, name));
  }
  for (const name of fs.readdirSync(path.join(root, 'scripts'))) {
    fs.symlinkSync(path.join(root, 'scripts', name), path.join(scripts, name));
  }
  for (const name of ['test-latest-buildroot-security-policy.sh',
    'prepare-buildroot-2026.05.1-security-source.sh']) {
    fs.unlinkSync(path.join(scripts, name));
    fs.writeFileSync(path.join(scripts, name), scriptSource(name), { mode: 0o755 });
  }
  const policy = path.join(scripts, 'test-latest-buildroot-security-policy.sh');
  check('clean project passes policy', () => {
    const result = run('sh', [policy]);
    assert.equal(result.status, 0, result.stderr);
  });
  if (!baseline) {
    const docs = path.join(fixture, 'docs');
    fs.unlinkSync(docs);
    fs.mkdirSync(docs);
    check('missing writer inventory rejects source policy', () => {
      const result = run('sh', [policy]);
      assert.notEqual(result.status, 0, 'policy accepted a missing writer inventory');
    });
    const inventory = JSON.parse(fs.readFileSync(path.join(root, 'docs/security-state-writers.json')));
    inventory.groups[0].members.REQUIRED.pop();
    fs.writeFileSync(path.join(docs, 'security-state-writers.json'), JSON.stringify(inventory));
    check('unclassified restore source rejects policy', () => {
      const result = run('sh', [policy]);
      assert.notEqual(result.status, 0, 'policy accepted an unclassified restore source');
    });
    fs.rmSync(docs, { recursive: true });
    fs.symlinkSync(path.join(root, 'docs'), docs);
  }
  const sentinel = path.join(fixture, 'kvmapp', '.synthetic-private-marker');
  for (const [label, content] of [
    ['text', '-----BEGIN TEST PRIVATE KEY-----\nsynthetic fixture, not a key\n'],
    ['binary', '\0-----BEGIN TEST PRIVATE KEY-----\nsynthetic fixture, not a key\n'],
  ]) {
    fs.writeFileSync(sentinel, content);
    check(`${label} private marker rejects policy`, () => {
      const result = run('sh', [policy]);
      assert.notEqual(result.status, 0, 'policy accepted synthetic private-key material');
    });
  }
  fs.unlinkSync(sentinel);

  const scanRoot = path.join(work, 'scan');
  fs.mkdirSync(scanRoot);
  const library = path.join(root, 'scripts/lib/build-security.sh');
  const scanArgs = ['-c', '. "$1"; build_assert_no_private_keys "$2"', 'sh', library, scanRoot];
  check('empty key-scan tree is valid', () => {
    const result = run('sh', scanArgs);
    assert.equal(result.status, 0, result.stderr);
  });
  check('missing key-scan tree fails closed', () => {
    const result = run('sh', [...scanArgs.slice(0, -1), path.join(work, 'missing')]);
    assert.notEqual(result.status, 0, 'scanner accepted a missing tree');
  });
  fs.writeFileSync(path.join(scanRoot, 'ordinary.txt'), 'ordinary fixture\n');
  const stubBin = path.join(work, 'stub-bin');
  fs.mkdirSync(stubBin);
  fs.writeFileSync(path.join(stubBin, 'grep'), '#!/bin/sh\nexit 2\n', { mode: 0o755 });
  check('key-scan inspection errors fail closed', () => {
    const result = run('sh', scanArgs, { PATH: `${stubBin}:${process.env.PATH}` });
    assert.notEqual(result.status, 0, 'scanner accepted an unreadable inspection');
  });

  // Cached preparation must verify the recipes, not just its historical receipt.
  // The recipes and receipt markers mirror the refreshed pins of
  // prepare-buildroot-2026.05.1-security-source.sh (backport patches 0004-0009).
  const prepared = path.join(work, 'prepared');
  const recipes = {
    openssh: 'OPENSSH_VERSION_MAJOR = 10.6\nOPENSSH_VERSION_MINOR = p2\n',
    libopenssl: 'LIBOPENSSL_VERSION = 3.6.5\n',
    expat: 'EXPAT_VERSION = 2.9.0\n',
    libcurl: 'LIBCURL_VERSION = 8.23.0\n',
    wpa_supplicant: 'WPA_SUPPLICANT_VERSION = 2.12\n',
    hostapd: 'HOSTAPD_VERSION = 2.12\n',
  };
  for (const [pkg, recipe] of Object.entries(recipes)) {
    fs.mkdirSync(path.join(prepared, 'package', pkg), { recursive: true });
    fs.writeFileSync(path.join(prepared, 'package', pkg, `${pkg}.mk`), recipe);
  }
  const hostapd = path.join(prepared, 'package/hostapd/hostapd.mk');
  const patchDir = path.join(fixture,
    'buildroot-external/hardened-sg2002/buildroot-patches/2026.05.1');
  const receipt = ['buildroot=2026.05.1', 'openssh=10.6p2', 'libopenssl=3.6.5', 'expat=2.9.0',
    'libcurl=8.23.0', 'wpa_supplicant=2.12', 'hostapd=2.12-no-11be'];
  for (const name of fs.readdirSync(patchDir).filter(name => name.endsWith('.patch')).sort()) {
    const file = path.join(patchDir, name);
    receipt.push(`${crypto.createHash('sha256').update(fs.readFileSync(file)).digest('hex')}  ${file}`);
  }
  fs.writeFileSync(path.join(prepared, '.hardened-security-backports'), receipt.join('\n') + '\n');
  const prepare = path.join(scripts, 'prepare-buildroot-2026.05.1-security-source.sh');
  const env = {
    BUILDROOT_ARCHIVE: path.join(root, 'build/downloads/buildroot-2026.05.1.tar.xz'),
    LATEST_BUILDROOT_SECURITY_SOURCE_DIR: prepared,
  };
  if (fs.existsSync(env.BUILDROOT_ARCHIVE)) {
    check('valid cached security recipes pass', () => {
      const result = run('bash', [prepare], env);
      assert.equal(result.status, 0, result.stderr);
    });
    fs.appendFileSync(hostapd, 'HOSTAPD_CONFIG_ENABLE += CONFIG_IEEE80211BE\n');
    check('cached receipt does not authorize forbidden 11be recipe', () => {
      const result = run('bash', [prepare], env);
      assert.notEqual(result.status, 0, 'cached source accepted forbidden 11be configuration');
    });
    fs.unlinkSync(hostapd);
    check('cached receipt does not authorize a missing recipe', () => {
      const result = run('bash', [prepare], env);
      assert.notEqual(result.status, 0, 'cached source accepted a missing recipe');
    });
  } else {
    throw new Error('cached preparation test needs the pinned Buildroot archive');
  }
} finally {
  fs.rmSync(work, { recursive: true, force: true });
}

if (failures) process.exitCode = 1;
else console.log('Build security gate regression tests passed');
