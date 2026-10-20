#!/usr/bin/env node
'use strict';

const assert = require('node:assert/strict');
const crypto = require('node:crypto');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const { spawnSync } = require('node:child_process');

const ROOT = path.resolve(__dirname, '..');
const args = process.argv.slice(2);
assert(args.length === 0 || (args.length === 2 && args[0] === '--baseline-ref'),
  'usage: node scripts/test-raw-bundle-signature-admission.cjs [--baseline-ref COMMIT]');
const work = fs.mkdtempSync(path.join(os.tmpdir(), 'nanokvm-raw-signature-test-'));
const keyRelative = 'kvmapp/system/keys/update-keys/hardened-system-prod-2026q3.pub.pem';
const legacyRelative = 'kvmapp/system/keys/system-update-signing.pub.pem';
const metadata = fs.readFileSync(path.join(__dirname, 'fixtures/rc12-system-latest.json'));
const signature = Buffer.from(fs.readFileSync(
  path.join(__dirname, 'fixtures/rc12-system-latest.json.sig.base64'), 'utf8').trim(), 'base64');
const publicKey = fs.readFileSync(path.join(ROOT, keyRelative));
let passed = 0;
let failed = 0;

function sha256(bytes) { return crypto.createHash('sha256').update(bytes).digest('hex'); }

try {
  assert.equal(sha256(metadata), 'b2397c9aaea621619c63b89e068bd434d82af2557ebbd8a8038aa0f82963e642');
  assert.equal(sha256(signature), '48515a9fb8d4e902fb9528d6b1417d845e772471845108dfe07edee20fce0380');
  assert.equal(sha256(crypto.createPublicKey(publicKey).export({ format: 'der', type: 'spki' })),
    '97ddb5600accf0e431c74f82b03acf249668bf75fe0de2e41724c91720516f75');
  assert(crypto.verify('sha256', metadata, {
    key: publicKey, padding: crypto.constants.RSA_PKCS1_PADDING,
  }, signature), 'public fixture signature must verify independently');

  const project = path.join(work, 'project');
  const scripts = path.join(project, 'scripts');
  fs.mkdirSync(scripts, { recursive: true });
  for (const relative of [keyRelative, legacyRelative]) {
    const destination = path.join(project, relative);
    fs.mkdirSync(path.dirname(destination), { recursive: true });
    fs.copyFileSync(path.join(ROOT, relative), destination);
  }
  const script = path.join(scripts, 'verify-rc12-raw-bundle.sh');
  if (args[1]) {
    const result = spawnSync('git', ['show', `${args[1]}:scripts/verify-rc12-raw-bundle.sh`],
      { cwd: ROOT, encoding: 'utf8', timeout: 10000 });
    assert.equal(result.status, 0, 'baseline source must be readable');
    fs.writeFileSync(script, result.stdout);
  } else fs.copyFileSync(path.join(ROOT, 'scripts/verify-rc12-raw-bundle.sh'), script);
  fs.copyFileSync(path.join(ROOT, 'scripts/verify-system-update-metadata.sh'),
    path.join(scripts, 'verify-system-update-metadata.sh'));
  // Deliberately stop BEFORE extraction. Real OpenSSL verifies metadata, but
  // this fixture does not decompress, hash or accept any raw payload/archive.
  const bin = path.join(work, 'bin');
  fs.mkdirSync(bin);
  fs.writeFileSync(path.join(bin, 'tar'),
    '#!/bin/sh\nprintf "archive inspection reached\\n" > "$RAW_SIGNATURE_TEST_VISITED"\nexit 97\n',
    { mode: 0o700 });
  const archive = path.join(work, 'hardened-nanokvm-system-0.3.0-raw.12.tar.gz');
  fs.writeFileSync(archive, 'not a real archive; signature admission fixture only\n');

  const cases = [
    { label: 'signed default selects production public key', admitted: true },
    { label: 'explicit signed mode', mode: 'signed', admitted: true },
    { label: 'matching explicit public key', key: keyRelative, admitted: true },
    { label: 'missing signature', noSignature: true },
    { label: 'missing signature file', missingSignature: true },
    { label: 'empty signature', emptySignature: true },
    { label: 'corrupt signature', corruptSignature: true },
    { label: 'legacy public key cannot verify production metadata', key: legacyRelative },
    { label: 'missing default public key', missingKey: true },
    { label: 'same JSON with changed bytes', append: ' ' },
    { label: 'wrong signing algorithm', field: ['signature_algorithm', 'unsigned'], diagnostic: 'signed algorithm' },
    { label: 'wrong signing key ID', field: ['signature_key_id', 'hardened-system-dev'], diagnostic: 'signed key id' },
    { label: 'unsigned metadata is rejected by default', unsigned: true, noSignature: true },
    { label: 'empty mode retains signed default', unsigned: true, mode: '', noSignature: true },
    { label: 'explicit unsigned fixture opt-in', unsigned: true, mode: 'unsigned', noSignature: true, admitted: true, warning: true },
    { label: 'unsigned mode rejects a supplied signature', unsigned: true, mode: 'unsigned' },
    { label: 'unknown mode fails before archive inspection', mode: 'auto', diagnostic: 'invalid EXPECTED_SIGNATURE_MODE' },
  ];
  for (const [index, test] of cases.entries()) {
    const directory = path.join(work, `case-${index}`);
    fs.mkdirSync(directory);
    const json = path.join(directory, 'system-latest.json');
    const sig = path.join(directory, 'system-latest.json.sig');
    const visited = path.join(directory, 'archive-visited');
    let bytes = metadata;
    if (test.unsigned || test.field) {
      const value = JSON.parse(metadata);
      if (test.unsigned) Object.assign(value, { signature_algorithm: 'unsigned', signature_key_id: 'unsigned' });
      if (test.field) value[test.field[0]] = test.field[1];
      bytes = Buffer.from(JSON.stringify(value));
    }
    if (test.append) bytes = Buffer.concat([bytes, Buffer.from(test.append)]);
    fs.writeFileSync(json, bytes);
    const sigBytes = Buffer.from(signature);
    if (test.corruptSignature) sigBytes[0] ^= 1;
    if (!test.missingSignature) fs.writeFileSync(sig, test.emptySignature ? '' : sigBytes);
    const productionKey = path.join(project, keyRelative);
    if (test.missingKey) fs.unlinkSync(productionKey);
    const env = {
      PATH: `${bin}:/usr/bin:/bin`, HOME: work, LANG: 'C', TMPDIR: work,
      RAW_SIGNATURE_TEST_VISITED: visited,
    };
    if (test.mode !== undefined) env.EXPECTED_SIGNATURE_MODE = test.mode;
    const argv = [script, archive, json];
    if (!test.noSignature) argv.push(sig);
    if (test.key) argv.push(path.join(project, test.key));
    const result = spawnSync('/bin/bash', argv,
      { cwd: project, env, encoding: 'utf8', timeout: 10000 });
    if (test.missingKey) fs.writeFileSync(productionKey, publicKey);
    try {
      assert(!result.error, 'fixture subprocess must terminate');
      assert.notEqual(result.status, 0, 'admission fixture must never claim payload acceptance');
      assert.equal(fs.existsSync(visited), Boolean(test.admitted),
        'invalid signatures/mode must fail before archive inspection');
      if (test.admitted) assert.equal(result.status, 97, 'archive sentinel must stop admitted metadata');
      if (test.diagnostic) assert(result.stderr.includes(test.diagnostic), 'specific policy rejection required');
      if (test.warning) assert(result.stderr.includes('not release acceptance'), 'unsigned opt-in must be conspicuous');
      assert(!result.stdout.includes('SUCCESS:'), 'no whole-bundle PASS from an admission test');
      console.log(`PASS ${test.label}`);
      passed += 1;
    } catch (error) {
      console.log(`FAIL ${test.label}: ${error.message}; status=${result.status}; ${result.stderr.trim().slice(0,240)}`);
      failed += 1;
    }
  }
  console.log(`raw signature admission: ${passed} passed, ${failed} failed; payload acceptance NOT TESTED`);
  if (failed) process.exitCode = 1;
} finally {
  // Only this fixture's fresh private tree, never retained release artifacts.
  fs.rmSync(work, { recursive: true, force: true });
}
