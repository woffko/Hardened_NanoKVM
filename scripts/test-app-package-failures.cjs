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
  'usage: node scripts/test-app-package-failures.cjs [--baseline-ref COMMIT]');
const work = fs.mkdtempSync(path.join(os.tmpdir(), 'nanokvm-package-test-'));
let failures = 0;

try {
  const project = path.join(work, 'project');
  fs.mkdirSync(path.join(project, 'scripts'), { recursive: true });
  fs.cpSync(path.join(root, 'kvmapp'), path.join(project, 'kvmapp'), { recursive: true });
  fs.symlinkSync(path.join(root, 'scripts/lib'), path.join(project, 'scripts/lib'));
  fs.symlinkSync(path.join(root, 'scripts/ssh-runtime-binding.py'),
    path.join(project, 'scripts/ssh-runtime-binding.py'));
  fs.symlinkSync(path.join(root, 'scripts/app-recovery-binding.py'),
    path.join(project, 'scripts/app-recovery-binding.py'));
  fs.symlinkSync(path.join(root, 'scripts/native-runtime-binding.py'),
    path.join(project, 'scripts/native-runtime-binding.py'));
  fs.symlinkSync(path.join(root, 'scripts/app-boot-delivery.py'),
    path.join(project, 'scripts/app-boot-delivery.py'));
  const compat = path.join(project, 'support/update-compat/rc12/S95nanokvm');
  fs.mkdirSync(path.dirname(compat), { recursive: true });
  const compatBytes = fs.readFileSync(path.join(root, 'support/update-compat/rc12/S95nanokvm'));
  fs.writeFileSync(compat, compatBytes);
  const script = path.join(project, 'scripts/package-rust-kvmapp.sh');
  if (args[1]) {
    const source = spawnSync('git', ['show', `${args[1]}:scripts/package-rust-kvmapp.sh`],
      { cwd: root, encoding: 'utf8' });
    if (source.error) throw source.error;
    assert.equal(source.status, 0, source.stderr);
    fs.writeFileSync(script, source.stdout);
  } else fs.copyFileSync(path.join(root, 'scripts/package-rust-kvmapp.sh'), script);
  // Host ELF bytes exercise packaging, not RISC-V/native ABI acceptance.
  const native = path.join(work, 'native');
  fs.mkdirSync(native);
  for (const name of ['libkvm.so', 'libkvm_mmf.so', 'libopencv_video.so.409']) {
    fs.copyFileSync('/bin/true', path.join(native, name));
  }
  const web = path.join(work, 'web');
  fs.mkdirSync(web);
  fs.writeFileSync(path.join(web, 'index.html'), 'synthetic frontend\n');
  const sentinel = path.join(project, 'kvmapp', '.synthetic-private-marker');
  // Synthetic RV64 header/envelope appended to a host ELF: tests only the
  // packaging consistency gate, not compilation, provenance or execution.
  const helper = Buffer.alloc(120);
  Buffer.from([0x7f, 69, 76, 70, 2, 1, 1]).copy(helper);
  for (const [offset, value] of [[16, 2], [18, 243], [52, 64], [54, 56], [56, 1]]) {
    helper.writeUInt16LE(value, offset);
  }
  helper.writeUInt32LE(1, 20);
  helper.writeBigUInt64LE(64n, 32);
  helper.writeUInt32LE(1, 64);
  const header = Buffer.alloc(48);
  header.write('NKSSHRT1');
  header.writeBigUInt64LE(BigInt(helper.length), 8);
  crypto.createHash('sha256').update(helper).digest().copy(header, 16);
  const envelope = Buffer.concat([header, helper]);
  const appHeader = Buffer.from(header);
  appHeader.write('NKAPPBT1');
  const appEnvelope = Buffer.concat([appHeader, helper]);
  const nativeMagics = { owner: 'NKNOWNR1', broker: 'NKNBRKR1', ctl: 'NKNCTL01', recovery: 'NKNREC01' };
  const nativeHelpers = {};
  const nativeEnvelopes = {};
  for (const [role, magic] of Object.entries(nativeMagics)) {
    nativeHelpers[role] = Buffer.concat([helper, Buffer.from(role)]);
    const roleHeader = Buffer.alloc(48);
    roleHeader.write(magic);
    roleHeader.writeBigUInt64LE(BigInt(nativeHelpers[role].length), 8);
    crypto.createHash('sha256').update(nativeHelpers[role]).digest().copy(roleHeader, 16);
    nativeEnvelopes[role] = Buffer.concat([roleHeader, nativeHelpers[role]]);
  }
  const host = fs.readFileSync('/bin/true');
  const bootNames = ['S02apprecover', 'S30eth', 'S30wifi', 'S95nanokvm'];
  const bootBytes = bootNames.map(name => fs.readFileSync(path.join(root, 'kvmapp/system/init.d', name)));
  const cases = [
    ['valid package matches its checksum', null],
    ['tar creation failure does not publish', 'tar-create'],
    ['tar inspection failure does not publish', 'tar-list'],
    ['empty tar inspection does not publish', 'tar-empty-list'],
    ['entry validation failure does not publish', 'entry-check'],
    ['gzip failure does not publish', 'gzip'],
    ['private marker is not packaged', 'private'],
    ['private marker through symlink is not packaged', 'private-link'],
    ['existing archive is preserved', 'existing'],
    ['concurrent stage lock rejects', 'stage-lock'],
    ['concurrent output lock rejects', 'output-lock'],
    ...(!args[1] ? [
      ['missing embedded helper rejects', 'binding-missing'],
      ['corrupt embedded helper rejects', 'binding-corrupt'],
      ['duplicate embedded helper rejects', 'binding-duplicate'],
      ['missing app recovery rejects', 'app-binding-missing'],
      ['corrupt app recovery rejects', 'app-binding-corrupt'],
      ['duplicate app recovery rejects', 'app-binding-duplicate'],
      ['SSH domain cannot replace app recovery', 'app-binding-wrong-domain'],
      ['bundled app recovery cannot replace embedded bytes', 'app-binding-bundled'],
      ...Object.keys(nativeMagics).flatMap(role =>
        ['missing', 'corrupt', 'duplicate', 'wrong-domain', 'bundled'].map(failure =>
          [`native ${role} ${failure} rejects`, `native-${role}-${failure}`])),
      ['absolute CARGO_TARGET_DIR is honored', 'target-absolute'],
      ['relative CARGO_TARGET_DIR is honored', 'target-relative'],
      ['missing compile-bound boot scripts rejects', 'boot-binding-missing'],
      ['duplicate compile-bound boot scripts rejects', 'boot-binding-duplicate'],
      ['changed compatibility script rejects', 'boot-compat-corrupt'],
      ['nonrelease app version rejects before publication', 'version-prerelease'],
    ] : []),
  ];
  for (const [index, [label, fault]] of cases.entries()) {
    const build = path.join(work, `case${index}`);
    const out = path.join(build, 'out');
    fs.mkdirSync(out, { recursive: true });
    const archive = path.join(out, 'fixture.tar.gz');
    const backend = path.join(build, 'backend');
    let binding = Buffer.from(envelope);
    if (fault === 'binding-missing') binding = Buffer.alloc(0);
    if (fault === 'binding-corrupt') binding[binding.length - 1] ^= 1;
    if (fault === 'binding-duplicate') binding = Buffer.concat([binding, binding]);
    let appBinding = Buffer.from(appEnvelope);
    if (fault === 'app-binding-missing' || fault === 'app-binding-bundled') appBinding = Buffer.alloc(0);
    if (fault === 'app-binding-corrupt') appBinding[appBinding.length - 1] ^= 1;
    if (fault === 'app-binding-duplicate') appBinding = Buffer.concat([appBinding, appBinding]);
    if (fault === 'app-binding-wrong-domain') {
      binding = Buffer.alloc(0);
      appBinding = Buffer.from(envelope);
    }
    const nativeBindings = Object.entries(nativeEnvelopes).map(([role, data]) => {
      let frame = Buffer.from(data);
      if (fault === `native-${role}-missing` || fault === `native-${role}-bundled`) frame = Buffer.alloc(0);
      if (fault === `native-${role}-corrupt`) frame[frame.length - 1] ^= 1;
      if (fault === `native-${role}-duplicate`) frame = Buffer.concat([frame, frame]);
      if (fault === `native-${role}-wrong-domain`) frame.write('NKAPPBT1');
      return frame;
    });
    let boot = fault === 'boot-binding-missing' ? [] : bootBytes;
    if (fault === 'boot-binding-duplicate') boot = [...boot, ...boot];
    fs.writeFileSync(backend, Buffer.concat([host, binding, appBinding, ...nativeBindings, ...boot]), { mode: 0o755 });
    if (fault === 'boot-compat-corrupt') fs.writeFileSync(compat, 'foreign compatibility code\n');
    const env = { ...process.env, BUILD_DIR: build, STAGE_DIR: path.join(build, 'stage'),
      OUT_DIR: out, ARTIFACT_NAME: 'fixture.tar.gz', RUST_BINARY: backend,
      HWMON_BINARY: '/bin/true', KVM_SYSTEM_SOURCE: '/bin/true', NATIVE_LIB_DIR: native,
      EXTRA_NATIVE_LIB_DIR: '', WEB_DIST: web, APP_VERSION: '2.0.43' };
    const succeeds = !fault || fault === 'target-absolute' || fault === 'target-relative';
    if (fault === 'version-prerelease') env.APP_VERSION = '2.0.43-dev';
    if (fault === 'target-absolute' || fault === 'target-relative') {
      const target = path.join(build, 'custom-target');
      const release = path.join(target, 'riscv64gc-unknown-linux-musl', 'release');
      fs.mkdirSync(release, { recursive: true });
      fs.copyFileSync(backend, path.join(release, 'nanokvm-rust-server'));
      fs.copyFileSync('/bin/true', path.join(release, 'nanokvm-hwmon'));
      delete env.RUST_BINARY;
      delete env.HWMON_BINARY;
      env.RUST_TARGET = 'riscv64gc-unknown-linux-musl';
      env.CARGO_TARGET_DIR = fault === 'target-absolute' ? target : path.relative(project, target);
    }
    if (['tar-create', 'tar-list', 'tar-empty-list', 'entry-check', 'gzip'].includes(fault)) {
      const bin = path.join(build, 'bin');
      fs.mkdirSync(bin);
      let body;
      if (fault === 'gzip' || fault === 'entry-check') body = 'exit 7';
      else {
        const flag = fault === 'tar-create' ? '-cf' : '-tzvf';
        const status = fault === 'tar-empty-list' ? 0 : 7;
        body = `for arg do\n  [ "$arg" != "${flag}" ] || exit ${status}\ndone\nexec /usr/bin/tar "$@"`;
      }
      const tool = fault === 'gzip' ? 'gzip' : fault === 'entry-check' ? 'awk' : 'tar';
      fs.writeFileSync(path.join(bin, tool), `#!/bin/sh\n${body}\n`, { mode: 0o755 });
      env.PATH = `${bin}:${process.env.PATH}`;
    }
    if (fault === 'private') fs.writeFileSync(sentinel,
      '-----BEGIN TEST PRIVATE KEY-----\nsynthetic marker, not a key\n');
    if (fault === 'private-link') {
      const target = path.join(work, 'synthetic-marker-target');
      fs.writeFileSync(target, '-----BEGIN TEST PRIVATE KEY-----\nsynthetic marker, not a key\n');
      fs.symlinkSync(target, sentinel);
    }
    if (fault === 'existing') fs.writeFileSync(archive, 'previous archive\n');
    if (fault === 'stage-lock') fs.mkdirSync(env.STAGE_DIR + '.lock');
    if (fault === 'output-lock') fs.mkdirSync(archive + '.lock');
    const bundledRecovery = path.join(project, 'kvmapp/system/bin/nanokvm-app-recovery');
    if (fault === 'app-binding-bundled') {
      fs.mkdirSync(path.dirname(bundledRecovery), { recursive: true });
      fs.writeFileSync(bundledRecovery, helper);
    }
    let bundledNative;
    for (const role of Object.keys(nativeMagics)) {
      if (fault === `native-${role}-bundled`) {
        bundledNative = path.join(project, 'kvmapp/system/bin/nanokvm-native-' + role);
        fs.mkdirSync(path.dirname(bundledNative), { recursive: true });
        fs.writeFileSync(bundledNative, nativeHelpers[role]);
      }
    }
    try {
      const result = spawnSync('sh', [script], { cwd: project, env, encoding: 'utf8', timeout: 15000 });
      if (result.error) throw result.error;
      if (succeeds) {
        assert.equal(result.status, 0, result.stderr);
        assert(fs.readFileSync(archive + '.sha256', 'utf8').startsWith(
          crypto.createHash('sha256').update(fs.readFileSync(archive)).digest('hex')));
        if (!args[1]) {
          const manifest = fs.readFileSync(path.join(env.STAGE_DIR, 'MANIFEST.txt'), 'utf8');
          assert(manifest.includes('ssh_runtime: embedded-static-rv64-v1\n'));
          assert(manifest.includes(`ssh_runtime_sha256: ${crypto.createHash('sha256').update(helper).digest('hex')}\n`));
          assert(manifest.includes('ssh_runtime_size: 120\n'));
          assert(manifest.includes('app_recovery: embedded-static-rv64-v1\n'));
          assert(manifest.includes(`app_recovery_sha256: ${crypto.createHash('sha256').update(helper).digest('hex')}\n`));
          assert(manifest.includes('app_recovery_size: 120\n'));
          assert.deepEqual(fs.readFileSync(path.join(env.STAGE_DIR, 'kvmapp/system/bin/nanokvm-app-recovery')), helper);
          for (const [role, bytes] of Object.entries(nativeHelpers)) {
            const digest = crypto.createHash('sha256').update(bytes).digest('hex');
            assert(manifest.includes(`native_${role}_sha256: ${digest}\n`));
            assert(manifest.includes(`native_${role}_size: ${bytes.length}\n`));
            const bundled = path.join(env.STAGE_DIR, 'kvmapp/system/bin/nanokvm-native-' + role);
            assert.deepEqual(fs.readFileSync(bundled), bytes);
            assert.equal(fs.statSync(bundled).mode & 0o7777, 0o755);
            const archived = spawnSync('tar', ['-xOf', archive, 'kvmapp/system/bin/nanokvm-native-' + role]);
            if (archived.error) throw archived.error;
            assert.equal(archived.status, 0, archived.stderr.toString());
            assert.deepEqual(archived.stdout, bytes);
          }
          assert(manifest.includes('app_archive_boot_profile: rc12-compat-bootstrap-v1\n'));
          const listing = spawnSync('tar', ['-tzf', archive], { encoding: 'utf8' });
          if (listing.error) throw listing.error;
          assert.equal(listing.status, 0, listing.stderr);
          const names = listing.stdout.split('\n');
          for (const name of bootNames.slice(0, -1)) {
            assert(!names.includes('kvmapp/system/init.d/' + name));
          }
          const archived = spawnSync('tar', ['-xOf', archive, 'kvmapp/system/init.d/S95nanokvm']);
          if (archived.error) throw archived.error;
          assert.equal(archived.status, 0, archived.stderr.toString());
          assert.deepEqual(archived.stdout, compatBytes);
          for (const [n, name] of bootNames.entries()) {
            assert.deepEqual(fs.readFileSync(path.join(env.STAGE_DIR, 'kvmapp/system/init.d', name)), bootBytes[n]);
          }
        }
      } else {
        assert.notEqual(result.status, 0, 'faulty package reported success');
        if (fault === 'existing') assert.equal(fs.readFileSync(archive, 'utf8'), 'previous archive\n');
        else assert(!fs.existsSync(archive), 'failed packaging published an archive');
      }
      console.log(`PASS ${label}`);
    } catch (error) {
      failures++;
      console.error(`FAIL ${label}: ${error.message}`);
    } finally {
      fs.rmSync(sentinel, { force: true });
      if (fault === 'app-binding-bundled') fs.rmSync(bundledRecovery);
      if (bundledNative) fs.rmSync(bundledNative);
      if (fault === 'boot-compat-corrupt') fs.writeFileSync(compat, compatBytes);
    }
  }
} finally {
  fs.rmSync(work, { recursive: true, force: true });
}
if (failures) process.exitCode = 1;
else console.log('App package failure regression tests passed');
