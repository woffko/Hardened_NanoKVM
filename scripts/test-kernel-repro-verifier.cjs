#!/usr/bin/env node
'use strict';

const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const { spawnSync } = require('node:child_process');
const root = path.resolve(__dirname, '..');
const args = process.argv.slice(2);
assert(args.length === 0 || (args.length === 2 && args[0] === '--baseline-ref'),
  'usage: node scripts/test-kernel-repro-verifier.cjs [--baseline-ref COMMIT]');
const work = fs.mkdtempSync(path.join(os.tmpdir(), 'nanokvm-repro-test-'));
let failures = 0;

// These are synthetic bytes for verifier behavior, not bootable artifacts.
const files = [
  'kernel/.config', 'kernel/Module.symvers', 'kernel/System.map', 'kernel/vmlinux',
  'kernel/arch/riscv/boot/Image',
  ...['sg2000_duo_sd', 'sg2002_duo_sd', 'sg2002_licheervnano_sd']
    .map(name => `kernel/arch/riscv/boot/dts/cvitek/${name}.dtb`),
  'runtime/system/sdk-release', 'runtime/kvmapp-dl-lib/libfixture.so',
  'runtime/loaders/ld-fixture.so', 'buildroot/images/rootfs.ext2',
  'buildroot/images/rootfs.tar', 'boot/workspace/boot.itb',
  'recovery/assembly/images/hardened-sg2002-port.img',
  'recovery/assembly/images/hardened-sg2002-port.img.xz',
  'recovery/extracted/boot.vfat', 'recovery/extracted/rootfs.sd',
  'recovery/extracted-boot-files/fip.bin', 'recovery/extracted-boot-files/boot.sd',
];
for (const [directory, count] of [
  ['kernel/modules', 24], ['external/artifacts', 30],
  ['media/artifacts', 3], ['runtime/system/ko', 57],
]) {
  for (let i = 0; i < count; i++) files.push(`${directory}/module${i}.ko`);
}

function seed(directory) {
  for (const name of files) {
    const file = path.join(directory, name);
    fs.mkdirSync(path.dirname(file), { recursive: true });
    fs.writeFileSync(file, `synthetic ${name}\n`);
  }
}

try {
  let verifier = path.join(root, 'scripts/verify-kernel-5.10.265-reproducibility.sh');
  if (args[1]) {
    const source = spawnSync('git', ['show', `${args[1]}:scripts/verify-kernel-5.10.265-reproducibility.sh`],
      { cwd: root, encoding: 'utf8' });
    if (source.error) throw source.error;
    assert.equal(source.status, 0, source.stderr);
    verifier = path.join(work, 'baseline.sh');
    fs.writeFileSync(verifier, source.stdout);
  }
  const cases = [
    ['complete identical inventories pass', 0, () => {}],
    ['different module bytes reject', 1, (left, right) => {
      fs.appendFileSync(path.join(right, 'external/artifacts/module0.ko'), 'different\n');
    }],
    ['both external trees empty reject', 1, (left, right) => {
      for (const dir of [left, right]) {
        fs.rmSync(path.join(dir, 'external/artifacts'), { recursive: true });
        fs.mkdirSync(path.join(dir, 'external/artifacts'));
      }
    }],
    ['both kernel module sets absent reject', 1, (left, right) => {
      for (const dir of [left, right]) fs.rmSync(path.join(dir, 'kernel/modules'), { recursive: true });
    }],
    ['both inventories missing one module reject', 1, (left, right) => {
      for (const dir of [left, right]) fs.unlinkSync(path.join(dir, 'media/artifacts/module0.ko'));
    }],
    ['both runtime loader trees empty reject', 1, (left, right) => {
      for (const dir of [left, right]) fs.unlinkSync(path.join(dir, 'runtime/loaders/ld-fixture.so'));
    }],
    ['empty mandatory rootfs artifacts reject', 1, (left, right) => {
      for (const dir of [left, right]) fs.truncateSync(path.join(dir, 'buildroot/images/rootfs.ext2'));
    }],
    ['missing mandatory artifact rejects', 1, (left, right) => {
      for (const dir of [left, right]) fs.unlinkSync(path.join(dir, 'kernel/vmlinux'));
    }],
    ['different symlink targets reject', 1, (left, right) => {
      fs.symlinkSync('ld-fixture.so', path.join(left, 'runtime/loaders/alias'));
      fs.symlinkSync('other.so', path.join(right, 'runtime/loaders/alias'));
    }],
  ];
  for (const [index, [label, expected, mutate]] of cases.entries()) {
    const left = path.join(work, `case${index}/left`);
    const right = path.join(work, `case${index}/right`);
    seed(left);
    seed(right);
    mutate(left, right);
    const result = spawnSync('bash', [verifier, left, right, path.join(work, `report${index}`)],
      { cwd: root, encoding: 'utf8', timeout: 15000 });
    if (result.error) throw result.error;
    const pass = expected === 0 ? result.status === 0 : result.status !== 0;
    console[pass ? 'log' : 'error'](`${pass ? 'PASS' : 'FAIL'} ${label}`);
    if (!pass) failures++;
  }
} finally {
  fs.rmSync(work, { recursive: true, force: true });
}
if (failures) process.exitCode = 1;
else console.log('Kernel reproducibility verifier regression tests passed');
