#!/usr/bin/env node
'use strict';

// Function-level shell fixture. It never invokes start_usb_dev, touches real
// configfs, or connects to a device. --baseline-ref executes the original
// mass-storage block, unmodified except for its /boot fixture path.
const fs = require('fs');
const os = require('os');
const path = require('path');
const { spawnSync } = require('child_process');
const root = path.resolve(__dirname, '..');
const args = process.argv.slice(2);
if (args.length && (args.length !== 2 || args[0] !== '--baseline-ref')) throw Error('invalid arguments');
const sourcePath = 'kvmapp/system/init.d/S03usbdev';
const source = args.length
  ? (() => {
    const r = spawnSync('git', ['show', `${args[1]}:${sourcePath}`], { cwd: root, encoding: 'utf8' });
    if (r.status !== 0) throw Error(r.stderr || 'git show failed');
    return r.stdout;
  })()
  : fs.readFileSync(path.join(root, sourcePath), 'utf8');
const fixture = fs.mkdtempSync(path.join(os.tmpdir(), 'nanokvm-usb-boundary-'));
let failures = 0;
try {
  for (const [name, value] of [
    ['empty legacy flag', ''],
    ['raw partition flag', '/dev/mmcblk0p3'],
    ['private raw payload flag', '/data/.hardened-kvmcache/system-update/payload/rootfs.img'],
    ['old media flag', '/data/installer.iso'],
  ]) {
    const dir = path.join(fixture, String(fs.readdirSync(fixture).length));
    const lun = path.join(dir, 'functions/mass_storage.disk0/lun.0');
    fs.mkdirSync(lun, { recursive: true });
    fs.mkdirSync(path.join(dir, 'configs/c.1'), { recursive: true });
    fs.mkdirSync(path.join(dir, 'boot'));
    fs.writeFileSync(path.join(dir, 'boot/usb.disk0'), value);
    fs.writeFileSync(path.join(lun, 'file'), '/dev/mmcblk0p3\n');
    let body = source.split(/^case "\$1" in/m)[0];
    if (!source.includes('configure_empty_storage()')) {
      const start = source.indexOf('    if [ -e /boot/usb.disk0 ]');
      const end = source.indexOf('\n    ls /sys/class/udc/', start);
      if (start < 0 || end < 0) throw Error('baseline mass-storage block not found');
      body += `\nconfigure_empty_storage() {\n${source.slice(start, end).replaceAll('/boot/', `${dir}/boot/`)}\n}\n`;
    }
    fs.writeFileSync(path.join(dir, 'fixture.sh'), `${body}\nconfigure_empty_storage\n`);
    const r = spawnSync('/bin/sh', ['fixture.sh'], { cwd: dir, encoding: 'utf8' });
    const backing = fs.readFileSync(path.join(lun, 'file'), 'utf8').trim();
    const ok = r.status === 0 && backing === '';
    process.stdout.write(`${ok ? 'PASS' : 'FAIL'} ${name}: backing=${JSON.stringify(backing)}\n`);
    if (!ok) failures++;
    if (ok) {
      // Repeated start must stay empty, including an old nonempty flag.
      const again = spawnSync('/bin/sh', ['fixture.sh'], { cwd: dir, encoding: 'utf8' });
      if (again.status !== 0 || fs.readFileSync(path.join(lun, 'file'), 'utf8').trim()) failures++;
    }
  }
  if (source.includes('configure_empty_storage()')) {
    for (const attribute of ['file', 'ro']) {
      const dir = path.join(fixture, `failure-${attribute}`);
      const lun = path.join(dir, 'functions/mass_storage.disk0/lun.0');
      fs.mkdirSync(lun, { recursive: true });
      fs.mkdirSync(path.join(dir, 'configs/c.1'), { recursive: true });
      fs.mkdirSync(path.join(lun, attribute));
      const body = source.split(/^case "\$1" in/m)[0];
      fs.writeFileSync(path.join(dir, 'fixture.sh'), `${body}\nconfigure_empty_storage\n`);
      const r = spawnSync('/bin/sh', ['fixture.sh'], { cwd: dir, encoding: 'utf8' });
      const ok = r.status !== 0 && !fs.existsSync(path.join(dir, 'configs/c.1/mass_storage.disk0'));
      process.stdout.write(`${ok ? 'PASS' : 'FAIL'} ${attribute} write failure refuses media link\n`);
      if (!ok) failures++;
    }
  }
} finally {
  fs.rmSync(fixture, { recursive: true, force: true });
}
if (failures) process.exitCode = 1;
