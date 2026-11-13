#!/usr/bin/env python3
"""Exercise the raw image prerequisite gate against an actual ext filesystem."""
import pathlib
import subprocess
import tempfile
import unittest

GATE = pathlib.Path(__file__).with_name('validate-raw-restore-rootfs.sh')


class RestoreImageGate(unittest.TestCase):
    def test_missing_and_unsafe_staging_are_rejected(self):
        with tempfile.TemporaryDirectory(prefix='raw-restore-gate-') as work:
            work = pathlib.Path(work)
            image = work / 'rootfs.img'
            with image.open('wb') as stream:
                stream.truncate(16 * 1024 * 1024)
            subprocess.run(['mke2fs', '-q', '-t', 'ext2', '-F', str(image)], check=True)
            marker = work / 'marker'
            marker.write_bytes(b'nanokvm-raw-restore-required-v1\n')
            helper = work / 'helper'
            helper.write_bytes(b'fixture executable\n')

            def edit(commands):
                batch = work / 'commands'
                batch.write_text('\n'.join(commands) + '\n')
                subprocess.run(['debugfs', '-w', '-f', str(batch), str(image)],
                               check=True, capture_output=True)

            def check(expected):
                result = subprocess.run(['sh', str(GATE), str(image)],
                                        capture_output=True, text=True)
                self.assertEqual(result.returncode, expected, result.stdout + result.stderr)

            edit(['mkdir /etc', 'mkdir /etc/kvm', 'mkdir /etc/init.d',
                  'mkdir /usr', 'mkdir /usr/libexec',
                  f'write {marker} /etc/kvm/raw-restore-required',
                  'sif /etc/kvm/raw-restore-required mode 0100644',
                  f'write {helper} /usr/libexec/nanokvm-early-restore',
                  f'write {helper} /etc/init.d/S01restore',
                  'sif /usr/libexec/nanokvm-early-restore mode 0100755',
                  'sif /etc/init.d/S01restore mode 0100755'])
            check(1)  # The released raw44 image omitted this directory.
            edit(['mkdir /etc/kvm/.raw-restore',
                  'sif /etc/kvm/.raw-restore mode 040700'])
            check(0)
            edit(['sif /etc/kvm/.raw-restore mode 040755'])
            check(1)
            edit(['sif /etc/kvm/.raw-restore mode 040700',
                  'sif /etc/kvm/.raw-restore uid 1000'])
            check(1)
            edit(['sif /etc/kvm/.raw-restore uid 0'])
            check(0)
            edit(['sif /etc/kvm/raw-restore-required mode 0100600'])
            check(1)


if __name__ == '__main__':
    unittest.main()
