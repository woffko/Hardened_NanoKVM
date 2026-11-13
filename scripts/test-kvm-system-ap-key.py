#!/usr/bin/env python3
"""Host checks of the kvm_system Wi-Fi AP key: generation and 0600 storage.

The header is compiled for the host with the system C++ compiler. No device,
OLED or hostapd is involved.
"""
from collections import Counter
from pathlib import Path
import os
import stat
import subprocess
import tempfile
import unittest

ROOT = Path(__file__).resolve().parent.parent
LIB = ROOT / "support/sg2002/kvm_system/main/lib/system_ctrl"
ALPHABET = "23456789abcdefghjkmnpqrstuvwxyz"

HARNESS = r'''
#include <errno.h>
#include <stddef.h>
#include <sys/types.h>
#if defined(AP_KEY_TEST_FAIL)
static ssize_t test_random(void *, size_t, unsigned) { errno = ENOSYS; return -1; }
#define AP_KEY_RANDOM test_random
#elif defined(AP_KEY_TEST_CHUNKED)
#include <sys/random.h>
static int calls;
// One EINTR, then at most three bytes per call.
static ssize_t test_random(void *buffer, size_t length, unsigned flags)
{
	if (calls++ == 0) { errno = EINTR; return -1; }
	return getrandom(buffer, length < 3 ? length : 3, flags);
}
#define AP_KEY_RANDOM test_random
#endif
#include "ap_key.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int main(int argc, char **argv)
{
	if (argc == 3 && strcmp(argv[1], "generate") == 0) {
		int count = atoi(argv[2]);
		for (int i = 0; i < count; i++) {
			char key[AP_KEY_CHARS + 1];
			memset(key, 'X', sizeof(key));
			int result = ap_key_generate(key);
			if (result != 0) {
				int cleared = 1;
				for (size_t j = 0; j < sizeof(key); j++) cleared &= key[j] == 0;
				printf("result=%d cleared=%d\n", result, cleared);
				return 0;
			}
			printf("%s\n", key);
		}
		return 0;
	}
	if (argc == 4 && strcmp(argv[1], "store") == 0) {
		printf("result=%d\n", ap_key_store(argv[2], argv[3]));
		return 0;
	}
	return 2;
}
'''


class ApKeyTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.temporary = tempfile.TemporaryDirectory(prefix="nanokvm-ap-key-")
        work = Path(cls.temporary.name)
        source = work / "harness.cpp"
        source.write_text(HARNESS)
        cls.programs = {}
        for name, define in [("normal", None), ("fail", "AP_KEY_TEST_FAIL"),
                             ("chunked", "AP_KEY_TEST_CHUNKED")]:
            program = work / name
            command = ["c++", "-std=c++17", "-Wall", "-Wextra", "-Werror", "-I", str(LIB),
                       str(source), "-o", str(program)]
            if define:
                command.insert(1, "-D" + define)
            subprocess.run(command, check=True, timeout=120)
            cls.programs[name] = program

    @classmethod
    def tearDownClass(cls):
        cls.temporary.cleanup()

    def run_program(self, name, *args):
        result = subprocess.run([str(self.programs[name]), *args], capture_output=True,
                                text=True, timeout=30, check=True)
        return result.stdout.splitlines()

    def test_keys_are_ten_uniform_unambiguous_characters(self):
        keys = self.run_program("normal", "generate", "3100")
        self.assertEqual(len(keys), 3100)
        for key in keys:
            self.assertEqual(len(key), 10, key)
            self.assertTrue(set(key) <= set(ALPHABET), key)
        self.assertEqual(len(set(keys)), len(keys))
        counts = Counter("".join(keys))
        self.assertEqual(set(counts), set(ALPHABET))
        expected = len(keys) * 10 / len(ALPHABET)
        chi_square = sum((counts[c] - expected) ** 2 / expected for c in ALPHABET)
        # 30 degrees of freedom; 80 is far beyond any plausible uniform sample.
        self.assertLess(chi_square, 80, counts)

    def test_short_and_interrupted_reads_still_fill_the_key(self):
        keys = self.run_program("chunked", "generate", "50")
        self.assertEqual(len(keys), 50)
        for key in keys:
            self.assertEqual(len(key), 10, key)
            self.assertTrue(set(key) <= set(ALPHABET), key)

    def test_a_failing_random_source_gives_no_key(self):
        self.assertEqual(self.run_program("fail", "generate", "1"), ["result=-1 cleared=1"])

    def test_the_key_file_is_replaced_with_mode_0600(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "ap.pass"
            path.write_text("11223344")
            path.chmod(0o644)
            self.assertEqual(self.run_program("normal", "store", str(path), "k3y7m9pq2x"),
                             ["result=0"])
            self.assertEqual(path.read_text(), "k3y7m9pq2x")
            self.assertEqual(stat.S_IMODE(path.stat().st_mode), 0o600)
            self.assertEqual(sorted(os.listdir(directory)), ["ap.pass"])

    def test_a_planted_scratch_link_is_replaced_not_followed(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "ap.pass"
            elsewhere = Path(directory) / "elsewhere"
            elsewhere.write_text("unrelated")
            (Path(directory) / "ap.pass.new").symlink_to(elsewhere)
            self.assertEqual(self.run_program("normal", "store", str(path), "k3y7m9pq2x"),
                             ["result=0"])
            self.assertEqual(elsewhere.read_text(), "unrelated")
            self.assertEqual(path.read_text(), "k3y7m9pq2x")
            self.assertFalse((Path(directory) / "ap.pass.new").exists())

    def test_a_failed_store_leaves_the_old_key(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "ap.pass"
            path.write_text("old")
            (Path(directory) / "ap.pass.new").mkdir()
            self.assertEqual(self.run_program("normal", "store", str(path), "k3y7m9pq2x"),
                             ["result=-1"])
            self.assertEqual(path.read_text(), "old")
            missing = Path(directory) / "missing" / "ap.pass"
            self.assertEqual(self.run_program("normal", "store", str(missing), "k3y7m9pq2x"),
                             ["result=-1"])
            self.assertFalse(missing.parent.exists())

    def test_both_qr_payloads_fit_version_3_at_level_m(self):
        ui = (ROOT / "support/sg2002/kvm_system/main/lib/oled_ui/oled_ui.cpp").read_text()
        self.assertIn("qrInit(3, QR_EM_8BIT, 1,", ui)
        self.assertIn('"WIFI:T:WPA2;S:NanoKVM;P:%s;;"', ui)
        self.assertIn('"http://%s/#/WIFI?P=%s"', ui)
        key = "x" * 10
        # The AP address is 10.<id3>.<id2>.1 with both bytes below 255.
        payloads = ["WIFI:T:WPA2;S:NanoKVM;P:%s;;" % key,
                    "http://%s/#/WIFI?P=%s" % ("10.254.254.1", key)]
        self.assertEqual([len(p) for p in payloads], [36, 39])
        self.assertTrue(all(len(p) <= 42 for p in payloads))

    def test_the_ap_start_uses_only_the_csprng_key(self):
        source = (LIB / "system_ctrl.cpp").read_text()
        self.assertNotIn("srand(", source)
        self.assertNotIn("rand()", source)
        self.assertIn("ap_key_generate(kvm_sys_state.wifi_ap_pass)", source)
        self.assertIn('ap_key_store("/kvmapp/kvm/ap.pass"', source)
        self.assertNotIn('write_text_file("/kvmapp/kvm/ap.pass"', source)


if __name__ == "__main__":
    unittest.main()
