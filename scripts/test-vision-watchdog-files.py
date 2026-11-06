#!/usr/bin/env python3
"""Compile native watchdog file operations and check hostile file handling."""
import pathlib
import re
import subprocess
import tempfile

root = pathlib.Path(__file__).resolve().parents[1]
source = (root / 'support/sg2002/additional/kvm/src/kvm_vision.cpp').read_text()
assert '"/tmp/watchdog"' not in source and '"/tmp/nanokvm_wd"' not in source
functions = '\n'.join(re.search(pattern + r'.*?\n}', source, re.S).group(0) for pattern in (
    r'static bool trusted_watchdog_flag\(', r'uint8_t watchdog_sf_is_open\(',
    r'int vision_update_watchdog\('))
with tempfile.TemporaryDirectory() as tmp:
    work = pathlib.Path(tmp)
    test = work / 'test.cpp'
    test.write_text('''#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <cstdint>
#include <cassert>
#define watchdog_mode_path "persistent"
#define watchdog_temp_path "temporary"
#define watchdog_file "heartbeat"
''' + functions + r'''
int main(int argc, char** argv) {
    assert(argc == 2); assert(chdir(argv[1]) == 0);
    assert(!watchdog_sf_is_open());
    int fd = open("temporary", O_CREAT | O_WRONLY | O_EXCL, 0600);
    assert(fd >= 0); close(fd);
    assert(watchdog_sf_is_open());
    assert(chmod("temporary", 0666) == 0);
    assert(!watchdog_sf_is_open());
    assert(unlink("temporary") == 0);
    assert(symlink("/etc/passwd", "temporary") == 0);
    assert(!watchdog_sf_is_open());
    assert(vision_update_watchdog() == 1);
    struct stat st;
    assert(stat("heartbeat", &st) == 0 && (st.st_mode & 0777) == 0600);
    fd = open("heartbeat", O_WRONLY); assert(fd >= 0);
    assert(write(fd, "keep", 4) == 4); close(fd);
    assert(link("heartbeat", "victim") == 0);
    assert(vision_update_watchdog() == -1);
    assert(stat("victim", &st) == 0 && st.st_size == 4);
    assert(unlink("heartbeat") == 0);
    assert(symlink("victim", "heartbeat") == 0);
    assert(vision_update_watchdog() == -1);
    assert(stat("victim", &st) == 0 && st.st_size == 4);
    assert(unlink("heartbeat") == 0);
    assert(mkfifo("heartbeat", 0600) == 0);
    assert(vision_update_watchdog() == -1);
    assert(unlink("heartbeat") == 0);
    assert(mkdir("heartbeat", 0700) == 0);
    assert(vision_update_watchdog() == -1);
}
''')
    subprocess.run(['c++', '-std=c++20', '-Wall', '-Wextra', '-Werror',
                    '-fno-exceptions', '-fno-rtti', str(test), '-o', str(work / 'test')], check=True)
    subprocess.run(['unshare', '--user', '--map-root-user', str(work / 'test'), tmp],
                   check=True, timeout=5)
print('native vision watchdog files: PASS')
