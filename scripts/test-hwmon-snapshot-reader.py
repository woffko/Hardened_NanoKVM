#!/usr/bin/env python3
"""Exercise the compiled native snapshot reader against hostile filesystem inputs."""
import pathlib
import re
import subprocess
import tempfile

root = pathlib.Path(__file__).resolve().parents[1]
source = (root / 'support/sg2002/kvm_system/main/lib/system_state/system_state.cpp').read_text()
reader = re.search(r'static int read_hwmon_snapshot_file\(.*?\n}', source, re.S).group(0)
with tempfile.TemporaryDirectory() as tmp:
    work = pathlib.Path(tmp)
    test = work / 'test.cpp'
    test.write_text('''#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <errno.h>
#include <time.h>
#include <cstring>
#include <cassert>
#define RUST_HWMON_MAX_AGE_SEC 20
#define RUST_HWMON_MAX_BYTES 8192
''' + reader + r'''
int main(int argc, char** argv) {
    assert(argc == 2); assert(chdir(argv[1]) == 0);
    char buf[8192];
    assert(!read_hwmon_snapshot_file("missing", buf, sizeof(buf)));
    int fd = open("state", O_CREAT | O_WRONLY | O_EXCL, 0600);
    assert(fd >= 0); assert(write(fd, "{}", 2) == 2); close(fd);
    assert(read_hwmon_snapshot_file("state", buf, sizeof(buf)));
    assert(strcmp(buf, "{}") == 0);
    assert(!read_hwmon_snapshot_file("state", buf, 2));
    assert(symlink("state", "link") == 0);
    assert(!read_hwmon_snapshot_file("link", buf, sizeof(buf)));
    assert(mkfifo("fifo", 0600) == 0);
    assert(!read_hwmon_snapshot_file("fifo", buf, sizeof(buf)));
    assert(mkdir("dir", 0700) == 0);
    assert(!read_hwmon_snapshot_file("dir", buf, sizeof(buf)));
    assert(!read_hwmon_snapshot_file("/etc/passwd", buf, sizeof(buf)));
    assert(chmod("state", 0666) == 0);
    assert(!read_hwmon_snapshot_file("state", buf, sizeof(buf)));
    assert(chmod("state", 0600) == 0);
    timespec times[2] = {{time(nullptr) - 60, 0}, {time(nullptr) - 60, 0}};
    assert(utimensat(AT_FDCWD, "state", times, 0) == 0);
    assert(!read_hwmon_snapshot_file("state", buf, sizeof(buf)));
    times[0].tv_sec = times[1].tv_sec = time(nullptr) + 60;
    assert(utimensat(AT_FDCWD, "state", times, 0) == 0);
    assert(!read_hwmon_snapshot_file("state", buf, sizeof(buf)));
    fd = open("state", O_WRONLY | O_TRUNC);
    assert(fd >= 0); assert(write(fd, "{\0}", 3) == 3); close(fd);
    assert(!read_hwmon_snapshot_file("state", buf, sizeof(buf)));
    assert(truncate("state", 9000) == 0);
    assert(!read_hwmon_snapshot_file("state", buf, sizeof(buf)));
    assert(truncate("state", 0) == 0);
    assert(!read_hwmon_snapshot_file("state", buf, sizeof(buf)));
}
''')
    subprocess.run(['c++', '-std=c++20', '-Wall', '-Wextra', '-Werror',
                    '-fno-exceptions', '-fno-rtti', str(test), '-o', str(work / 'test')], check=True)
    subprocess.run(['unshare', '--user', '--map-root-user', str(work / 'test'), tmp],
                   check=True, timeout=5)
print('native hwmon snapshot reader: PASS')
