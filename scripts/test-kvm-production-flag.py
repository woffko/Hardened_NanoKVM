#!/usr/bin/env python3
"""Compile the actual native flag predicate and exercise real file metadata."""
import pathlib
import re
import subprocess
import tempfile

root = pathlib.Path(__file__).resolve().parents[1]
source = (root / 'support/sg2002/kvm_system/main/src/main.cpp').read_text()
predicate = re.search(r'static bool trusted_runtime_flag\([^}]+\n}', source).group(0)
assert 'trusted_runtime_flag("/run/nanokvm-production-test")' in source
assert '/tmp/S49kvmtest' not in source
with tempfile.TemporaryDirectory() as tmp:
    work = pathlib.Path(tmp)
    test = work / 'test.cpp'
    test.write_text('#include <sys/stat.h>\n#include <unistd.h>\n#include <fcntl.h>\n'
                    '#include <cassert>\n' + predicate + r'''
int main(int argc, char** argv) {
    assert(argc == 2);
    assert(chdir(argv[1]) == 0);
    assert(!trusted_runtime_flag("missing"));
    int fd = open("flag", O_CREAT | O_WRONLY | O_EXCL, 0600);
    assert(fd >= 0); close(fd);
    assert(trusted_runtime_flag("flag"));
    assert(chmod("flag", 0666) == 0);
    assert(!trusted_runtime_flag("flag"));
    assert(chmod("flag", 0620) == 0);
    assert(!trusted_runtime_flag("flag"));
    assert(chmod("flag", 0600) == 0);
    assert(symlink("flag", "link") == 0);
    assert(!trusted_runtime_flag("link"));
    assert(mkfifo("fifo", 0600) == 0);
    assert(!trusted_runtime_flag("fifo"));
    assert(mkdir("directory", 0700) == 0);
    assert(!trusted_runtime_flag("directory"));
    // Root-owned host files are unmapped, hence foreign, in this namespace.
    assert(!trusted_runtime_flag("/etc/passwd"));
}
''')
    subprocess.run(['c++', '-std=c++20', '-Wall', '-Wextra', '-Werror',
                    '-fno-exceptions', '-fno-rtti', str(test), '-o', str(work / 'test')], check=True)
    subprocess.run(['unshare', '--user', '--map-root-user', str(work / 'test'), tmp], check=True)
print('native production flag: PASS')
