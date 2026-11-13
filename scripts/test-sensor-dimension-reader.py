#!/usr/bin/env python3
"""The frame dimension reader of the vendor sensor code, compiled for the host
with the address and undefined-behaviour sanitizers. The whole file used to be
read into a 35-byte array on the stack; a longer file must now be harmless, and
a well-formed one must give what atoi() gave."""
import pathlib
import re
import subprocess
import tempfile

root = pathlib.Path(__file__).resolve().parents[1]
path = root / 'support/sg2002/additional/sophgo-middleware/v2/sample/common/sample_common_sensor.c'
source = path.read_text()
reader = re.search(r'static CVI_U32 SAMPLE_COMM_SNS_ReadDimension\(.*?\n}', source, re.S).group(0)
case = source.split('case PIC_CUSTOMIZE:', 1)[1].split('break;', 1)[0]
assert 'RW_Data' not in source, 'the unbounded stack buffer is back'
assert 'SAMPLE_COMM_SNS_ReadDimension("/kvmapp/kvm/width", 1920)' in case, case
assert 'SAMPLE_COMM_SNS_ReadDimension("/kvmapp/kvm/height", 1080)' in case, case
assert 'fread' not in case and 'ftell' not in case, 'the customize case reads a file by itself'

with tempfile.TemporaryDirectory() as tmp:
    work = pathlib.Path(tmp)
    (work / 'test.c').write_text('''#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
typedef unsigned int CVI_U32;
''' + reader + r'''
static void put(const char *name, const char *bytes, size_t length) {
    FILE *fp = fopen(name, "w");
    assert(fp != NULL);
    assert(fwrite(bytes, 1, length, fp) == length);
    assert(fclose(fp) == 0);
}
static CVI_U32 text(const char *value) {
    put("value", value, strlen(value));
    return SAMPLE_COMM_SNS_ReadDimension("value", 1920);
}
int main(void) {
    char big[4096];
    assert(SAMPLE_COMM_SNS_ReadDimension("missing", 1920) == 1920);
    assert(SAMPLE_COMM_SNS_ReadDimension(".", 1080) == 1080 || SAMPLE_COMM_SNS_ReadDimension(".", 1080) == 0);
    /* What kvm_system writes, and what atoi() made of other text. */
    assert(text("1920\n") == 1920);
    assert(text("1080") == 1080);
    assert(text("0\n") == 0);
    assert(text("") == 0);
    assert(text("abc\n") == 0);
    assert(text("720\n480\n") == 720);
    assert(text("65535\n") == 65535);
    /* Out of range gives the fallback instead of a wrapped number. */
    assert(text("65536\n") == 1920);
    assert(text("-1\n") == 1920);
    assert(text("99999999999999999999999999999999999999999999\n") == 1920);
    /* Longer than the old 35-byte array: digits, then padding, then no NUL. */
    memset(big, '9', sizeof(big));
    put("value", big, sizeof(big));
    assert(SAMPLE_COMM_SNS_ReadDimension("value", 1920) == 1920);
    memset(big, '\n', sizeof(big));
    memcpy(big, "1280", 4);
    put("value", big, sizeof(big));
    assert(SAMPLE_COMM_SNS_ReadDimension("value", 1920) == 1280);
    memset(big, 0, sizeof(big));
    put("value", big, 36);
    assert(SAMPLE_COMM_SNS_ReadDimension("value", 1920) == 0);
    return 0;
}
''')
    subprocess.run(['cc', '-std=c11', '-O1', '-g', '-Wall', '-Wextra', '-Werror',
                    '-fsanitize=address,undefined', '-fno-sanitize-recover=all',
                    '-fno-omit-frame-pointer', 'test.c', '-o', 'test'], cwd=work, check=True)
    subprocess.run([str(work / 'test')], cwd=work, check=True,
                   env={'ASAN_OPTIONS': 'detect_leaks=0:halt_on_error=1',
                        'UBSAN_OPTIONS': 'halt_on_error=1'})
print('sensor dimension reader: PASS')
