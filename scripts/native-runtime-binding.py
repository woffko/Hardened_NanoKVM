#!/usr/bin/env python3
"""One closed native helper domain, using the shared bounded binding format."""
import importlib.util
from pathlib import Path
import sys

spec = importlib.util.spec_from_file_location("binding", Path(__file__).with_name("ssh-runtime-binding.py"))
binding = importlib.util.module_from_spec(spec)
spec.loader.exec_module(binding)

if __name__ == "__main__":
    try:
        if len(sys.argv) < 2 or sys.argv[1] not in binding.NATIVE_MAGICS:
            raise ValueError("expected fixed native role: owner, broker, ctl or recovery")
        magic = binding.NATIVE_MAGICS[sys.argv.pop(1)]
        binding.main(magic, __doc__)
    except (OSError, ValueError) as error:
        print("Native runtime binding rejected: " + str(error), file=sys.stderr)
        sys.exit(1)
