#!/usr/bin/env python3
"""Bind the independent static app recovery to its exact backend build.

This is a build consistency tool, not an RSA signature or runtime health API.
The app domain cannot satisfy the SSH helper domain (or vice versa).
"""

import importlib.util
from pathlib import Path
import sys

SPEC = importlib.util.spec_from_file_location(
    "nanokvm_runtime_binding", Path(__file__).with_name("ssh-runtime-binding.py"))
binding = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(binding)

MAGIC = binding.APP_RECOVERY_MAGIC


if __name__ == "__main__":
    try:
        binding.main(magic=MAGIC, description=__doc__)
    except (OSError, ValueError) as error:
        print(f"App recovery binding rejected: {error}", file=sys.stderr)
        sys.exit(1)
