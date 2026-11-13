# Native SDK Docker input boundary

`docker/Dockerfile` builds the SG2002 native SDK environment. It does not need
the Rust backend, web tree, runtime app tree, Git history, Buildroot outputs or
local test/deployment state.

The root `.dockerignore` starts with a deny-all rule and admits only exact
native source/build files and `docker/Dockerfile` / `docker/entrypoint`.
Directory exceptions permit traversal and are immediately followed by a child
deny rule. A new file is not admitted merely because it is next to an approved
source file. The Dockerfile also copies only its explicit native inputs, never
the repository root.

Do not add broad directory/glob exceptions. When native inputs change, review
the new files and update the exact file exceptions. Keep the directory fences
in ancestor-first order. A Dockerfile-specific ignore file can override the
root policy, so do not introduce one without equivalent validation.

Before a native SDK Docker build, run:

```sh
python3 -B scripts/test-docker-context.py
python3 -B scripts/test-docker-context.py --engine
docker build --file docker/Dockerfile .
```

The first command checks the restricted policy structure, complete tracked
input inventory, regular nonsymlink source paths and explicit COPY inputs. It
is not an implementation of Docker's glob matcher and does not prove engine
behavior. The second command requires Docker/Buildx and exports two scratch
images made exclusively from synthetic fixture files: the previous policy must
expose the synthetic sentinels; the new policy must export every required input
and no sentinel. It downloads no base image and sends no repository contents
to the builder. Use a trusted local builder for the actual SDK build.

At implementation time Docker/BuildKit was unavailable on the build host.
Static checks passed; real engine context acceptance and the SDK build remain
NOT TESTED. This is a source-level M13 improvement, not complete release
acceptance.

The image inputs are pinned (L-S13):

- the base image by digest (`ubuntu:24.04@sha256:68ee2200…`, the 24.04 index
  on 2026-10-23);
- the toolchain by SHA-256. It is now `host-tools-2025.7.28.tar.xz` from the
  MaixCDK release, the archive MaixCDK pins in `dl/pkgs_info.json` and the
  native builds use, instead of the unhashed 2023 vendor archive;
- MaixCDK by commit (`5b0aa5b1…`, the base of the local SDK checkout);
- the Python packages by `docker/maixcdk-requirements.lock`, installed with
  `--require-hashes --no-deps`.

`scripts/lock-maixcdk-requirements.py` writes the lock from `pip freeze` of the
MaixCDK environment, with the PyPI hashes of the files that fit CPython 3.12 on
x86_64. A fresh virtual environment installed from it matched that freeze
exactly. The apt packages still come from the Ubuntu archive at build time and
are not pinned. The image has not been built with these pins, because no Docker
engine is available here.

`kvm_system/main/lib/system_ctrl/ap_key.h`, added with the AP key fix (M2),
was not admitted and would have been missing from a Docker build. It is
admitted now.

The allowlist does not detect a secret deliberately written into an approved
source file, authorize untrusted changes, or replace source review and release
secret scans. Do not put private keys or credentials into source inputs.

Docker's context filtering and ignore-file precedence are described in the
[official build-context documentation](https://docs.docker.com/build/concepts/context/#dockerignore-files).
