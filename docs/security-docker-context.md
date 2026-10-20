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
acceptance. Pinning Ubuntu, MaixCDK, Python and toolchain downloads is separate
unfinished work (L-S13); those inputs were not changed here.

The allowlist does not detect a secret deliberately written into an approved
source file, authorize untrusted changes, or replace source review and release
secret scans. Do not put private keys or credentials into source inputs.

Docker's context filtering and ignore-file precedence are described in the
[official build-context documentation](https://docs.docker.com/build/concepts/context/#dockerignore-files).
