# PicoClaw local tool policy

The PicoClaw runtime still runs as root on the NanoKVM. Until it runs as its own
unprivileged user, the backend enforces one local tool policy on every
configuration it publishes or launches. This is the first-release measure for
audit finding H2: the dangerous mode is disabled rather than isolated.

The policy closes the NanoKVM's own shell, its hardware buses, local MCP
commands, and every file outside the runtime's workspace.

Control of the connected computer is unchanged. Screenshots, mouse, keyboard,
hotkeys and long input go through the `nanokvm` MCP server. That covers BIOS,
installers and the connected computer's own terminal, without an approval step
per key, hotkey or batch.

## The policy

| Key | Enforced value |
| --- | --- |
| `agents.defaults.restrict_to_workspace` | `true` |
| `agents.defaults.allow_read_outside_workspace` | `false` |
| `agents.defaults.workspace` | `<Home>/workspace` when absent; otherwise it must lie inside it |
| `agents.list[].workspace` | absent, or inside `<Home>/workspace` |
| `tools.exec.enabled` | `false` |
| `tools.cron.allow_command` | `false` (scheduled prompts stay) |
| `tools.serial`, `tools.spi`, `tools.i2c` `.enabled` | `false` |
| `tools.allow_read_paths`, `tools.allow_write_paths` | absent or empty |
| any other MCP server started as a local command (`command` set, or `type: stdio`) | `enabled: false` |

The `nanokvm` MCP server is always the loopback HTTP server. Its entry never
keeps a `command`, `args`, `env` or `env_file`.

Workspace containment is checked on the path text: it must be an absolute path
without `..`, compared component by component. `<Home>/workspace` keeps
`config.json`, `.security.yml` and the internal token outside the tools' reach.

The tools that stay available act on the workspace or the network, not on the
NanoKVM's root: the workspace-confined file tools, web fetch and search
(private hosts are blocked by default), scheduled prompts, sub-agents, skills,
remote (HTTP or SSE) MCP servers and chat channels.

## Why these keys

The keys were chosen by reading upstream picoclaw v0.2.8:

- `DefaultConfig` turns on `exec` (with `allow_remote`), cron commands and all
  file tools. A configuration that omits a key gets the upstream default, so an
  RC12 runtime had a root shell tool. RC12 also forced both workspace switches
  open on every start.
- In restricted mode, the file tools are confined by Go `os.Root` on the
  workspace, which is checked at open and safe against symlinks. The two
  allowlists bypass that confinement through raw host access, with a
  check-then-use gap.
- A per-agent `workspace` overrides the default one. A workspace of `/` would
  make the confinement the whole filesystem.
- `serial`, `spi` and `i2c` reach the NanoKVM's own UARTs, SPI devices and I²C
  bus, including the HDMI bridge and its EDID flash.
- An MCP server of type `stdio` is a local command started by the root runtime.
- Upstream's own `isolation` wraps commands in `bwrap`. That tool is absent
  here, so isolation would fail closed. It also mounts every absolute path
  argument into the sandbox, so it is not a boundary against a hostile agent,
  and the policy does not rely on it.

## Where it is enforced

1. The Startup defaults transform. Both the Startup job and the Model job apply
   it, so every pair they publish carries the policy over any explicit value.
2. Launch preparation for Ensure refuses a pair without the policy.
3. A Profile or Install job never resumes the runtime on a pair without the
   policy. If the runtime was running, its receipt reports that it did not
   resume. The next Startup job applies the policy first.
4. Before Ensure, `nanokvm-native-ctl ensure-picoclaw` (S96 `start`) runs a
   Startup job, as the API start and the gateway connection already do. An
   updated device therefore gets the policy at its first start.

A malformed shape at one of these keys, or a workspace outside
`<Home>/workspace`, is refused: the runtime does not start until the
configuration is corrected.

## What changes for users

- The shell-based `kvm-control` skill cannot run while `exec` is off. The KVM
  profile already uses it only as a fallback when MCP is unavailable, and the
  Startup job always configures the MCP server.
- A user who enabled `exec`, cron commands, hardware tools, extra paths or
  local MCP servers loses them. Administering the NanoKVM itself is planned as a
  separate, explicitly enabled capability. Permission to operate the connected
  computer does not grant it.

## Residual risks

- The runtime is still root. The confinement that remains is upstream
  application code: `os.Root` for the file tools, and a path validator for
  `send_file` with a check-then-use gap. Exploiting that gap needs a process
  that swaps links in the workspace, and the policy leaves the agent no way to
  start one.
- A workspace path that root has replaced with a symlink is outside this
  policy's reach.
- The real operating-system boundary is the next step (WP-15 P2): a separate
  unprivileged user, a private workspace, and a minimal broker to the NanoKVM
  API that grants the KVM capability only.

These are host-tested source paths, not proof that the separately supplied
optional binary matches the inspected upstream source, and not device
acceptance.
