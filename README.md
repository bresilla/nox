# nox

A declarative Linux installer TUI. nox drives an interactive wizard — locally
or over SSH against a target machine — and emits **exactly one artifact**: a
[LIS](https://github.com/onix-os/lis) document (`system.lis.json`) describing
the machine to build. It writes no distro configuration itself; the config
repo it operates on translates the document at evaluation time.

```
┌───────────────┐        ┌─────────────────────┐        ┌──────────────────┐
│   nox (TUI)   │  emits │  system.lis.json    │  read  │  config repo     │
│   the wizard  │ ─────▶ │  the LIS document   │ ─────▶ │  host/lis/*.nix  │
└───────────────┘        └─────────────────────┘        │  → disko, users, │
      also probes disks, runs preflight,                │    secrets, boot │
      and executes the install steps                    └──────────────────┘
```

## What the wizard covers

Target scope (local / remote over SSH with an auto-bootstrapped agent), disks
painted into LVM pools across multiple drives, per-volume filesystems with
btrfs subvolumes, encryption, users with in-process password hashing, secrets
policy (YubiKey / age key file / install without secrets), and a preflight
panel (ssh, remote tools, capacity, target facts, secrets) gating a typed
destructive confirmation.

## Commands

- `nox install-preview` — run the full wizard, execute nothing
- `nox install` — the real thing (destructive steps stay behind preflight + confirmation)
- `nox lis-apply --file doc.lis.json` — validate a LIS document and stage it as the repo's `system.lis.json`
- `nox storage plan` — human-readable view of the staged document's storage
- `nox preflight`, `nox facts`, `nox disk-scan …` — individual probes

The wizard also **resumes**: a `system.lis.json` from an earlier session
restores all previous answers on startup.

## Pairing with a config repo

nox operates on a repo identified by `host/flake.nix`. Since v0.2.0 the repo
must carry the LIS applier (`host/lis/` translating `generated/system.lis.json`
into disko devices and system options) — see
[bresilla/nixos](https://github.com/bresilla/nixos). The install plan applies
storage via the repo's committed `host/lis/disko.nix`, then runs
`nixos-install` against the repo flake.

## Build & develop

```
nix build .#nox           # wrapped binary (disko on PATH)
nix build .#nox-static    # fully static single-file binary (what releases ship)
nix develop               # dev shell (pcsclite, rust toolchain)
make run                  # cargo run -- install-preview
```

The remote agent is nix-built from this flake; set `NOX_FLAKE=path:$PWD`
(done by `.envrc`) so local development bootstraps agents from your checkout
instead of the published `github:bresilla/nox`.

Releases: `gh release create vX.Y.Z` — CI attaches the static binary as `nox`,
which `install.sh` in the config repo fetches:
`curl -L https://nix.bresilla.dev | bash`.
