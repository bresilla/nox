# nox

Declarative Linux installer TUI. Drives an interactive wizard (local or over
SSH against a target machine), emits a [LIS](https://github.com/onix-os/lis)
document describing the system, and applies it to NixOS via its opinionated
translator (disko + flake config generation).

- `nox install-preview` — run the wizard without executing anything
- `nox install` — the real thing (destructive steps gated behind preflight + a typed confirmation)
- `nox lis-apply --file system.lis.json` — LIS document → generated nix files

Build: `nix build .#nox` (or `.#nox-static` for a portable single binary).
Develop: `nix develop`, then `make run`.
