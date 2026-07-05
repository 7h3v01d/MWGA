# MWGA — Make Windows Great Again

A **governed tweak console for Windows 11**. It restores the "it just worked on
Windows 10" behaviour that Win11 quietly took away — legacy programs that won't
launch, games that regressed on the same hardware, and homebrew patchers or
customizers that Win11 blocks — without turning your machine into an unaudited
pile of registry edits.

- **Author:** Leon Priest / 7h3v01d
- **License:** Apache 2.0
- **Target:** Windows 11 (Python 3.11). Detects the live OS and gates
  version-specific tweaks accordingly.

---

<img width="1296" height="849" alt="MWGA" src="https://github.com/user-attachments/assets/59d46070-ff5b-433a-abee-2d62a60fca14" />


## Why it isn't a debloat script

Debloat scripts fire a wall of edits with no record and no way back. MWGA treats
every change as a governed operation:

1. **Detect** the current state before doing anything.
2. **Preview** exactly what will change, with an honest tradeoff for anything
   that lowers security.
3. **Approve** — deny-first. Nothing applies without explicit consent, and
   HIGH-risk changes need a second acknowledgement.
4. **Restore point** is created first (best-effort; one per batch).
5. **Backup** the exact prior state — so revert is a real undo, not a guess.
6. **Apply**, then re-detect.
7. **Audit** every stage to a chain-hashed, tamper-evident log.

One-click / one-command **revert** restores the captured prior state precisely,
including restoring a value to *absent* if that's how it started.

---

## Architecture

The layers are cleanly separated — the domain is pure data, and each layer on
top only depends on the ones below it.

| Module              | Role |
|---------------------|------|
| `mwga_catalog.py`   | Domain layer. Declarative `Tweak` objects composed of `Operation`s (`RegistryOp`, `ServiceOp`, `CommandOp`, `AppCompatLayersOp`). Soft-imports `winreg` so the catalog is inspectable and testable off-Windows. |
| `mwga_engine.py`    | `GovernedApplier` — the deny-first pipeline, plus chain-hashed `AuditLog`, `BackupStore`, `RestorePointGate`, and parameter binding with `path_guard` + PowerShell escaping. |
| `mwga_profiles.py`  | Named batches ("gaming", "privacy", "legacy") run through **one** shared restore point instead of one per tweak. |
| `mwga_cli.py`       | Stdlib-only CLI. Qt-free. Structured exit codes for CI. |
| `mwga_panel.py`     | PyQt6 desktop GUI. Dark-industrial theme, category tabs, profile cards, live audit log. |
| `test_mwga.py`      | Test suite (54 passing + 1 Windows-only real-registry round-trip). |

Because the GUI and CLI both build themselves from the catalog, **adding a tweak
is appending one declarative object** — every front-end picks it up
automatically.

---

## Install

```bash
git clone <your-repo-url> MWGA
cd MWGA

# GUI:
pip install -r requirements.txt

# Tests / development (Qt-free):
pip install -r requirements-dev.txt
```

The GUI requires **PyQt6** (imported explicitly; PySide6 is not a drop-in). The
CLI and the test suite need no third-party packages.

Some tweaks write to `HKLM` or run DISM/Defender commands and therefore need an
**elevated** shell; the per-user compatibility shims and most UX tweaks do not.
System Restore also needs admin and System Protection enabled on the system
drive.

---

## Usage — GUI

```bash
python mwga_panel.py
```

- **Profiles** tab — apply a curated set in one governed sweep.
- Category tabs — apply/revert individual tweaks. HIGH-risk rows are flagged and
  gate behind a tradeoff acknowledgement.
- **Restore point first** / **Dry run** toggles apply to every action.
- **Detect all** re-reads current state; **Verify audit** checks the log chain.
- Read-only advisory items (e.g. Smart App Control) show an **Info** button
  instead of Apply — MWGA reports their state but never writes them.

## Usage — CLI

```bash
python mwga_cli.py env                       # host + paths
python mwga_cli.py list                      # all tweaks by category
python mwga_cli.py profiles                  # available profiles
python mwga_cli.py detect [ids...]           # current state (--json for scripts)
python mwga_cli.py show <id>                  # full detail incl. operations

# deny-first: nothing applies without --yes; HIGH also needs --i-understand
python mwga_cli.py apply ux.show_extensions --yes
python mwga_cli.py apply sec.hvci_memory_integrity --yes --i-understand
python mwga_cli.py apply compat.per_app_fso_off --param exe="C:\Games\game.exe" --yes
python mwga_cli.py revert ux.show_extensions --yes

python mwga_cli.py run-profile legacy_compat --yes
python mwga_cli.py run-profile gaming_aggressive --yes --i-understand --dry-run

python mwga_cli.py verify-audit
```

Flags: `--yes`, `--i-understand`, `--dry-run`, `--no-restore-point`,
`--param KEY=VALUE` (repeatable), `--json`.

### Exit codes

| Code | Meaning |
|------|---------|
| 0 | applied / dry-run / advisory |
| 1 | error |
| 2 | usage error |
| 3 | denied (missing consent) |
| 4 | aborted (restore point / batch) |
| 5 | not applicable to this machine |
| 6 | audit chain broken |

State and backups live under `~/.mwga/` (`audit.jsonl`, `backups/`).

---

## What it covers

Tweaks are grouped into categories: **ISO & File Handling**, **Security &
Isolation**, **Gaming & GPU**, **Performance & Power**, **Telemetry &
Services**, **Explorer & UX**, and **Legacy Compatibility**.

Targeted at the common "worked on Win10, broke on Win11" cases:

- **Games that regressed on the same machine** — Memory Integrity (HVCI) / VBS,
  Multi-Plane Overlay, Fullscreen Optimizations (system-wide *and* per-game),
  HAGS, GameDVR.
- **Older programs that won't run** — per-app compatibility shims (run-as-admin,
  Win7/Win8 mode, high-DPI override) via a token-merging `AppCompatLayersOp`,
  plus .NET Framework 3.5 and DirectPlay enablement, and long-path support.
- **Homebrew / patchers / customizers** — scoped Defender folder exclusions,
  PUA/HackTool protection, Mark-of-the-Web suppression, per-exe CFG mitigation
  for injection-based mods, and a **read-only Smart App Control status** report.
- **Snappier desktop & privacy** — animations/delay trims, classic context menu
  (Win11 only), telemetry service and advertising-ID controls.

Profiles bundle safe sets: `gaming_safe`, `gaming_aggressive`, `privacy`,
`responsiveness`, `legacy_compat`, `ssd_services`.

---

## Safety & security (read this)

- **HIGH-risk tweaks genuinely lower your security posture.** Disabling HVCI,
  SmartScreen, PUA protection or Mark-of-the-Web are real downgrades. MWGA's job
  is to make that cost visible and reversible, not to hide it — every HIGH tweak
  carries a tradeoff, and the test suite *fails* if one doesn't.
- **Prefer scoped over global.** For patchers/customizers, a Defender exclusion
  pointed at one specific mods folder is far safer than turning protection off
  system-wide. The catalog is written to steer you that way.
- **Smart App Control is report-only** by design — it cannot be turned back on
  without reinstalling Windows, so MWGA will not toggle it.
- **Restore point + per-change backups + exact revert** are your safety net, but
  they are not a substitute for knowing what a change does. Read the tradeoff.

---

## Testing

```bash
pytest -q
```

The suite is Qt-free and OS-portable: the full governance pipeline is exercised
via an in-memory operation, and a Windows-only block performs a real
`winreg` write → detect → revert against a scratch `HKCU` key (no admin,
self-cleaning). Run it **on real Windows hardware** — CI alone won't exercise
the registry, service and PowerShell/DISM paths.

---

## Status & caveats

- Built on Windows 10; targets Windows 11. OS-version gating means
  Win11-only tweaks report as *not applicable* on Win10.
- The registry engine is validated on real hardware (the `winreg` round-trip
  test passes on Windows). The `AppCompatLayersOp` write path and the
  PowerShell/DISM command tweaks (.NET 3.5, DirectPlay, Defender, CFG) are
  covered by structural/unit tests but should be verified per-machine — use
  `--dry-run` first.
- No warranty. This edits system settings; understand each change before
  applying it.

---

## License

Apache License 2.0. © Leon Priest / 7h3v01d.
