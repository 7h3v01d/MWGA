"""
MWGA — Make Windows Great Again
CLI layer: headless, stdlib-only access to the governed engine.

Author : Leon Priest / 7h3v01d
License : Apache 2.0

Qt-free by design, so it runs anywhere the engine does. Consent is explicit and
deny-first: without --yes nothing applies (the engine's own approver denies),
and HIGH-risk changes additionally require --i-understand. Exit codes are
structured for CI use.

Examples
--------
    python -m mwga_cli list
    python -m mwga_cli detect
    python -m mwga_cli show sec.hvci_memory_integrity
    python -m mwga_cli apply ux.show_extensions --yes
    python -m mwga_cli apply sec.hvci_memory_integrity --yes --i-understand
    python -m mwga_cli apply iso.defender_exclusion_path --param path="D:\\ISOs" --yes --i-understand
    python -m mwga_cli revert ux.show_extensions --yes
    python -m mwga_cli run-profile gaming_safe --yes
    python -m mwga_cli run-profile gaming_aggressive --yes --i-understand --dry-run
    python -m mwga_cli verify-audit
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Optional

from mwga_catalog import (
    REGISTRY, RiskLevel, TweakState, is_windows_10, is_windows_11, windows_build,
)
from mwga_engine import (
    ApplyStatus, AuditLog, BackupStore, Decision, GovernedApplier,
    RestorePointGate, confirm_never, deny_all,
)
from mwga_profiles import PROFILE_REGISTRY, ProfileRunner


# --------------------------------------------------------------------------- #
#  Exit codes (CI-friendly)                                                    #
# --------------------------------------------------------------------------- #
EXIT_OK = 0
EXIT_ERROR = 1
EXIT_USAGE = 2          # argparse default
EXIT_DENIED = 3
EXIT_ABORTED = 4        # restore point / batch abort
EXIT_NOT_APPLICABLE = 5
EXIT_AUDIT_BROKEN = 6

_STATUS_EXIT = {
    ApplyStatus.APPLIED: EXIT_OK,
    ApplyStatus.DRY_RUN: EXIT_OK,
    ApplyStatus.ADVISORY: EXIT_OK,
    ApplyStatus.DENIED: EXIT_DENIED,
    ApplyStatus.ABORTED_RESTORE: EXIT_ABORTED,
    ApplyStatus.SKIPPED_NA: EXIT_NOT_APPLICABLE,
    ApplyStatus.ERROR: EXIT_ERROR,
}

MWGA_HOME = Path.home() / ".mwga"
AUDIT_PATH = MWGA_HOME / "audit.jsonl"


def _err(msg: str) -> None:
    print(f"error: {msg}", file=sys.stderr)


def _safe_state(tweak) -> TweakState:
    try:
        return tweak.detect()
    except Exception:  # noqa: BLE001 - wrong OS / access -> unknown
        return TweakState.UNKNOWN


def _build_applier(args) -> GovernedApplier:
    approver = (lambda r: Decision.APPROVE) if args.yes else deny_all
    confirm = (lambda r: True) if args.i_understand else confirm_never
    want_rp = not args.no_restore_point
    return GovernedApplier(
        REGISTRY,
        approver=approver,
        high_risk_confirm=confirm,
        backup_store=BackupStore(MWGA_HOME / "backups"),
        audit=AuditLog(AUDIT_PATH),
        restore_gate=RestorePointGate(enabled=want_rp),
        require_restore_point=want_rp,
        dry_run=args.dry_run,
    )


def _parse_params(pairs: Optional[list[str]]) -> dict[str, str]:
    out: dict[str, str] = {}
    for raw in pairs or []:
        if "=" not in raw:
            raise ValueError(f"--param must be key=value, got {raw!r}")
        k, v = raw.split("=", 1)
        out[k.strip()] = v
    return out


# --------------------------------------------------------------------------- #
#  Commands                                                                    #
# --------------------------------------------------------------------------- #
def cmd_env(args) -> int:
    b = windows_build()
    edition = "Windows 11" if is_windows_11() and b else \
              "Windows 10" if is_windows_10() else \
              "non-Windows / unknown"
    if args.json:
        print(json.dumps({"build": b, "edition": edition,
                          "win11": is_windows_11(), "win10": is_windows_10()}))
    else:
        print(f"host      : {edition}")
        print(f"build     : {b if b is not None else 'n/a'}")
        print(f"audit log : {AUDIT_PATH}")
        print(f"backups   : {MWGA_HOME / 'backups'}")
    return EXIT_OK


def cmd_list(args) -> int:
    if args.json:
        print(json.dumps([
            {"id": t.id, "name": t.name, "category": str(t.category),
             "risk": t.risk.value, "requires_reboot": t.requires_reboot,
             "requires_explorer_restart": t.requires_explorer_restart,
             "params": [p.key for p in t.params]}
            for t in REGISTRY
        ], indent=2))
        return EXIT_OK
    for cat in REGISTRY.categories():
        print(f"\n[{cat}]")
        for t in REGISTRY.by_category(cat):
            flags = []
            if t.requires_reboot:
                flags.append("reboot")
            if t.requires_explorer_restart:
                flags.append("explorer")
            if t.params:
                flags.append("param")
            tail = f"  ({', '.join(flags)})" if flags else ""
            print(f"  {t.risk.value.upper():6} {t.id:32} {t.name}{tail}")
    print()
    return EXIT_OK


def cmd_profiles(args) -> int:
    problems = PROFILE_REGISTRY.validate(REGISTRY)
    if problems:
        for p in problems:
            _err(p)
        return EXIT_ERROR
    if args.json:
        print(json.dumps([
            {"id": p.id, "name": p.name, "description": p.description,
             "tweaks": list(p.tweak_ids)} for p in PROFILE_REGISTRY
        ], indent=2))
        return EXIT_OK
    for p in PROFILE_REGISTRY:
        counts = {r: 0 for r in RiskLevel}
        for tid in p.tweak_ids:
            counts[REGISTRY.get(tid).risk] += 1
        chips = " ".join(f"{counts[r]}{r.value[0].upper()}"
                         for r in RiskLevel if counts[r])
        print(f"\n{p.id}  [{chips}]")
        print(f"  {p.name} — {p.description}")
        for tid in p.tweak_ids:
            print(f"    • {tid}")
    print()
    return EXIT_OK


def cmd_detect(args) -> int:
    ids = args.ids or [t.id for t in REGISTRY]
    rows = []
    for tid in ids:
        try:
            t = REGISTRY.get(tid)
        except KeyError:
            _err(f"unknown tweak: {tid}")
            return EXIT_ERROR
        rows.append((t, _safe_state(t)))
    if args.json:
        print(json.dumps([
            {"id": t.id, "state": s.value, "risk": t.risk.value,
             "category": str(t.category), "name": t.name}
            for t, s in rows
        ], indent=2))
        return EXIT_OK
    for t, s in rows:
        print(f"  {s.value:12} {t.risk.value.upper():6} {t.id:32} {t.name}")
    return EXIT_OK


def cmd_show(args) -> int:
    try:
        t = REGISTRY.get(args.id)
    except KeyError:
        _err(f"unknown tweak: {args.id}")
        return EXIT_ERROR
    print(f"{t.id}")
    print(f"  name       : {t.name}")
    print(f"  category   : {t.category}")
    print(f"  risk       : {t.risk.value.upper()}")
    print(f"  state      : {_safe_state(t).value}")
    print(f"  summary    : {t.summary}")
    print(f"  rationale  : {t.rationale}")
    if t.tradeoff:
        print(f"  tradeoff   : {t.tradeoff}")
    flags = []
    if t.requires_reboot:
        flags.append("reboot")
    if t.requires_explorer_restart:
        flags.append("Explorer restart")
    if flags:
        print(f"  finish     : {', '.join(flags)}")
    if t.params:
        print(f"  params     : {', '.join(p.key + ' (' + p.kind + ')' for p in t.params)}")
    print("  operations :")
    for op in t.operations:
        print(f"    - {op.describe()}")
    return EXIT_OK


def cmd_apply(args) -> int:
    try:
        params = _parse_params(args.param)
    except ValueError as exc:
        _err(str(exc))
        return EXIT_USAGE
    if args.id not in {t.id for t in REGISTRY}:
        _err(f"unknown tweak: {args.id}")
        return EXIT_ERROR
    tweak = REGISTRY.get(args.id)
    if tweak.advisory:
        print(f"[advisory] {tweak.name} — state: {_safe_state(tweak).value}")
        print(f"  {tweak.advice}")
        return EXIT_OK
    if not args.yes:
        print(f"[denied] apply needs --yes")
        if tweak.risk is RiskLevel.HIGH:
            print("  (HIGH-risk: also requires --i-understand)")
        return EXIT_DENIED

    applier = _build_applier(args)
    res = applier.apply(args.id, params or None)
    tail = f"  {res.before}->{res.after}" if res.after else ""
    print(f"[{res.status.value}] {res.tweak_id}{tail} — {res.message}")
    if res.status is ApplyStatus.DENIED and REGISTRY.get(args.id).risk is RiskLevel.HIGH \
            and not args.i_understand:
        print("  (HIGH-risk: re-run with --yes --i-understand to proceed)")
    if res.requires_reboot:
        print("  note: reboot to finish")
    if res.requires_explorer_restart:
        print("  note: Explorer restart to finish")
    return _STATUS_EXIT.get(res.status, EXIT_ERROR)


def cmd_revert(args) -> int:
    if args.id not in {t.id for t in REGISTRY}:
        _err(f"unknown tweak: {args.id}")
        return EXIT_ERROR
    if not args.yes:
        print("[denied] revert needs --yes")
        return EXIT_DENIED
    applier = _build_applier(args)
    res = applier.revert(args.id, backup_id=args.backup_id)
    print(f"[{res.status.value}] {res.tweak_id} — {res.message}")
    return _STATUS_EXIT.get(res.status, EXIT_ERROR)


def cmd_run_profile(args) -> int:
    try:
        profile = PROFILE_REGISTRY.get(args.id)
    except KeyError:
        _err(f"unknown profile: {args.id}")
        return EXIT_ERROR

    applier = _build_applier(args)
    runner = ProfileRunner(applier)

    plan = runner.preview(args.id)
    if not args.yes:
        print(f"[denied] run-profile needs --yes")
        return EXIT_DENIED
    # deny-first for HIGH: refuse the whole batch rather than partially apply
    if plan.needs_double_confirm and not args.i_understand:
        print(f"[denied] profile '{args.id}' contains HIGH-risk changes:")
        for it in plan.high_risk_items:
            print(f"    • {it.plan.name}: {it.plan.tradeoff}")
        print("  re-run with --yes --i-understand to proceed")
        return EXIT_DENIED

    def _emit(res):
        tail = f"  {res.before}->{res.after}" if res.after else ""
        print(f"  [{res.status.value}] {res.tweak_id}{tail} — {res.message}")

    print(f"running profile: {plan.name}")
    result = runner.run(args.id, on_result=_emit)
    if result.aborted:
        print(f"[aborted] restore point failed: {result.restore_point_reason}")
        return EXIT_ABORTED
    print(f"done — {result.applied} applied, {result.denied} denied, "
          f"{result.errored} errored")
    if result.requires_reboot:
        print("  note: reboot to finish")
    if result.requires_explorer_restart:
        print("  note: Explorer restart to finish")
    if result.errored:
        return EXIT_ERROR
    if result.applied == 0 and result.denied:
        return EXIT_DENIED
    return EXIT_OK


def cmd_verify_audit(args) -> int:
    audit = AuditLog(AUDIT_PATH)
    n = len(audit.entries())
    if not AUDIT_PATH.exists():
        print("no audit log yet")
        return EXIT_OK
    if audit.verify():
        print(f"audit chain verified — {n} entries intact ({AUDIT_PATH})")
        return EXIT_OK
    print(f"AUDIT CHAIN BROKEN — history tampered ({AUDIT_PATH})", file=sys.stderr)
    return EXIT_AUDIT_BROKEN


# --------------------------------------------------------------------------- #
#  Parser                                                                      #
# --------------------------------------------------------------------------- #
def _add_consent_flags(p: argparse.ArgumentParser) -> None:
    p.add_argument("-y", "--yes", action="store_true",
                   help="approve the change (without this, nothing applies)")
    p.add_argument("--i-understand", action="store_true",
                   help="acknowledge the security tradeoff for HIGH-risk changes")
    p.add_argument("--dry-run", action="store_true",
                   help="show what would change; write nothing")
    p.add_argument("--no-restore-point", action="store_true",
                   help="skip creating a System Restore point first")


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="mwga",
        description="Make Windows Great Again — governed tweak console (CLI).",
    )
    sub = p.add_subparsers(dest="command", required=True)

    s = sub.add_parser("env", help="show host / paths")
    s.add_argument("--json", action="store_true")
    s.set_defaults(func=cmd_env)

    s = sub.add_parser("list", help="list all tweaks")
    s.add_argument("--json", action="store_true")
    s.set_defaults(func=cmd_list)

    s = sub.add_parser("profiles", help="list profiles")
    s.add_argument("--json", action="store_true")
    s.set_defaults(func=cmd_profiles)

    s = sub.add_parser("detect", help="detect current state")
    s.add_argument("ids", nargs="*", help="tweak ids (default: all)")
    s.add_argument("--json", action="store_true")
    s.set_defaults(func=cmd_detect)

    s = sub.add_parser("show", help="show a tweak's details")
    s.add_argument("id")
    s.set_defaults(func=cmd_show)

    s = sub.add_parser("apply", help="apply a tweak")
    s.add_argument("id")
    s.add_argument("--param", action="append", metavar="KEY=VALUE",
                   help="parameter value (repeatable)")
    _add_consent_flags(s)
    s.set_defaults(func=cmd_apply)

    s = sub.add_parser("revert", help="revert a tweak from its backup")
    s.add_argument("id")
    s.add_argument("--backup-id", help="specific backup (default: latest)")
    _add_consent_flags(s)
    s.set_defaults(func=cmd_revert)

    s = sub.add_parser("run-profile", help="apply a named profile as one batch")
    s.add_argument("id")
    _add_consent_flags(s)
    s.set_defaults(func=cmd_run_profile)

    s = sub.add_parser("verify-audit", help="check the audit chain")
    s.set_defaults(func=cmd_verify_audit)

    return p


def main(argv: Optional[list[str]] = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    try:
        return args.func(args)
    except KeyboardInterrupt:
        return EXIT_ERROR
    except Exception as exc:  # noqa: BLE001 - clean CLI error, no traceback
        _err(str(exc))
        return EXIT_ERROR


if __name__ == "__main__":
    sys.exit(main())
