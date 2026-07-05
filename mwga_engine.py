"""
MWGA — Make Windows Great Again
Engine layer: governed application of catalog tweaks.

Author : Leon Priest / 7h3v01d
License : Apache 2.0

Pipeline (deny-first, ordered — any gate can veto):

    resolve tweak
      -> applicability check          (skip if N/A for this machine)
      -> bind + validate params       (path_guard + PowerShell escaping)
      -> approval                     (default: DENY)
      -> high-risk confirm            (HIGH only; default: DENY)
      -> restore-point gate           (abort batch on failure, unless waived)
      -> backup                       (exact prior state, persisted)
      -> apply                        (skipped when dry_run)
      -> post-detect + audit

Every stage writes a chain-hashed audit entry. Backups are data, so revert is
an exact undo. Nothing about a HIGH-risk change is hidden: the tradeoff string
rides through the approval request.
"""

from __future__ import annotations

import dataclasses
import hashlib
import json
import os
import re
import subprocess
import time
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
from typing import Any, Callable, Optional

from mwga_catalog import (
    ABSENT,
    CommandOp,
    Operation,
    ParamSpec,
    RegistryOp,
    RiskLevel,
    Tweak,
    TweakRegistry,
    TweakState,
)


# --------------------------------------------------------------------------- #
#  Errors                                                                      #
# --------------------------------------------------------------------------- #
class ParamError(ValueError):
    """A param value failed validation / binding."""


class GovernanceError(RuntimeError):
    """A governed operation could not proceed for a policy reason."""


# --------------------------------------------------------------------------- #
#  Approval model (deny-first)                                                 #
# --------------------------------------------------------------------------- #
class Decision(Enum):
    APPROVE = "approve"
    DENY = "deny"


@dataclass(frozen=True)
class ApprovalRequest:
    tweak_id: str
    name: str
    risk: RiskLevel
    summary: str
    tradeoff: str
    requires_reboot: bool
    requires_explorer_restart: bool
    operation_previews: tuple[str, ...]
    current_state: TweakState

    @property
    def needs_double_confirm(self) -> bool:
        return self.risk is RiskLevel.HIGH


Approver = Callable[[ApprovalRequest], Decision]
HighRiskConfirm = Callable[[ApprovalRequest], bool]


def deny_all(_req: ApprovalRequest) -> Decision:
    """Default approver: deny-first."""
    return Decision.DENY


def confirm_never(_req: ApprovalRequest) -> bool:
    """Default high-risk confirm: deny-first."""
    return False


# --------------------------------------------------------------------------- #
#  Param binding — path_guard + PowerShell escaping                           #
# --------------------------------------------------------------------------- #
_BAD_PATH_CHARS = ("\r", "\n", "\x00")
# Reject characters that let a value break out of a PS token / add operators.
_PS_METACHARS = re.compile(r"[`$;&|<>]")


def ps_single_quote_escape(value: str) -> str:
    """Make `value` safe to embed inside a PowerShell single-quoted string."""
    return value.replace("'", "''")


def validate_path_param(value: str, *, must_exist: bool = True) -> str:
    """
    path_guard: reject anything that isn't a plain, absolute filesystem path.
    Defender exclusions in particular must never be built from an unvalidated
    string that reaches PowerShell.
    """
    if not value or not value.strip():
        raise ParamError("empty path")
    if any(c in value for c in _BAD_PATH_CHARS):
        raise ParamError("path contains control characters")
    if _PS_METACHARS.search(value):
        raise ParamError("path contains shell metacharacters")
    p = Path(value)
    if not p.is_absolute():
        raise ParamError(f"path must be absolute: {value!r}")
    if must_exist and not p.exists():
        raise ParamError(f"path does not exist: {value!r}")
    return os.path.normpath(str(p))


def _validate(spec: ParamSpec, raw: str, *, must_exist: bool) -> str:
    if spec.kind == "path":
        return validate_path_param(raw, must_exist=must_exist)
    if spec.kind == "text":
        if any(c in raw for c in _BAD_PATH_CHARS) or _PS_METACHARS.search(raw):
            raise ParamError("text contains disallowed characters")
        return raw
    raise ParamError(f"unknown param kind: {spec.kind}")


def _sub(template: str, key: str, value: str) -> str:
    return template.replace("{" + key + "}", value)


def _bind_command_op(op: CommandOp, key: str, raw: str, escaped: str) -> CommandOp:
    # Command lists reach PowerShell -> use the escaped value.
    # Match strings (desired/default signal) are compared against tool output
    # -> use the raw value.
    return CommandOp(
        detect_cmd=[_sub(t, key, escaped) for t in op.detect_cmd],
        desired_signal=_sub(op.desired_signal, key, raw),
        apply_cmd=[_sub(t, key, escaped) for t in op.apply_cmd],
        revert_cmd=[_sub(t, key, escaped) for t in op.revert_cmd],
        default_signal=(
            _sub(op.default_signal, key, raw) if op.default_signal else None
        ),
        shell_note=op.shell_note,
    )


def _bind_registry_op(op: RegistryOp, key: str, raw: str) -> RegistryOp:
    def s(v: Any) -> Any:
        return _sub(v, key, raw) if isinstance(v, str) else v

    return dataclasses.replace(
        op, path=s(op.path), name=s(op.name), desired=s(op.desired),
        default=(op.default if op.default is ABSENT else s(op.default)),
    )


def bind_params(
    tweak: Tweak,
    values: Optional[dict[str, str]] = None,
    *,
    must_exist: bool = True,
) -> Tweak:
    """
    Return a resolved copy of `tweak` with every {param} substituted and
    validated. The source catalog object is never mutated.
    """
    values = values or {}
    if not tweak.params:
        if values:
            raise ParamError(f"{tweak.id}: no params accepted")
        return tweak

    clean: dict[str, str] = {}
    for spec in tweak.params:
        if spec.key not in values:
            if spec.required:
                raise ParamError(f"{tweak.id}: missing required param '{spec.key}'")
            continue
        clean[spec.key] = _validate(spec, values[spec.key], must_exist=must_exist)

    ops: list[Operation] = []
    for op in tweak.operations:
        new_op = op
        for key, raw in clean.items():
            if isinstance(new_op, CommandOp):
                new_op = _bind_command_op(new_op, key, raw, ps_single_quote_escape(raw))
            elif isinstance(new_op, RegistryOp):
                new_op = _bind_registry_op(new_op, key, raw)
        ops.append(new_op)

    return dataclasses.replace(tweak, operations=ops)


# --------------------------------------------------------------------------- #
#  Chain-hashed audit log                                                      #
# --------------------------------------------------------------------------- #
_GENESIS = "0" * 64


def _canonical(payload: dict) -> str:
    return json.dumps(payload, sort_keys=True, separators=(",", ":"))


def _hash_entry(payload: dict, prev_hash: str) -> str:
    return hashlib.sha256((_canonical(payload) + prev_hash).encode("utf-8")).hexdigest()


class AuditLog:
    """
    Append-only, tamper-evident log. Each entry's hash chains the previous
    entry's hash, so any edit to history breaks verification downstream.
    """

    def __init__(self, path: Optional[str | Path] = None):
        self.path = Path(path) if path else None
        self._entries: list[dict] = []
        if self.path and self.path.exists():
            self._load()

    def _load(self) -> None:
        with self.path.open("r", encoding="utf-8") as fh:
            for line in fh:
                line = line.strip()
                if line:
                    self._entries.append(json.loads(line))

    @property
    def head(self) -> str:
        return self._entries[-1]["entry_hash"] if self._entries else _GENESIS

    def append(self, event: str, **detail: Any) -> dict:
        payload = {
            "seq": len(self._entries),
            "ts": time.time(),
            "event": event,
            "detail": detail,
        }
        prev = self.head
        entry = {**payload, "prev_hash": prev, "entry_hash": _hash_entry(payload, prev)}
        self._entries.append(entry)
        if self.path:
            self.path.parent.mkdir(parents=True, exist_ok=True)
            with self.path.open("a", encoding="utf-8") as fh:
                fh.write(json.dumps(entry) + "\n")
        return entry

    def entries(self) -> list[dict]:
        return list(self._entries)

    def verify(self) -> bool:
        prev = _GENESIS
        for e in self._entries:
            payload = {k: e[k] for k in ("seq", "ts", "event", "detail")}
            if e["prev_hash"] != prev:
                return False
            if e["entry_hash"] != _hash_entry(payload, prev):
                return False
            prev = e["entry_hash"]
        return True


# --------------------------------------------------------------------------- #
#  Backup store                                                                #
# --------------------------------------------------------------------------- #
@dataclass
class BackupRecord:
    backup_id: str
    tweak_id: str
    ts: float
    data: dict


class BackupStore:
    """Persists per-tweak backups so revert survives a restart."""

    def __init__(self, base_dir: Optional[str | Path] = None):
        self.base = Path(base_dir) if base_dir else Path.home() / ".mwga" / "backups"

    def save(self, tweak_id: str, data: dict) -> str:
        self.base.mkdir(parents=True, exist_ok=True)
        backup_id = f"{tweak_id}.{time.time_ns()}"
        rec = BackupRecord(backup_id, tweak_id, time.time(), data)
        (self.base / f"{backup_id}.json").write_text(
            json.dumps(dataclasses.asdict(rec), indent=2), encoding="utf-8"
        )
        return backup_id

    def load(self, backup_id: str) -> BackupRecord:
        raw = json.loads((self.base / f"{backup_id}.json").read_text("utf-8"))
        return BackupRecord(**raw)

    def list_for(self, tweak_id: str) -> list[BackupRecord]:
        out: list[BackupRecord] = []
        if not self.base.exists():
            return out
        for f in self.base.glob(f"{tweak_id}.*.json"):
            out.append(BackupRecord(**json.loads(f.read_text("utf-8"))))
        return sorted(out, key=lambda r: r.ts)

    def latest(self, tweak_id: str) -> Optional[BackupRecord]:
        recs = self.list_for(tweak_id)
        return recs[-1] if recs else None


# --------------------------------------------------------------------------- #
#  Restore-point gate                                                          #
# --------------------------------------------------------------------------- #
@dataclass
class RestorePointResult:
    ok: bool
    reason: str = ""


class RestorePointGate:
    """
    Creates a System Restore checkpoint before a batch of changes.

    Notes: requires admin + System Protection enabled on the system drive, and
    Windows rate-limits checkpoints (default one per 24h). A skipped/rate-limited
    checkpoint still returns ok=True — the point is best-effort safety netting,
    not a guarantee. Off-Windows this is a no-op that reports ok=False.
    """

    def __init__(self, enabled: bool = True):
        self.enabled = enabled

    def create(self, description: str) -> RestorePointResult:
        if not self.enabled:
            return RestorePointResult(ok=True, reason="gate disabled")
        try:
            r = subprocess.run(
                ["powershell", "-NoProfile", "-Command",
                 f"Checkpoint-Computer -Description '{ps_single_quote_escape(description)}' "
                 "-RestorePointType 'MODIFY_SETTINGS'"],
                capture_output=True, text=True, timeout=180, check=False,
            )
        except (OSError, subprocess.SubprocessError) as exc:
            return RestorePointResult(ok=False, reason=str(exc))
        if r.returncode == 0:
            return RestorePointResult(ok=True)
        return RestorePointResult(ok=False, reason=(r.stderr or r.stdout).strip())


# --------------------------------------------------------------------------- #
#  Results                                                                     #
# --------------------------------------------------------------------------- #
class ApplyStatus(Enum):
    APPLIED = "applied"
    DENIED = "denied"
    SKIPPED_NA = "skipped_not_applicable"
    ABORTED_RESTORE = "aborted_restore_point"
    DRY_RUN = "dry_run"
    ERROR = "error"


@dataclass
class ApplyResult:
    status: ApplyStatus
    tweak_id: str
    message: str = ""
    backup_id: Optional[str] = None
    before: Optional[TweakState] = None
    after: Optional[TweakState] = None
    requires_reboot: bool = False
    requires_explorer_restart: bool = False


@dataclass
class Plan:
    tweak_id: str
    name: str
    risk: RiskLevel
    current_state: TweakState
    tradeoff: str
    requires_reboot: bool
    requires_explorer_restart: bool
    operation_previews: tuple[str, ...]
    needs_double_confirm: bool


# --------------------------------------------------------------------------- #
#  Governed applier                                                            #
# --------------------------------------------------------------------------- #
class GovernedApplier:
    def __init__(
        self,
        registry: TweakRegistry,
        *,
        approver: Approver = deny_all,
        high_risk_confirm: HighRiskConfirm = confirm_never,
        backup_store: Optional[BackupStore] = None,
        audit: Optional[AuditLog] = None,
        restore_gate: Optional[RestorePointGate] = None,
        require_restore_point: bool = True,
        dry_run: bool = False,
        param_must_exist: bool = True,
    ):
        self.registry = registry
        self.approver = approver
        self.high_risk_confirm = high_risk_confirm
        self.backups = backup_store or BackupStore()
        self.audit = audit or AuditLog()
        self.restore_gate = restore_gate or RestorePointGate(enabled=require_restore_point)
        self.require_restore_point = require_restore_point
        self.dry_run = dry_run
        self.param_must_exist = param_must_exist

    # -- helpers ------------------------------------------------------------ #
    def _resolve(self, tweak_id: str, params: Optional[dict[str, str]]) -> Tweak:
        base = self.registry.get(tweak_id)
        return bind_params(base, params, must_exist=self.param_must_exist)

    def _request(self, tweak: Tweak, state: TweakState) -> ApprovalRequest:
        return ApprovalRequest(
            tweak_id=tweak.id,
            name=tweak.name,
            risk=tweak.risk,
            summary=tweak.summary,
            tradeoff=tweak.tradeoff,
            requires_reboot=tweak.requires_reboot,
            requires_explorer_restart=tweak.requires_explorer_restart,
            operation_previews=tuple(op.describe() for op in tweak.operations),
            current_state=state,
        )

    def preview(self, tweak_id: str, params: Optional[dict[str, str]] = None) -> Plan:
        tweak = self._resolve(tweak_id, params)
        try:
            state = tweak.detect()
        except Exception:  # noqa: BLE001 - preview must never crash the caller
            state = TweakState.UNKNOWN
        return Plan(
            tweak_id=tweak.id, name=tweak.name, risk=tweak.risk,
            current_state=state, tradeoff=tweak.tradeoff,
            requires_reboot=tweak.requires_reboot,
            requires_explorer_restart=tweak.requires_explorer_restart,
            operation_previews=tuple(op.describe() for op in tweak.operations),
            needs_double_confirm=tweak.risk is RiskLevel.HIGH,
        )

    # -- apply -------------------------------------------------------------- #
    def apply(self, tweak_id: str, params: Optional[dict[str, str]] = None) -> ApplyResult:
        try:
            tweak = self._resolve(tweak_id, params)
        except ParamError as exc:
            self.audit.append("param_rejected", tweak_id=tweak_id, error=str(exc))
            return ApplyResult(ApplyStatus.ERROR, tweak_id, message=str(exc))

        # applicability
        if not tweak.is_applicable():
            self.audit.append("skipped_not_applicable", tweak_id=tweak_id)
            return ApplyResult(ApplyStatus.SKIPPED_NA, tweak_id,
                               message="not applicable to this machine")

        before = tweak.detect()
        req = self._request(tweak, before)

        # approval (deny-first)
        if self.approver(req) is not Decision.APPROVE:
            self.audit.append("denied", tweak_id=tweak_id, risk=str(tweak.risk),
                              stage="approval")
            return ApplyResult(ApplyStatus.DENIED, tweak_id, before=before,
                               message="denied at approval")

        # high-risk confirm (deny-first)
        if req.needs_double_confirm and not self.high_risk_confirm(req):
            self.audit.append("denied", tweak_id=tweak_id, risk=str(tweak.risk),
                              stage="high_risk_confirm")
            return ApplyResult(ApplyStatus.DENIED, tweak_id, before=before,
                               message="high-risk confirmation withheld")

        # restore-point gate
        if self.require_restore_point and not self.dry_run:
            rp = self.restore_gate.create(f"MWGA {tweak.id}")
            if not rp.ok:
                self.audit.append("aborted_restore_point", tweak_id=tweak_id,
                                  reason=rp.reason)
                return ApplyResult(ApplyStatus.ABORTED_RESTORE, tweak_id,
                                   before=before,
                                   message=f"restore point failed: {rp.reason}")

        # backup (always, even in dry-run — cheap insurance / audit trail)
        backup_data = tweak.backup()
        backup_id = self.backups.save(tweak.id, backup_data)

        if self.dry_run:
            self.audit.append("dry_run", tweak_id=tweak_id, backup_id=backup_id,
                              before=str(before))
            return ApplyResult(ApplyStatus.DRY_RUN, tweak_id, backup_id=backup_id,
                               before=before, after=before,
                               requires_reboot=tweak.requires_reboot,
                               requires_explorer_restart=tweak.requires_explorer_restart,
                               message="dry run — no changes written")

        # apply
        try:
            tweak.apply()
        except Exception as exc:  # noqa: BLE001 - surface + audit, then revert-safe
            self.audit.append("apply_error", tweak_id=tweak_id, backup_id=backup_id,
                              error=str(exc))
            return ApplyResult(ApplyStatus.ERROR, tweak_id, backup_id=backup_id,
                               before=before, message=str(exc))

        after = tweak.detect()
        self.audit.append("applied", tweak_id=tweak_id, backup_id=backup_id,
                          risk=str(tweak.risk), before=str(before), after=str(after))
        return ApplyResult(
            ApplyStatus.APPLIED, tweak_id, backup_id=backup_id,
            before=before, after=after,
            requires_reboot=tweak.requires_reboot,
            requires_explorer_restart=tweak.requires_explorer_restart,
            message="applied",
        )

    # -- revert ------------------------------------------------------------- #
    def revert(
        self,
        tweak_id: str,
        backup_id: Optional[str] = None,
        params: Optional[dict[str, str]] = None,
    ) -> ApplyResult:
        rec = self.backups.load(backup_id) if backup_id else self.backups.latest(tweak_id)
        if rec is None:
            self.audit.append("revert_no_backup", tweak_id=tweak_id)
            return ApplyResult(ApplyStatus.ERROR, tweak_id,
                               message="no backup found")
        tweak = self._resolve(tweak_id, params)
        try:
            tweak.revert(rec.data)
        except Exception as exc:  # noqa: BLE001
            self.audit.append("revert_error", tweak_id=tweak_id,
                              backup_id=rec.backup_id, error=str(exc))
            return ApplyResult(ApplyStatus.ERROR, tweak_id, backup_id=rec.backup_id,
                               message=str(exc))
        after = tweak.detect()
        self.audit.append("reverted", tweak_id=tweak_id, backup_id=rec.backup_id,
                          after=str(after))
        return ApplyResult(ApplyStatus.APPLIED, tweak_id, backup_id=rec.backup_id,
                           after=after, message="reverted")


__all__ = [
    "Decision", "ApprovalRequest", "Approver", "HighRiskConfirm",
    "deny_all", "confirm_never",
    "ParamError", "GovernanceError",
    "ps_single_quote_escape", "validate_path_param", "bind_params",
    "AuditLog", "BackupStore", "BackupRecord",
    "RestorePointGate", "RestorePointResult",
    "ApplyStatus", "ApplyResult", "Plan", "GovernedApplier",
]
