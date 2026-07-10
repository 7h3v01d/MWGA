"""
MWGA test suite.

OS-independent coverage runs everywhere via an in-memory Operation. A small
block of Windows-only tests exercises real winreg against a scratch HKCU key
(no admin, self-cleaning).

Run:  pytest -q test_mwga.py
"""

from __future__ import annotations

import dataclasses
import sys

import pytest

import mwga_catalog as cat
from mwga_catalog import (
    ABSENT,
    Category,
    OpState,
    ParamSpec,
    RiskLevel,
    Tweak,
    TweakRegistry,
    TweakState,
)
import mwga_engine as eng
from mwga_engine import (
    ApplyStatus,
    AuditLog,
    BackupStore,
    Decision,
    GovernedApplier,
    ParamError,
    RestorePointGate,
    RestorePointResult,
    bind_params,
    ps_single_quote_escape,
    validate_path_param,
)
from mwga_profiles import (
    Profile,
    ProfileRegistry,
    ProfileRunner,
    PROFILE_REGISTRY,
)

IS_WIN = sys.platform.startswith("win")


# --------------------------------------------------------------------------- #
#  In-memory operation + test fixtures                                         #
# --------------------------------------------------------------------------- #
@dataclasses.dataclass
class MemoryOp(cat.Operation):
    """Simulates a single value so engine tests run off-Windows."""

    key: str
    desired: str
    default: str
    _store: dict = dataclasses.field(default_factory=dict)
    kind: str = "memory"

    # Presence is defined solely by the store — construction has no side effects.
    def describe(self) -> str:
        return f"mem:{self.key} -> {self.desired}"

    def current_state(self) -> OpState:
        if self.key not in self._store:
            return OpState.ABSENT
        v = self._store[self.key]
        if v == self.desired:
            return OpState.DESIRED
        if v == self.default:
            return OpState.DEFAULT
        return OpState.OTHER

    def snapshot(self) -> dict:
        if self.key in self._store:
            return {"present": True, "value": self._store[self.key]}
        return {"present": False}

    def apply(self) -> None:
        self._store[self.key] = self.desired

    def restore(self, snapshot: dict) -> None:
        if snapshot.get("present"):
            self._store[self.key] = snapshot["value"]
        else:
            self._store.pop(self.key, None)

    def reset_default(self) -> None:
        self._store[self.key] = self.default


def make_tweak(risk=RiskLevel.LOW, store=None, applies=True, tid="test.mem",
               seed=True) -> Tweak:
    store = store if store is not None else {}
    if seed:
        store.setdefault("k", "off")  # value present at its default
    return Tweak(
        id=tid,
        name="Memory tweak",
        category=Category.PERFORMANCE,
        risk=risk,
        summary="flip a value",
        rationale="because",
        tradeoff="some cost" if risk is RiskLevel.HIGH else "",
        operations=[MemoryOp(key="k", desired="on", default="off", _store=store)],
        applies_when=(lambda: applies),
    )


@pytest.fixture
def approve_all():
    return lambda req: Decision.APPROVE


@pytest.fixture
def confirm_yes():
    return lambda req: True


@pytest.fixture
def applier_factory(tmp_path, approve_all, confirm_yes):
    def _make(tweak, **kw):
        reg = TweakRegistry([tweak])
        kw.setdefault("approver", approve_all)
        kw.setdefault("high_risk_confirm", confirm_yes)
        kw.setdefault("require_restore_point", False)
        return GovernedApplier(
            reg,
            backup_store=BackupStore(tmp_path / "backups"),
            audit=AuditLog(tmp_path / "audit.jsonl"),
            **kw,
        )
    return _make


# --------------------------------------------------------------------------- #
#  Catalog integrity                                                           #
# --------------------------------------------------------------------------- #
def test_catalog_has_no_duplicate_ids():
    ids = [t.id for t in cat.CATALOG]
    assert len(ids) == len(set(ids))


def test_catalog_validate_clean():
    assert cat.REGISTRY.validate() == []


def test_every_high_risk_has_tradeoff():
    for t in cat.CATALOG:
        if t.risk is RiskLevel.HIGH:
            assert t.tradeoff.strip(), f"{t.id} HIGH without tradeoff"


def test_all_tweaks_have_operations():
    for t in cat.CATALOG:
        assert t.operations, f"{t.id} has no operations"


def test_registry_lookup_and_filters():
    r = cat.REGISTRY
    assert r.get("game.gamedvr_disable").risk is RiskLevel.LOW
    assert all(t.risk is RiskLevel.HIGH for t in r.by_risk(RiskLevel.HIGH))
    assert r.by_category(Category.GAMING)
    assert r.by_tag("security")


def test_duplicate_id_registry_raises():
    t = make_tweak()
    with pytest.raises(ValueError):
        TweakRegistry([t, t])


# --------------------------------------------------------------------------- #
#  Detection aggregation                                                       #
# --------------------------------------------------------------------------- #
def test_detect_states():
    store = {}
    t = make_tweak(store=store)
    assert t.detect() is TweakState.NOT_APPLIED
    t.apply()
    assert t.detect() is TweakState.APPLIED


def test_detect_partial():
    store = {}
    op_on = MemoryOp(key="a", desired="on", default="off", _store=store)
    op_off = MemoryOp(key="b", desired="on", default="off", _store=store)
    t = dataclasses.replace(make_tweak(store=store), operations=[op_on, op_off])
    op_on.apply()
    assert t.detect() is TweakState.PARTIAL


def test_not_applicable():
    t = make_tweak(applies=False)
    assert t.detect() is TweakState.NOT_APPLICABLE


# --------------------------------------------------------------------------- #
#  Audit chain                                                                 #
# --------------------------------------------------------------------------- #
def test_audit_chain_verifies(tmp_path):
    log = AuditLog(tmp_path / "a.jsonl")
    log.append("applied", tweak_id="x")
    log.append("reverted", tweak_id="x")
    assert log.verify()
    assert len(log.entries()) == 2


def test_audit_tamper_detected(tmp_path):
    log = AuditLog(tmp_path / "a.jsonl")
    log.append("applied", tweak_id="x")
    log.append("applied", tweak_id="y")
    log._entries[0]["detail"]["tweak_id"] = "z"  # tamper
    assert not log.verify()


def test_audit_persists_and_reloads(tmp_path):
    p = tmp_path / "a.jsonl"
    log = AuditLog(p)
    log.append("applied", tweak_id="x")
    reloaded = AuditLog(p)
    assert reloaded.verify()
    assert reloaded.entries()[0]["detail"]["tweak_id"] == "x"


# --------------------------------------------------------------------------- #
#  Backup store                                                                #
# --------------------------------------------------------------------------- #
def test_backup_roundtrip(tmp_path):
    store = BackupStore(tmp_path)
    bid = store.save("t.id", {"0": {"present": True, "value": "off"}})
    rec = store.load(bid)
    assert rec.tweak_id == "t.id"
    assert rec.data["0"]["value"] == "off"
    assert store.latest("t.id").backup_id == bid


# --------------------------------------------------------------------------- #
#  Governance: deny-first                                                      #
# --------------------------------------------------------------------------- #
def test_default_applier_denies(tmp_path):
    store = {}
    t = make_tweak(store=store)
    app = GovernedApplier(
        TweakRegistry([t]),
        backup_store=BackupStore(tmp_path / "b"),
        audit=AuditLog(tmp_path / "a.jsonl"),
        require_restore_point=False,
    )  # no approver -> deny_all default
    res = app.apply(t.id)
    assert res.status is ApplyStatus.DENIED
    assert store["k"] == "off"  # unchanged


def test_approved_low_applies(applier_factory):
    store = {}
    t = make_tweak(store=store)
    app = applier_factory(t)
    res = app.apply(t.id)
    assert res.status is ApplyStatus.APPLIED
    assert store["k"] == "on"
    assert res.backup_id
    assert app.audit.verify()


def test_high_risk_requires_confirm(applier_factory):
    store = {}
    t = make_tweak(risk=RiskLevel.HIGH, store=store)
    app = applier_factory(t, high_risk_confirm=lambda r: False)  # approve but no confirm
    res = app.apply(t.id)
    assert res.status is ApplyStatus.DENIED
    assert "confirmation" in res.message
    assert store["k"] == "off"  # unchanged


def test_high_risk_confirmed_applies(applier_factory):
    store = {}
    t = make_tweak(risk=RiskLevel.HIGH, store=store)
    app = applier_factory(t)  # confirm_yes fixture
    assert app.apply(t.id).status is ApplyStatus.APPLIED
    assert store["k"] == "on"


def test_not_applicable_skipped(applier_factory):
    t = make_tweak(applies=False)
    assert applier_factory(t).apply(t.id).status is ApplyStatus.SKIPPED_NA


# --------------------------------------------------------------------------- #
#  Governance: restore-point gate                                             #
# --------------------------------------------------------------------------- #
class FailGate(RestorePointGate):
    def create(self, description):
        return RestorePointResult(ok=False, reason="simulated failure")


def test_restore_point_failure_aborts(tmp_path, approve_all, confirm_yes):
    store = {}
    t = make_tweak(store=store)
    app = GovernedApplier(
        TweakRegistry([t]),
        approver=approve_all, high_risk_confirm=confirm_yes,
        backup_store=BackupStore(tmp_path / "b"),
        audit=AuditLog(tmp_path / "a.jsonl"),
        restore_gate=FailGate(), require_restore_point=True,
    )
    res = app.apply(t.id)
    assert res.status is ApplyStatus.ABORTED_RESTORE
    assert store["k"] == "off"  # unchanged


# --------------------------------------------------------------------------- #
#  Governance: dry-run + revert                                               #
# --------------------------------------------------------------------------- #
def test_dry_run_writes_nothing_but_backs_up(applier_factory):
    store = {}
    t = make_tweak(store=store)
    app = applier_factory(t, dry_run=True)
    res = app.apply(t.id)
    assert res.status is ApplyStatus.DRY_RUN
    assert store["k"] == "off"  # unchanged
    assert res.backup_id  # backup still captured


def test_revert_restores_prior_state(applier_factory):
    store = {}
    t = make_tweak(store=store)
    app = applier_factory(t)
    app.apply(t.id)
    assert store["k"] == "on"
    res = app.revert(t.id)
    assert res.status is ApplyStatus.APPLIED
    assert store["k"] == "off"  # exact prior value restored
    assert app.audit.verify()


def test_revert_absent_value(applier_factory):
    store = {}  # value starts genuinely absent (no seed)
    op = MemoryOp(key="k", desired="on", default="off", _store=store)
    t = dataclasses.replace(make_tweak(store=store, seed=False), operations=[op])
    app = applier_factory(t)
    app.apply(t.id)
    assert store["k"] == "on"
    app.revert(t.id)
    assert "k" not in store  # restored to absent, not to default


def test_revert_no_backup(applier_factory):
    t = make_tweak()
    assert applier_factory(t).revert(t.id).status is ApplyStatus.ERROR


# --------------------------------------------------------------------------- #
#  Param binding / path_guard / escaping                                      #
# --------------------------------------------------------------------------- #
def test_ps_escape_doubles_quotes():
    assert ps_single_quote_escape("O'Brien") == "O''Brien"


def test_path_guard_rejects_metachars(tmp_path):
    with pytest.raises(ParamError):
        validate_path_param(str(tmp_path) + "; rm -rf", must_exist=False)


def test_path_guard_rejects_newline():
    with pytest.raises(ParamError):
        validate_path_param("C:\\x\ny", must_exist=False)


def test_path_guard_rejects_relative():
    with pytest.raises(ParamError):
        validate_path_param("relative\\path", must_exist=False)


def test_path_guard_requires_existence(tmp_path):
    with pytest.raises(ParamError):
        validate_path_param(str(tmp_path / "nope"), must_exist=True)
    assert validate_path_param(str(tmp_path), must_exist=True)


def test_bind_substitutes_command_op(tmp_path):
    t = cat.REGISTRY.get("iso.defender_exclusion_path")
    bound = bind_params(t, {"path": str(tmp_path)}, must_exist=True)
    op = bound.operations[0]
    joined = " ".join(op.apply_cmd)
    assert "{path}" not in joined
    assert str(tmp_path) in joined
    # original catalog object untouched
    assert "{path}" in " ".join(t.operations[0].apply_cmd)


def test_bind_escapes_quote_in_path(tmp_path):
    d = tmp_path / "O'Dir"
    d.mkdir()
    bound = bind_params(
        cat.REGISTRY.get("iso.defender_exclusion_path"),
        {"path": str(d)}, must_exist=True,
    )
    joined = " ".join(bound.operations[0].apply_cmd)
    assert "O''Dir" in joined  # single quote doubled for PS


def test_bind_missing_required_param():
    with pytest.raises(ParamError):
        bind_params(cat.REGISTRY.get("iso.defender_exclusion_path"), {})


def test_bind_rejects_unexpected_param():
    with pytest.raises(ParamError):
        bind_params(make_tweak(), {"nope": "x"})


def test_preview_reports_state(applier_factory):
    store = {}
    t = make_tweak(risk=RiskLevel.HIGH, store=store)
    plan = applier_factory(t).preview(t.id)
    assert plan.current_state is TweakState.NOT_APPLIED
    assert plan.needs_double_confirm is True
    assert plan.tradeoff


# --------------------------------------------------------------------------- #
#  OS-version applicability gating                                            #
# --------------------------------------------------------------------------- #
def test_classic_menu_gated_off_on_win10(monkeypatch):
    monkeypatch.setattr(cat, "is_windows_11", lambda: False)
    t = cat.REGISTRY.get("ux.classic_context_menu")
    assert t.is_applicable() is False
    assert t.detect() is TweakState.NOT_APPLICABLE


def test_classic_menu_applicable_on_win11(monkeypatch):
    monkeypatch.setattr(cat, "is_windows_11", lambda: True)
    t = cat.REGISTRY.get("ux.classic_context_menu")
    assert t.is_applicable() is True


def test_win11_build_threshold(monkeypatch):
    monkeypatch.setattr(cat, "windows_build", lambda: 22631)
    assert cat.is_windows_11()
    monkeypatch.setattr(cat, "windows_build", lambda: 19045)
    assert not cat.is_windows_11()
    assert cat.is_windows_10()
    monkeypatch.setattr(cat, "windows_build", lambda: None)
    assert cat.is_windows_11()      # unknown host -> don't hide
    assert not cat.is_windows_10()


# --------------------------------------------------------------------------- #
#  Profiles: integrity                                                        #
# --------------------------------------------------------------------------- #
def test_profile_registry_validates_against_catalog():
    assert PROFILE_REGISTRY.validate(cat.REGISTRY) == []


def test_profile_no_duplicate_ids():
    ids = [p.id for p in PROFILE_REGISTRY]
    assert len(ids) == len(set(ids))


def test_profile_unknown_tweak_detected():
    bad = ProfileRegistry([Profile("x", "X", "d", ("nope.tweak",))])
    assert bad.validate(cat.REGISTRY)


# --------------------------------------------------------------------------- #
#  Profiles: batch runner (in-memory)                                         #
# --------------------------------------------------------------------------- #
class CountingGate(RestorePointGate):
    def __init__(self):
        super().__init__(enabled=True)
        self.calls = 0

    def create(self, description):
        self.calls += 1
        return RestorePointResult(ok=True)


def _batch_registry(store):
    tweaks = []
    for i in range(3):
        op = MemoryOp(key=f"k{i}", desired="on", default="off", _store=store)
        store[f"k{i}"] = "off"
        tweaks.append(dataclasses.replace(
            make_tweak(store=store, seed=False, tid=f"t{i}"), operations=[op]))
    return TweakRegistry(tweaks)


def _runner(store, tmp_path, gate=None, **kw):
    reg = _batch_registry(store)
    app = GovernedApplier(
        reg, approver=lambda r: Decision.APPROVE,
        high_risk_confirm=lambda r: True,
        backup_store=BackupStore(tmp_path / "b"),
        audit=AuditLog(tmp_path / "a.jsonl"),
        restore_gate=gate or CountingGate(),
        require_restore_point=True, **kw,
    )
    profiles = ProfileRegistry([Profile("p", "P", "d", ("t0", "t1", "t2"))])
    return ProfileRunner(app, profiles), app


def test_batch_applies_all(tmp_path):
    store = {}
    runner, app = _runner(store, tmp_path)
    res = runner.run("p")
    assert res.applied == 3
    assert all(store[f"k{i}"] == "on" for i in range(3))
    assert app.audit.verify()


def test_batch_uses_single_restore_point(tmp_path):
    store = {}
    gate = CountingGate()
    runner, _ = _runner(store, tmp_path, gate=gate)
    runner.run("p")
    assert gate.calls == 1  # one checkpoint for the whole batch, not per-tweak


def test_batch_aborts_on_restore_failure(tmp_path):
    store = {}
    runner, _ = _runner(store, tmp_path, gate=FailGate())
    res = runner.run("p")
    assert res.aborted
    assert res.results == []
    assert all(store[f"k{i}"] == "off" for i in range(3))  # nothing applied


def test_batch_dry_run_skips_restore_and_changes(tmp_path):
    store = {}
    gate = CountingGate()
    runner, app = _runner(store, tmp_path, gate=gate, dry_run=True)
    res = runner.run("p")
    assert gate.calls == 0                       # no checkpoint in dry-run
    assert all(store[f"k{i}"] == "off" for i in range(3))
    assert all(r.status is ApplyStatus.DRY_RUN for r in res.results)


def test_batch_restore_point_flag_restored_after_run(tmp_path):
    store = {}
    runner, app = _runner(store, tmp_path)
    assert app.require_restore_point is True
    runner.run("p")
    assert app.require_restore_point is True     # flag restored post-batch


def test_batch_preview_reports_aggregate(tmp_path):
    store = {}
    runner, _ = _runner(store, tmp_path)
    plan = runner.preview("p")
    assert len(plan.items) == 3
    assert len(plan.to_change) == 3
    assert plan.already_applied == []


# --------------------------------------------------------------------------- #
#  AppCompatLayersOp — token merge semantics (no real registry)               #
# --------------------------------------------------------------------------- #
class FakeLayers:
    """Stand-in for the Layers registry value, injected into an op subclass."""
    def __init__(self, initial=None):
        self.value = initial  # None == absent


def _appcompat_op(store: FakeLayers, add, remove=()):
    from mwga_catalog import AppCompatLayersOp

    class _Op(AppCompatLayersOp):
        def _read(self):
            return store.value

        def _write(self, value):
            store.value = value

        def _delete(self):
            store.value = None

    return _Op(exe_path="C:\\game.exe", add=tuple(add), remove=tuple(remove))


def test_appcompat_adds_token_preserving_others():
    store = FakeLayers("~ HIGHDPIAWARE")
    op = _appcompat_op(store, add=["RUNASADMIN"])
    op.apply()
    toks = store.value.split()
    assert "RUNASADMIN" in toks and "HIGHDPIAWARE" in toks and toks[0] == "~"


def test_appcompat_from_absent_adds_marker():
    store = FakeLayers(None)
    op = _appcompat_op(store, add=["RUNASADMIN"])
    assert op.current_state() is OpState.ABSENT
    op.apply()
    assert store.value.split() == ["~", "RUNASADMIN"]
    assert op.current_state() is OpState.DESIRED


def test_appcompat_mode_is_mutually_exclusive():
    store = FakeLayers("~ WIN7RTM")
    op = _appcompat_op(store, add=["WIN8RTM"])
    op.apply()
    toks = store.value.split()
    assert "WIN8RTM" in toks and "WIN7RTM" not in toks  # mode swap, not stack


def test_appcompat_restore_exact_prior():
    store = FakeLayers("~ HIGHDPIAWARE")
    op = _appcompat_op(store, add=["RUNASADMIN"])
    snap = op.snapshot()
    op.apply()
    op.restore(snap)
    assert store.value == "~ HIGHDPIAWARE"  # untouched other token preserved


def test_appcompat_restore_to_absent():
    store = FakeLayers(None)
    op = _appcompat_op(store, add=["RUNASADMIN"])
    snap = op.snapshot()
    op.apply()
    op.restore(snap)
    assert store.value is None


def test_appcompat_bind_substitutes_exe():
    t = cat.REGISTRY.get("compat.run_as_admin")
    bound = bind_params(t, {"exe": "/tmp"}, must_exist=True)
    assert bound.operations[0].exe_path == "/tmp"
    assert t.operations[0].exe_path == "{exe}"  # original untouched


# --------------------------------------------------------------------------- #
#  Advisory (report-only) tweaks                                              #
# --------------------------------------------------------------------------- #
def test_advisory_apply_never_writes(applier_factory):
    store = {"k": "off"}
    t = dataclasses.replace(make_tweak(store=store), advisory=True,
                            advice="do it in Settings", id="adv.x")
    res = applier_factory(t).apply("adv.x")
    assert res.status is ApplyStatus.ADVISORY
    assert store["k"] == "off"          # engine did not write
    assert "Settings" in res.message


def test_advisory_revert_noop(applier_factory):
    store = {"k": "off"}
    t = dataclasses.replace(make_tweak(store=store), advisory=True, id="adv.y")
    app = applier_factory(t)
    app.backups.save("adv.y", {"0": {"present": True, "value": "off"}})
    res = app.revert("adv.y")
    assert res.status is ApplyStatus.ADVISORY


def test_sac_status_is_advisory():
    t = cat.REGISTRY.get("compat.smart_app_control_status")
    assert t.advisory and t.advice


# --------------------------------------------------------------------------- #
#  Windows-only: real registry round-trip (scratch HKCU, no admin)            #
# --------------------------------------------------------------------------- #
@pytest.mark.skipif(not IS_WIN, reason="registry tests require Windows")
class TestRealRegistry:
    SCRATCH = "Software\\MWGA\\_pytest_scratch"

    def _tweak(self):
        from mwga_catalog import RegistryOp, RegType
        return Tweak(
            id="test.reg", name="scratch", category=Category.EXPLORER,
            risk=RiskLevel.LOW, summary="s", rationale="r", tradeoff="",
            operations=[RegistryOp("HKCU", self.SCRATCH, "Flag",
                                   RegType.DWORD, 1, 0, create_key=True)],
        )

    def _cleanup(self):
        import winreg
        try:
            winreg.DeleteKey(winreg.HKEY_CURRENT_USER, self.SCRATCH)
        except FileNotFoundError:
            pass

    def test_apply_detect_revert(self, tmp_path):
        self._cleanup()
        try:
            t = self._tweak()
            app = GovernedApplier(
                TweakRegistry([t]),
                approver=lambda r: Decision.APPROVE,
                backup_store=BackupStore(tmp_path / "b"),
                audit=AuditLog(tmp_path / "a.jsonl"),
                require_restore_point=False,
            )
            assert t.detect() in (TweakState.NOT_APPLIED, TweakState.UNKNOWN)
            assert app.apply(t.id).status is ApplyStatus.APPLIED
            assert t.detect() is TweakState.APPLIED
            assert app.revert(t.id).status is ApplyStatus.APPLIED
            assert t.detect() is TweakState.NOT_APPLIED
            assert app.audit.verify()
        finally:
            self._cleanup()


if __name__ == "__main__":
    sys.exit(pytest.main([__file__, "-q"]))
