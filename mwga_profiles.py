"""
MWGA — Make Windows Great Again
Profiles layer: named batches of tweaks applied through one governed sweep.

Author : Leon Priest / 7h3v01d
License : Apache 2.0

A profile is declarative data — a name and an ordered set of tweak ids. The
ProfileRunner drives them through the existing GovernedApplier, with one
important difference from applying tweaks one at a time: the whole batch shares
a SINGLE restore point (creating one per tweak would be wasteful and hits
Windows' ~24h checkpoint rate limit anyway). If that one checkpoint fails and
restore points are required, the entire batch aborts before anything is written
— deny-first, at batch scope.

Like the engine, run() assumes consent: the caller (GUI/CLI) shows the
BatchPlan and only calls run() once the user has approved. Each individual
apply still flows through the applier's own approval + audit path.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Callable, Optional

from mwga_catalog import RiskLevel, TweakRegistry, TweakState
from mwga_engine import ApplyResult, ApplyStatus, GovernedApplier, Plan


# --------------------------------------------------------------------------- #
#  Profile definition + registry                                              #
# --------------------------------------------------------------------------- #
@dataclass(frozen=True)
class Profile:
    id: str
    name: str
    description: str
    tweak_ids: tuple[str, ...]
    tags: tuple[str, ...] = ()


PROFILES: list[Profile] = [
    Profile(
        id="gaming_safe",
        name="Gaming — safe",
        description="Frame-pacing and capture-overhead wins with no security "
                    "downgrade. Good default before touching anything HIGH.",
        tweak_ids=(
            "game.gamedvr_disable",
            "game.fso_disable_global",
            "game.mpo_disable",
            "perf.ultimate_power_plan",
        ),
        tags=("gaming",),
    ),
    Profile(
        id="gaming_aggressive",
        name="Gaming — aggressive",
        description="Everything in the safe profile plus the isolation "
                    "features that cost frame-time. Includes HIGH-risk items "
                    "that lower security posture — read each tradeoff.",
        tweak_ids=(
            "game.gamedvr_disable",
            "game.fso_disable_global",
            "game.mpo_disable",
            "perf.ultimate_power_plan",
            "game.hags",
            "sec.hvci_memory_integrity",
        ),
        tags=("gaming", "aggressive"),
    ),
    Profile(
        id="privacy",
        name="Privacy & telemetry",
        description="Cut background telemetry and per-user tracking. No "
                    "security downgrade; a couple of Store-app niceties pause.",
        tweak_ids=(
            "tel.diagtrack",
            "tel.allow_telemetry",
            "tel.advertising_id",
            "ux.background_apps",
        ),
        tags=("privacy",),
    ),
    Profile(
        id="responsiveness",
        name="Snappy desktop",
        description="Trim the delays and animations Win11 layered onto routine "
                    "interaction. All reversible cosmetics.",
        tweak_ids=(
            "ux.visual_effects_perf",
            "ux.startup_delay",
            "ux.classic_context_menu",
            "iso.icons_only",
            "ux.show_extensions",
        ),
        tags=("ux",),
    ),
    Profile(
        id="ssd_services",
        name="SSD service trim",
        description="Disable prefetch and search indexing. Sensible on an "
                    "all-SSD rig; leave these ON if you run spinning disks.",
        tweak_ids=(
            "tel.sysmain",
            "tel.wsearch",
        ),
        tags=("performance", "ssd"),
    ),
]


class ProfileRegistry:
    def __init__(self, profiles: list[Profile]):
        self._by_id: dict[str, Profile] = {}
        for p in profiles:
            if p.id in self._by_id:
                raise ValueError(f"duplicate profile id: {p.id}")
            self._by_id[p.id] = p
        self._profiles = list(profiles)

    def __iter__(self):
        return iter(self._profiles)

    def __len__(self) -> int:
        return len(self._profiles)

    def get(self, profile_id: str) -> Profile:
        return self._by_id[profile_id]

    def all(self) -> list[Profile]:
        return list(self._profiles)

    def validate(self, tweaks: TweakRegistry) -> list[str]:
        """Every referenced tweak id must exist in the tweak registry."""
        known = {t.id for t in tweaks}
        problems: list[str] = []
        for p in self._profiles:
            if not p.tweak_ids:
                problems.append(f"{p.id}: empty profile")
            for tid in p.tweak_ids:
                if tid not in known:
                    problems.append(f"{p.id}: unknown tweak '{tid}'")
        return problems


PROFILE_REGISTRY = ProfileRegistry(PROFILES)


# --------------------------------------------------------------------------- #
#  Plans + results                                                            #
# --------------------------------------------------------------------------- #
@dataclass
class BatchItem:
    tweak_id: str
    plan: Plan


@dataclass
class BatchPlan:
    profile_id: str
    name: str
    description: str
    items: list[BatchItem]

    @property
    def risk_counts(self) -> dict[RiskLevel, int]:
        counts = {r: 0 for r in RiskLevel}
        for it in self.items:
            counts[it.plan.risk] += 1
        return counts

    @property
    def high_risk_items(self) -> list[BatchItem]:
        return [it for it in self.items if it.plan.risk is RiskLevel.HIGH]

    @property
    def needs_double_confirm(self) -> bool:
        return bool(self.high_risk_items)

    @property
    def requires_reboot(self) -> bool:
        return any(it.plan.requires_reboot for it in self.items)

    @property
    def requires_explorer_restart(self) -> bool:
        return any(it.plan.requires_explorer_restart for it in self.items)

    @property
    def to_change(self) -> list[BatchItem]:
        return [it for it in self.items
                if it.plan.current_state is not TweakState.APPLIED
                and it.plan.current_state is not TweakState.NOT_APPLICABLE]

    @property
    def already_applied(self) -> list[BatchItem]:
        return [it for it in self.items
                if it.plan.current_state is TweakState.APPLIED]


@dataclass
class BatchResult:
    profile_id: str
    results: list[ApplyResult]
    restore_point_ok: bool = True
    restore_point_reason: str = ""
    aborted: bool = False

    @property
    def applied(self) -> int:
        return sum(r.status is ApplyStatus.APPLIED for r in self.results)

    @property
    def denied(self) -> int:
        return sum(r.status is ApplyStatus.DENIED for r in self.results)

    @property
    def errored(self) -> int:
        return sum(r.status is ApplyStatus.ERROR for r in self.results)

    @property
    def requires_reboot(self) -> bool:
        return any(r.requires_reboot for r in self.results)

    @property
    def requires_explorer_restart(self) -> bool:
        return any(r.requires_explorer_restart for r in self.results)


# --------------------------------------------------------------------------- #
#  Runner                                                                     #
# --------------------------------------------------------------------------- #
ResultCallback = Callable[[ApplyResult], None]


class ProfileRunner:
    def __init__(self, applier: GovernedApplier,
                 profiles: ProfileRegistry = PROFILE_REGISTRY):
        self.applier = applier
        self.profiles = profiles

    def preview(self, profile_id: str,
                param_map: Optional[dict[str, dict]] = None) -> BatchPlan:
        profile = self.profiles.get(profile_id)
        param_map = param_map or {}
        items = [
            BatchItem(tid, self.applier.preview(tid, param_map.get(tid)))
            for tid in profile.tweak_ids
        ]
        return BatchPlan(profile.id, profile.name, profile.description, items)

    def run(self, profile_id: str,
            param_map: Optional[dict[str, dict]] = None,
            on_result: Optional[ResultCallback] = None) -> BatchResult:
        profile = self.profiles.get(profile_id)
        param_map = param_map or {}
        audit = self.applier.audit
        audit.append("profile_run_start", profile_id=profile_id,
                     tweaks=list(profile.tweak_ids))

        # one restore point for the whole batch
        rp_ok, rp_reason = True, ""
        if self.applier.require_restore_point and not self.applier.dry_run:
            rp = self.applier.restore_gate.create(f"MWGA profile {profile_id}")
            rp_ok, rp_reason = rp.ok, rp.reason
            if not rp.ok:
                audit.append("profile_aborted_restore_point",
                            profile_id=profile_id, reason=rp.reason)
                return BatchResult(profile_id, [], restore_point_ok=False,
                                   restore_point_reason=rp.reason, aborted=True)

        # suppress per-tweak checkpoints for the batch; restore afterwards
        gate_was = self.applier.require_restore_point
        self.applier.require_restore_point = False
        results: list[ApplyResult] = []
        try:
            for tid in profile.tweak_ids:
                res = self.applier.apply(tid, param_map.get(tid))
                results.append(res)
                if on_result:
                    on_result(res)
        finally:
            self.applier.require_restore_point = gate_was

        result = BatchResult(profile_id, results,
                             restore_point_ok=rp_ok, restore_point_reason=rp_reason)
        audit.append("profile_run_complete", profile_id=profile_id,
                     applied=result.applied, denied=result.denied,
                     errored=result.errored)
        return result


__all__ = [
    "Profile", "PROFILES", "ProfileRegistry", "PROFILE_REGISTRY",
    "BatchItem", "BatchPlan", "BatchResult", "ProfileRunner",
]
