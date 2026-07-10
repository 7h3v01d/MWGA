"""
MWGA — Make Windows Great Again
UI layer: governed tweak console (PyQt6).

Author : Leon Priest / 7h3v01d
License : Apache 2.0

The panel is the approver. Consent is gathered by a dialog on the UI thread
(deny-first: Cancel is default; HIGH-risk keeps Apply disabled until the
tradeoff is acknowledged). Only after the dialog accepts does a QThread worker
call engine.apply() — so the engine's approver seam is satisfied by explicit,
informed user consent rather than a rubber stamp.

Threading: detection, apply and revert all run off the UI thread via QThread
subclasses. Live worker references are held in `_worker_refs` to prevent the
classic PyQt GC-mid-run crash on Windows. All slots are @pyqtSlot-decorated.
"""

from __future__ import annotations

import subprocess
import sys
from typing import Optional

from PyQt6.QtCore import Qt, QThread, pyqtSignal, pyqtSlot
from PyQt6.QtGui import QFont, QFontDatabase
from PyQt6.QtWidgets import (
    QApplication, QCheckBox, QDialog, QDialogButtonBox, QFileDialog, QFrame,
    QHBoxLayout, QLabel, QMainWindow, QMessageBox, QPlainTextEdit, QPushButton,
    QScrollArea, QSizePolicy, QTabWidget, QVBoxLayout, QWidget,
)

from mwga_catalog import Category, RiskLevel, TweakState, REGISTRY
from mwga_engine import (
    ApplyResult, ApplyStatus, AuditLog, BackupStore, Decision, GovernedApplier,
    ParamError, Plan, RestorePointGate, bind_params,
)
from mwga_profiles import (
    BatchPlan, BatchResult, Profile, ProfileRunner, PROFILE_REGISTRY,
)


# --------------------------------------------------------------------------- #
#  Theme — Leon Priest / 7h3v01d dark-industrial tokens                       #
# --------------------------------------------------------------------------- #
BG        = "#0b0f14"   # obsidian
PANEL     = "#11161d"
SURFACE   = "#161c24"
SURFACE_2 = "#1b232d"
BORDER    = "#232c37"
TEXT      = "#d7dee7"
TEXT_DIM  = "#7c8794"
TEAL      = "#2fd6c3"   # primary accent
AMBER     = "#ffb454"   # warning / medium / partial
RED       = "#ff5c66"   # danger / high
PHOSPHOR  = "#4be08a"   # applied / success
MONO      = "JetBrains Mono, Consolas, Menlo, monospace"

RISK_COLOR = {RiskLevel.LOW: TEAL, RiskLevel.MEDIUM: AMBER, RiskLevel.HIGH: RED}
STATE_COLOR = {
    TweakState.APPLIED: PHOSPHOR,
    TweakState.NOT_APPLIED: TEXT_DIM,
    TweakState.PARTIAL: AMBER,
    TweakState.UNKNOWN: TEXT_DIM,
    TweakState.NOT_APPLICABLE: BORDER,
}
STATE_LABEL = {
    TweakState.APPLIED: "APPLIED",
    TweakState.NOT_APPLIED: "not applied",
    TweakState.PARTIAL: "PARTIAL",
    TweakState.UNKNOWN: "unknown",
    TweakState.NOT_APPLICABLE: "n/a",
}

STYLE = f"""
* {{ font-family: {MONO}; color: {TEXT}; }}
QMainWindow, QWidget#root {{ background: {BG}; }}
QLabel#title {{ font-size: 18px; font-weight: 700; color: {TEAL};
                letter-spacing: 1px; }}
QLabel#subtitle {{ color: {TEXT_DIM}; font-size: 11px; }}
QTabWidget::pane {{ border: 1px solid {BORDER}; background: {PANEL}; }}
QTabBar::tab {{ background: {SURFACE}; color: {TEXT_DIM};
    padding: 8px 14px; border: 1px solid {BORDER}; border-bottom: none;
    margin-right: 2px; font-size: 11px; }}
QTabBar::tab:selected {{ background: {PANEL}; color: {TEAL};
    border-top: 2px solid {TEAL}; }}
QScrollArea {{ border: none; background: {PANEL}; }}
QScrollArea > QWidget {{ background: {PANEL}; }}
QWidget#page {{ background: {PANEL}; }}
QFrame#row {{ background: {SURFACE}; border: 1px solid {BORDER}; }}
QFrame#row[high="true"] {{ border-left: 3px solid {RED}; }}
QLabel.rowName {{ font-size: 13px; font-weight: 600; }}
QLabel.rowSummary {{ color: {TEXT_DIM}; font-size: 11px; }}
QPushButton {{ background: {SURFACE_2}; color: {TEXT}; border: 1px solid {BORDER};
    padding: 6px 14px; border-radius: 0px; font-size: 11px; font-weight: 600; }}
QPushButton:hover {{ border-color: {TEAL}; color: {TEAL}; }}
QPushButton:disabled {{ color: {BORDER}; border-color: {BORDER}; }}
QPushButton#apply:hover {{ border-color: {PHOSPHOR}; color: {PHOSPHOR}; }}
QPushButton#danger:hover {{ border-color: {RED}; color: {RED}; }}
QPushButton#primary {{ background: {TEAL}; color: {BG}; border: none; }}
QPushButton#primary:disabled {{ background: {BORDER}; color: {TEXT_DIM}; }}
QCheckBox {{ color: {TEXT_DIM}; font-size: 11px; spacing: 8px; }}
QCheckBox::indicator {{ width: 14px; height: 14px; border: 1px solid {BORDER};
    background: {SURFACE}; }}
QCheckBox::indicator:checked {{ background: {TEAL}; border-color: {TEAL}; }}
QPlainTextEdit#log {{ background: {BG}; border: 1px solid {BORDER};
    font-size: 11px; }}
QFrame#banner {{ background: {SURFACE_2}; border: 1px solid {AMBER}; }}
QLabel#bannerText {{ color: {AMBER}; font-size: 11px; }}
QDialog {{ background: {PANEL}; }}
"""


def _badge(text: str, color: str) -> QLabel:
    lbl = QLabel(text)
    lbl.setStyleSheet(
        f"color:{color}; border:1px solid {color}; padding:2px 8px;"
        f"font-size:10px; font-weight:700; letter-spacing:0.5px;"
    )
    lbl.setAlignment(Qt.AlignmentFlag.AlignCenter)
    lbl.setSizePolicy(QSizePolicy.Policy.Fixed, QSizePolicy.Policy.Fixed)
    return lbl


# --------------------------------------------------------------------------- #
#  Workers (QThread subclass — Windows-reliable per Leon's convention)        #
# --------------------------------------------------------------------------- #
class DetectWorker(QThread):
    detected = pyqtSignal(str, object)   # tweak_id, TweakState
    done = pyqtSignal()

    def __init__(self, registry):
        super().__init__()
        self._registry = registry

    def run(self) -> None:
        for tweak in self._registry:
            try:
                state = tweak.detect()
            except Exception:  # noqa: BLE001 - off-Windows / access -> unknown
                state = TweakState.UNKNOWN
            self.detected.emit(tweak.id, state)
        self.done.emit()


class ApplyWorker(QThread):
    result = pyqtSignal(object)          # ApplyResult

    def __init__(self, applier: GovernedApplier, tweak_id: str,
                 params: Optional[dict]):
        super().__init__()
        self._applier = applier
        self._tweak_id = tweak_id
        self._params = params

    def run(self) -> None:
        self.result.emit(self._applier.apply(self._tweak_id, self._params))


class RevertWorker(QThread):
    result = pyqtSignal(object)

    def __init__(self, applier: GovernedApplier, tweak_id: str,
                 params: Optional[dict]):
        super().__init__()
        self._applier = applier
        self._tweak_id = tweak_id
        self._params = params

    def run(self) -> None:
        self.result.emit(self._applier.revert(self._tweak_id, params=self._params))


class BatchWorker(QThread):
    item_result = pyqtSignal(object)     # ApplyResult per tweak
    done = pyqtSignal(object)            # BatchResult

    def __init__(self, runner: ProfileRunner, profile_id: str):
        super().__init__()
        self._runner = runner
        self._profile_id = profile_id

    def run(self) -> None:
        result = self._runner.run(self._profile_id, on_result=self.item_result.emit)
        self.done.emit(result)


# --------------------------------------------------------------------------- #
#  Batch approval dialog                                                       #
# --------------------------------------------------------------------------- #
class BatchApprovalDialog(QDialog):
    def __init__(self, plan: BatchPlan, parent=None):
        super().__init__(parent)
        self.setWindowTitle(f"Run profile — {plan.name}")
        self.setMinimumWidth(520)
        v = QVBoxLayout(self)
        v.setContentsMargins(20, 20, 20, 16)
        v.setSpacing(10)

        name = QLabel(plan.name)
        name.setStyleSheet(f"font-size:15px; font-weight:700; color:{TEAL};")
        v.addWidget(name)
        desc = QLabel(plan.description)
        desc.setStyleSheet(f"color:{TEXT_DIM}; font-size:11px;")
        desc.setWordWrap(True)
        v.addWidget(desc)

        counts = plan.risk_counts
        chips = QHBoxLayout()
        chips.setSpacing(6)
        for risk in (RiskLevel.LOW, RiskLevel.MEDIUM, RiskLevel.HIGH):
            if counts[risk]:
                chips.addWidget(_badge(f"{counts[risk]} {risk.value.upper()}",
                                       RISK_COLOR[risk]))
        chips.addStretch(1)
        v.addLayout(chips)

        lines = []
        for it in plan.items:
            mark = {TweakState.APPLIED: "✓ ", TweakState.NOT_APPLICABLE: "– "}.get(
                it.plan.current_state, "")
            lines.append(f"  {mark}{it.plan.name}  [{it.plan.risk.value}]")
        body = QLabel("Will apply:\n" + "\n".join(lines))
        body.setStyleSheet(f"color:{TEXT}; font-size:11px;")
        body.setWordWrap(True)
        v.addWidget(body)

        flags = []
        if plan.requires_reboot:
            flags.append("reboot to finish")
        if plan.requires_explorer_restart:
            flags.append("Explorer restart to finish")
        if flags:
            f = QLabel("Note: " + ", ".join(flags))
            f.setStyleSheet(f"color:{AMBER}; font-size:11px;")
            v.addWidget(f)

        self._ack: Optional[QCheckBox] = None
        if plan.needs_double_confirm:
            trs = "\n".join(f"  • {it.plan.name}: {it.plan.tradeoff}"
                            for it in plan.high_risk_items)
            warn = QLabel(f"This profile includes HIGH-risk changes:\n{trs}")
            warn.setStyleSheet(f"color:{RED}; font-size:11px;")
            warn.setWordWrap(True)
            v.addWidget(warn)
            self._ack = QCheckBox("I understand these lower my security posture.")
            self._ack.stateChanged.connect(self._sync)
            v.addWidget(self._ack)

        bb = QDialogButtonBox()
        self._ok = QPushButton("Run profile")
        self._ok.setObjectName("primary")
        cancel = QPushButton("Cancel")
        bb.addButton(self._ok, QDialogButtonBox.ButtonRole.AcceptRole)
        bb.addButton(cancel, QDialogButtonBox.ButtonRole.RejectRole)
        bb.accepted.connect(self.accept)
        bb.rejected.connect(self.reject)
        cancel.setDefault(True)
        v.addWidget(bb)
        self._sync()

    @pyqtSlot()
    def _sync(self) -> None:
        self._ok.setEnabled(self._ack is None or self._ack.isChecked())


# --------------------------------------------------------------------------- #
#  Profile card + page                                                         #
# --------------------------------------------------------------------------- #
class ProfileCard(QFrame):
    run_requested = pyqtSignal(str)

    def __init__(self, profile: Profile, registry, parent=None):
        super().__init__(parent)
        self.setObjectName("row")
        has_high = any(registry.get(t).risk is RiskLevel.HIGH
                       for t in profile.tweak_ids)
        self.setProperty("high", "true" if has_high else "false")

        outer = QHBoxLayout(self)
        outer.setContentsMargins(12, 10, 12, 10)
        outer.setSpacing(12)

        left = QVBoxLayout()
        left.setSpacing(3)
        name = QLabel(profile.name)
        name.setStyleSheet("font-size:13px; font-weight:600;")
        desc = QLabel(profile.description)
        desc.setStyleSheet(f"color:{TEXT_DIM}; font-size:11px;")
        desc.setWordWrap(True)
        left.addWidget(name)
        left.addWidget(desc)
        # risk chips
        chips = QHBoxLayout()
        chips.setSpacing(6)
        counts = {r: 0 for r in RiskLevel}
        for tid in profile.tweak_ids:
            counts[registry.get(tid).risk] += 1
        for risk in (RiskLevel.LOW, RiskLevel.MEDIUM, RiskLevel.HIGH):
            if counts[risk]:
                chips.addWidget(_badge(f"{counts[risk]} {risk.value.upper()}",
                                       RISK_COLOR[risk]))
        chips.addStretch(1)
        left.addLayout(chips)
        outer.addLayout(left, 1)

        run = QPushButton("Run profile")
        run.setObjectName("apply")
        run.clicked.connect(lambda: self.run_requested.emit(profile.id))
        run.setEnabled(bool(profile.tweak_ids))
        outer.addWidget(run, 0, Qt.AlignmentFlag.AlignTop)


class ProfilesPage(QScrollArea):
    run_requested = pyqtSignal(str)

    def __init__(self, registry, profiles=PROFILE_REGISTRY, parent=None):
        super().__init__(parent)
        self.setWidgetResizable(True)
        inner = QWidget()
        inner.setObjectName("page")
        lay = QVBoxLayout(inner)
        lay.setContentsMargins(8, 8, 8, 8)
        lay.setSpacing(8)
        intro = QLabel("Apply a curated set in one governed sweep — a single "
                       "restore point, then each change through the normal "
                       "audit path.")
        intro.setStyleSheet(f"color:{TEXT_DIM}; font-size:11px;")
        intro.setWordWrap(True)
        lay.addWidget(intro)
        for profile in profiles:
            card = ProfileCard(profile, registry)
            card.run_requested.connect(self.run_requested)
            lay.addWidget(card)
        lay.addStretch(1)
        self.setWidget(inner)


# --------------------------------------------------------------------------- #
#  Approval dialog — where informed consent is gathered                        #
# --------------------------------------------------------------------------- #
class ApprovalDialog(QDialog):
    def __init__(self, plan: Plan, parent=None):
        super().__init__(parent)
        self.setWindowTitle("Confirm change")
        self.setMinimumWidth(460)
        v = QVBoxLayout(self)
        v.setContentsMargins(20, 20, 20, 16)
        v.setSpacing(10)

        head = QHBoxLayout()
        name = QLabel(plan.name)
        name.setStyleSheet("font-size:14px; font-weight:700;")
        head.addWidget(name, 1)
        head.addWidget(_badge(plan.risk.value.upper(), RISK_COLOR[plan.risk]))
        v.addLayout(head)

        state = QLabel(f"Current state: {STATE_LABEL[plan.current_state]}")
        state.setStyleSheet(f"color:{TEXT_DIM}; font-size:11px;")
        v.addWidget(state)

        ops = QLabel("Changes:\n" + "\n".join(f"  • {o}" for o in plan.operation_previews))
        ops.setStyleSheet(f"color:{TEXT}; font-size:11px;")
        ops.setWordWrap(True)
        v.addWidget(ops)

        flags = []
        if plan.requires_reboot:
            flags.append("reboot to finish")
        if plan.requires_explorer_restart:
            flags.append("Explorer restart to finish")
        if flags:
            f = QLabel("Note: " + ", ".join(flags))
            f.setStyleSheet(f"color:{AMBER}; font-size:11px;")
            v.addWidget(f)

        self._ack: Optional[QCheckBox] = None
        if plan.needs_double_confirm:
            tr = QLabel(f"Tradeoff: {plan.tradeoff}")
            tr.setStyleSheet(f"color:{RED}; font-size:11px;")
            tr.setWordWrap(True)
            v.addWidget(tr)
            self._ack = QCheckBox("I understand this lowers my security posture.")
            self._ack.stateChanged.connect(self._sync)
            v.addWidget(self._ack)

        bb = QDialogButtonBox()
        self._ok = QPushButton("Apply")
        self._ok.setObjectName("primary")
        cancel = QPushButton("Cancel")
        bb.addButton(self._ok, QDialogButtonBox.ButtonRole.AcceptRole)
        bb.addButton(cancel, QDialogButtonBox.ButtonRole.RejectRole)
        bb.accepted.connect(self.accept)
        bb.rejected.connect(self.reject)
        cancel.setDefault(True)   # deny-first: Cancel is the default action
        v.addWidget(bb)
        self._sync()

    @pyqtSlot()
    def _sync(self) -> None:
        self._ok.setEnabled(self._ack is None or self._ack.isChecked())


# --------------------------------------------------------------------------- #
#  Tweak row                                                                   #
# --------------------------------------------------------------------------- #
class TweakRow(QFrame):
    apply_requested = pyqtSignal(str)
    revert_requested = pyqtSignal(str)

    def __init__(self, tweak, parent=None):
        super().__init__(parent)
        self.tweak = tweak
        self.setObjectName("row")
        self.setProperty("high", "true" if tweak.risk is RiskLevel.HIGH else "false")

        outer = QHBoxLayout(self)
        outer.setContentsMargins(12, 10, 12, 10)
        outer.setSpacing(12)

        left = QVBoxLayout()
        left.setSpacing(3)
        name = QLabel(tweak.name)
        name.setProperty("class", "rowName")
        name.setStyleSheet("font-size:13px; font-weight:600;")
        summary = QLabel(tweak.summary)
        summary.setStyleSheet(f"color:{TEXT_DIM}; font-size:11px;")
        summary.setWordWrap(True)
        left.addWidget(name)
        left.addWidget(summary)
        outer.addLayout(left, 1)

        self.risk_badge = _badge(tweak.risk.value.upper(), RISK_COLOR[tweak.risk])
        outer.addWidget(self.risk_badge)

        self.state_badge = _badge("…", TEXT_DIM)
        self.state_badge.setMinimumWidth(90)
        outer.addWidget(self.state_badge)

        self.apply_btn = QPushButton("Info" if tweak.advisory else "Apply")
        self.apply_btn.setObjectName("apply")
        self.apply_btn.clicked.connect(lambda: self.apply_requested.emit(tweak.id))
        outer.addWidget(self.apply_btn)

        self.revert_btn = QPushButton("Revert")
        self.revert_btn.setObjectName("danger")
        self.revert_btn.clicked.connect(lambda: self.revert_requested.emit(tweak.id))
        outer.addWidget(self.revert_btn)
        if tweak.advisory:
            self.revert_btn.hide()

    def set_state(self, state: TweakState) -> None:
        self.state_badge.setText(STATE_LABEL[state])
        color = STATE_COLOR[state]
        self.state_badge.setStyleSheet(
            f"color:{color}; border:1px solid {color}; padding:2px 8px;"
            f"font-size:10px; font-weight:700;"
        )
        if self.tweak.advisory:
            return  # Info button always available; no revert
        na = state is TweakState.NOT_APPLICABLE
        self.apply_btn.setEnabled(not na)
        self.revert_btn.setEnabled(not na)

    def set_busy(self, busy: bool) -> None:
        self.apply_btn.setEnabled(not busy)
        self.revert_btn.setEnabled(not busy)


# --------------------------------------------------------------------------- #
#  Main panel                                                                  #
# --------------------------------------------------------------------------- #
class MWGAPanel(QWidget):
    def __init__(self, registry=REGISTRY, applier: Optional[GovernedApplier] = None):
        super().__init__()
        self.setObjectName("root")
        self.registry = registry
        self.applier = applier or GovernedApplier(
            registry,
            approver=lambda r: Decision.APPROVE,      # consent gathered by dialog
            high_risk_confirm=lambda r: True,         # ditto (dialog gates HIGH)
            backup_store=BackupStore(),
            audit=AuditLog(),
            restore_gate=RestorePointGate(enabled=True),
            require_restore_point=True,
        )
        self._worker_refs: set[QThread] = set()
        self._rows: dict[str, TweakRow] = {}
        self._pending_reboot: set[str] = set()
        self._pending_explorer: set[str] = set()
        self.runner = ProfileRunner(self.applier)
        self._build()
        self.refresh()

    # -- construction ------------------------------------------------------- #
    def _build(self) -> None:
        root = QVBoxLayout(self)
        root.setContentsMargins(16, 16, 16, 16)
        root.setSpacing(12)

        # header
        header = QHBoxLayout()
        titles = QVBoxLayout()
        titles.setSpacing(2)
        t = QLabel("MWGA")
        t.setObjectName("title")
        s = QLabel("Make Windows Great Again — governed tweak console")
        s.setObjectName("subtitle")
        titles.addWidget(t)
        titles.addWidget(s)
        header.addLayout(titles, 1)

        self.restore_cb = QCheckBox("Restore point first")
        self.restore_cb.setChecked(True)
        self.dry_cb = QCheckBox("Dry run")
        header.addWidget(self.restore_cb)
        header.addWidget(self.dry_cb)

        self.refresh_btn = QPushButton("Detect all")
        self.refresh_btn.clicked.connect(self.refresh)
        self.verify_btn = QPushButton("Verify audit")
        self.verify_btn.clicked.connect(self._verify_audit)
        header.addWidget(self.refresh_btn)
        header.addWidget(self.verify_btn)
        root.addLayout(header)

        # pending-actions banner (hidden until something is pending)
        self.banner = QFrame()
        self.banner.setObjectName("banner")
        bl = QHBoxLayout(self.banner)
        bl.setContentsMargins(12, 8, 12, 8)
        self.banner_text = QLabel("")
        self.banner_text.setObjectName("bannerText")
        bl.addWidget(self.banner_text, 1)
        self.explorer_btn = QPushButton("Restart Explorer")
        self.explorer_btn.clicked.connect(self._restart_explorer)
        bl.addWidget(self.explorer_btn)
        self.banner.hide()
        root.addWidget(self.banner)

        # category tabs (Profiles first)
        self.tabs = QTabWidget()
        profiles_page = ProfilesPage(self.registry)
        profiles_page.run_requested.connect(self._on_run_profile)
        self.tabs.addTab(profiles_page, "Profiles")
        for cat in self.registry.categories():
            self.tabs.addTab(self._category_page(cat), str(cat))
        root.addWidget(self.tabs, 1)

        # log
        self.log = QPlainTextEdit()
        self.log.setObjectName("log")
        self.log.setReadOnly(True)
        self.log.setFixedHeight(150)
        self.log.setFont(QFont("JetBrains Mono", 9))
        root.addWidget(self.log)

        self.setStyleSheet(STYLE)
        self._log("ready", TEAL)

    def _category_page(self, category: Category) -> QScrollArea:
        area = QScrollArea()
        area.setWidgetResizable(True)
        inner = QWidget()
        inner.setObjectName("page")
        lay = QVBoxLayout(inner)
        lay.setContentsMargins(8, 8, 8, 8)
        lay.setSpacing(8)
        for tweak in self.registry.by_category(category):
            row = TweakRow(tweak)
            row.apply_requested.connect(self._on_apply)
            row.revert_requested.connect(self._on_revert)
            self._rows[tweak.id] = row
            lay.addWidget(row)
        lay.addStretch(1)
        area.setWidget(inner)
        return area

    # -- detection ---------------------------------------------------------- #
    @pyqtSlot()
    def refresh(self) -> None:
        self.refresh_btn.setEnabled(False)
        self._log("detecting current state…", TEXT_DIM)
        w = DetectWorker(self.registry)
        w.detected.connect(self._on_detected)
        w.done.connect(self._on_detect_done)
        self._launch(w)

    @pyqtSlot(str, object)
    def _on_detected(self, tweak_id: str, state: TweakState) -> None:
        row = self._rows.get(tweak_id)
        if row:
            row.set_state(state)

    @pyqtSlot()
    def _on_detect_done(self) -> None:
        self.refresh_btn.setEnabled(True)
        self._log("detection complete", TEAL)

    # -- apply / revert ----------------------------------------------------- #
    @pyqtSlot(str)
    def _on_apply(self, tweak_id: str) -> None:
        tweak = self.registry.get(tweak_id)
        if tweak.advisory:
            QMessageBox.information(self, tweak.name, tweak.advice)
            return
        params = self._collect_params(tweak)
        if params is None and tweak.params:
            return  # cancelled at param prompt
        try:
            plan = self.applier.preview(tweak_id, params)
        except ParamError as exc:
            self._log(f"param error: {exc}", RED)
            QMessageBox.warning(self, "Invalid input", str(exc))
            return

        dlg = ApprovalDialog(plan, self)
        if dlg.exec() != QDialog.DialogCode.Accepted:
            self._log(f"denied {tweak_id} (cancelled)", TEXT_DIM)
            return

        self.applier.dry_run = self.dry_cb.isChecked()
        self.applier.require_restore_point = self.restore_cb.isChecked()
        self.applier.restore_gate.enabled = self.restore_cb.isChecked()

        self._set_busy(tweak_id, True)
        w = ApplyWorker(self.applier, tweak_id, params)
        w.result.connect(self._on_result)
        self._launch(w)

    @pyqtSlot(str)
    def _on_revert(self, tweak_id: str) -> None:
        tweak = self.registry.get(tweak_id)
        params = self._collect_params(tweak) if tweak.params else None
        if tweak.params and params is None:
            return
        if QMessageBox.question(
            self, "Revert", f"Restore the previous state for:\n{tweak.name}?"
        ) != QMessageBox.StandardButton.Yes:
            return
        self._set_busy(tweak_id, True)
        w = RevertWorker(self.applier, tweak_id, params)
        w.result.connect(self._on_result)
        self._launch(w)

    @pyqtSlot(object)
    def _on_result(self, res: ApplyResult) -> None:
        self._set_busy(res.tweak_id, False)
        color = {
            ApplyStatus.APPLIED: PHOSPHOR,
            ApplyStatus.DRY_RUN: TEAL,
            ApplyStatus.ADVISORY: TEAL,
            ApplyStatus.DENIED: TEXT_DIM,
            ApplyStatus.SKIPPED_NA: TEXT_DIM,
            ApplyStatus.ABORTED_RESTORE: AMBER,
            ApplyStatus.ERROR: RED,
        }.get(res.status, TEXT)
        tail = f"  {res.before}→{res.after}" if res.after else ""
        self._log(f"[{res.status.value}] {res.tweak_id}{tail} — {res.message}", color)

        if res.status is ApplyStatus.APPLIED:
            if res.requires_reboot:
                self._pending_reboot.add(res.tweak_id)
            if res.requires_explorer_restart:
                self._pending_explorer.add(res.tweak_id)
            self._sync_banner()
        # re-detect just this tweak
        row = self._rows.get(res.tweak_id)
        if row:
            try:
                row.set_state(self.registry.get(res.tweak_id).detect())
            except Exception:  # noqa: BLE001
                row.set_state(TweakState.UNKNOWN)

    # -- profiles / batch --------------------------------------------------- #
    @pyqtSlot(str)
    def _on_run_profile(self, profile_id: str) -> None:
        try:
            plan = self.runner.preview(profile_id)
        except Exception as exc:  # noqa: BLE001
            self._log(f"profile preview error: {exc}", RED)
            return
        dlg = BatchApprovalDialog(plan, self)
        if dlg.exec() != QDialog.DialogCode.Accepted:
            self._log(f"denied profile {profile_id} (cancelled)", TEXT_DIM)
            return

        self.applier.dry_run = self.dry_cb.isChecked()
        self.applier.require_restore_point = self.restore_cb.isChecked()
        self.applier.restore_gate.enabled = self.restore_cb.isChecked()

        self._set_all_busy(True)
        self._log(f"running profile: {plan.name}", TEAL)
        w = BatchWorker(self.runner, profile_id)
        w.item_result.connect(self._on_result)
        w.done.connect(self._on_batch_done)
        self._launch(w)

    @pyqtSlot(object)
    def _on_batch_done(self, res: BatchResult) -> None:
        self._set_all_busy(False)
        if res.aborted:
            self._log(f"profile aborted — restore point failed: "
                      f"{res.restore_point_reason}", AMBER)
            return
        self._log(f"profile complete — {res.applied} applied, {res.denied} denied, "
                  f"{res.errored} errored", PHOSPHOR if not res.errored else AMBER)
        self._sync_banner()

    def _set_all_busy(self, busy: bool) -> None:
        for row in self._rows.values():
            row.set_busy(busy)

    # -- params ------------------------------------------------------------- #
    def _collect_params(self, tweak) -> Optional[dict]:
        if not tweak.params:
            return {}
        values: dict[str, str] = {}
        for spec in tweak.params:
            if spec.kind == "path":
                path = QFileDialog.getExistingDirectory(self, spec.label)
                if not path:
                    return None
                values[spec.key] = path
            else:
                return None  # text params: add an input dialog when needed
        return values

    # -- banner / explorer -------------------------------------------------- #
    def _sync_banner(self) -> None:
        parts = []
        if self._pending_reboot:
            parts.append(f"Reboot to finish: {', '.join(sorted(self._pending_reboot))}")
        if self._pending_explorer:
            parts.append(
                f"Explorer restart to finish: {', '.join(sorted(self._pending_explorer))}"
            )
        if parts:
            self.banner_text.setText("   •   ".join(parts))
            self.explorer_btn.setVisible(bool(self._pending_explorer))
            self.banner.show()
        else:
            self.banner.hide()

    @pyqtSlot()
    def _restart_explorer(self) -> None:
        try:
            subprocess.run(["taskkill", "/f", "/im", "explorer.exe"],
                           capture_output=True, timeout=15, check=False)
            subprocess.Popen(["explorer.exe"])
            self._pending_explorer.clear()
            self._sync_banner()
            self._log("Explorer restarted", PHOSPHOR)
        except (OSError, subprocess.SubprocessError) as exc:
            self._log(f"Explorer restart failed: {exc}", RED)

    # -- audit -------------------------------------------------------------- #
    @pyqtSlot()
    def _verify_audit(self) -> None:
        ok = self.applier.audit.verify()
        n = len(self.applier.audit.entries())
        if ok:
            self._log(f"audit chain verified — {n} entries intact", PHOSPHOR)
        else:
            self._log("AUDIT CHAIN BROKEN — history has been tampered with", RED)

    # -- plumbing ----------------------------------------------------------- #
    def _launch(self, worker: QThread) -> None:
        self._worker_refs.add(worker)                 # GC-safety
        worker.finished.connect(lambda w=worker: self._worker_refs.discard(w))
        worker.start()

    def _set_busy(self, tweak_id: str, busy: bool) -> None:
        row = self._rows.get(tweak_id)
        if row:
            row.set_busy(busy)

    def _log(self, msg: str, color: str = TEXT) -> None:
        self.log.appendHtml(f'<span style="color:{color};">▸ {msg}</span>')


# --------------------------------------------------------------------------- #
#  Entry point                                                                 #
# --------------------------------------------------------------------------- #
def main() -> int:
    app = QApplication(sys.argv)
    try:
        QFontDatabase.addApplicationFont("")  # no-op; JetBrains Mono if installed
    except Exception:  # noqa: BLE001
        pass
    win = QMainWindow()
    win.setWindowTitle("MWGA — Make Windows Great Again")
    win.resize(940, 780)
    panel = MWGAPanel()
    win.setCentralWidget(panel)
    win.setStyleSheet(STYLE)
    win.show()
    return app.exec()


if __name__ == "__main__":
    sys.exit(main())
