"""
MWGA — Make Windows Great Again
Domain layer: declarative tweak catalog + operation model.

Author : Leon Priest / 7h3v01d
License : Apache 2.0
Target  : Windows 11 (Python 3.11)

Design contract
---------------
A Tweak is *data*. It owns an ordered list of Operations. The engine never
needs bespoke logic per tweak — detect / backup / apply / revert are composed
generically from the Operations. Backup is the exact prior state (present or
absent), so revert is a real undo, not a guess at "the default".

Every high-risk item carries an honest `tradeoff` string. MWGA's job is to make
the cost visible and the change reversible, not to hide it.

winreg is soft-imported so the catalog can be inspected / unit-tested on
non-Windows. Detection and application raise NotSupportedError off-Windows.
"""

from __future__ import annotations

import subprocess
import sys
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Callable, Optional

try:  # soft import: catalog stays inspectable on Linux/CI
    import winreg  # type: ignore
    _WINREG = True
except ImportError:  # pragma: no cover - non-Windows
    winreg = None  # type: ignore
    _WINREG = False


# --------------------------------------------------------------------------- #
#  OS detection (for applicability gating)                                     #
# --------------------------------------------------------------------------- #
def windows_build() -> Optional[int]:
    """Windows build number, or None off-Windows / if undetectable."""
    if not sys.platform.startswith("win"):
        return None
    try:
        return sys.getwindowsversion().build  # type: ignore[attr-defined]
    except Exception:  # pragma: no cover
        return None


def is_windows_11() -> bool:
    """True on Win11 (build >= 22000). Unknown host -> True (don't hide)."""
    b = windows_build()
    return True if b is None else b >= 22000


def is_windows_10() -> bool:
    """True on Win10 (build 10240..21999)."""
    b = windows_build()
    return b is not None and 10240 <= b < 22000


# --------------------------------------------------------------------------- #
#  Errors                                                                      #
# --------------------------------------------------------------------------- #
class NotSupportedError(RuntimeError):
    """Raised when an operation is executed on a non-Windows host."""


class OperationError(RuntimeError):
    """Raised when an operation fails to read/apply/restore."""


# --------------------------------------------------------------------------- #
#  Enums / sentinels                                                           #
# --------------------------------------------------------------------------- #
class RiskLevel(Enum):
    LOW = "low"          # cosmetic / reversible / no security impact
    MEDIUM = "medium"    # behavioural change, reboot, or minor posture shift
    HIGH = "high"        # measurably lowers security posture — explicit consent

    def __str__(self) -> str:
        return self.value


class Category(Enum):
    ISO_FILES = "ISO & File Handling"
    SECURITY = "Security & Isolation"
    GAMING = "Gaming & GPU"
    PERFORMANCE = "Performance & Power"
    TELEMETRY = "Telemetry & Services"
    EXPLORER = "Explorer & UX"
    COMPAT = "Legacy Compatibility"

    def __str__(self) -> str:
        return self.value


class OpState(Enum):
    DESIRED = "desired"      # currently matches the tweak's target value
    DEFAULT = "default"      # currently matches the Windows default
    OTHER = "other"          # a third, user/OEM-set value
    ABSENT = "absent"        # value/key does not exist
    UNKNOWN = "unknown"      # could not be read


class TweakState(Enum):
    APPLIED = "applied"          # all ops DESIRED
    NOT_APPLIED = "not_applied"  # all ops DEFAULT or ABSENT (baseline)
    PARTIAL = "partial"          # mixed — some ops DESIRED, some not
    UNKNOWN = "unknown"          # at least one op unreadable
    NOT_APPLICABLE = "n/a"       # detected as irrelevant to this machine


class RegType(Enum):
    DWORD = "DWORD"
    SZ = "SZ"
    EXPAND_SZ = "EXPAND_SZ"
    MULTI_SZ = "MULTI_SZ"
    BINARY = "BINARY"

    def to_winreg(self) -> int:
        if not _WINREG:
            raise NotSupportedError("winreg unavailable")
        return {
            RegType.DWORD: winreg.REG_DWORD,
            RegType.SZ: winreg.REG_SZ,
            RegType.EXPAND_SZ: winreg.REG_EXPAND_SZ,
            RegType.MULTI_SZ: winreg.REG_MULTI_SZ,
            RegType.BINARY: winreg.REG_BINARY,
        }[self]


class _Absent:
    """Sentinel: the value/key should not exist (default == removal)."""
    _instance: "Optional[_Absent]" = None

    def __new__(cls) -> "_Absent":
        if cls._instance is None:
            cls._instance = super().__new__(cls)
        return cls._instance

    def __repr__(self) -> str:
        return "ABSENT"

    def __bool__(self) -> bool:
        return False


ABSENT = _Absent()


_HIVES = {
    "HKLM": "HKEY_LOCAL_MACHINE",
    "HKCU": "HKEY_CURRENT_USER",
    "HKCR": "HKEY_CLASSES_ROOT",
    "HKU": "HKEY_USERS",
}


def _hive(short: str) -> int:
    if not _WINREG:
        raise NotSupportedError("winreg unavailable")
    return getattr(winreg, _HIVES[short])


# --------------------------------------------------------------------------- #
#  Operation model                                                            #
# --------------------------------------------------------------------------- #
class Operation(ABC):
    """
    Atomic, reversible change. Subclasses implement the four verbs the engine
    composes. `snapshot()` returns a JSON-serialisable dict capturing the exact
    prior state; `restore()` consumes one to undo precisely.
    """

    kind: str = "operation"

    @abstractmethod
    def describe(self) -> str: ...

    @abstractmethod
    def current_state(self) -> OpState: ...

    @abstractmethod
    def snapshot(self) -> dict: ...

    @abstractmethod
    def apply(self) -> None: ...

    @abstractmethod
    def restore(self, snapshot: dict) -> None: ...

    @abstractmethod
    def reset_default(self) -> None: ...


@dataclass
class RegistryOp(Operation):
    """
    A single registry value. `desired` is the target; `default` is the stock
    Windows value (use ABSENT when the stock state is 'value does not exist').
    An empty `name` ("") targets the key's (Default) value.
    """

    hive: str                       # "HKLM" | "HKCU" | ...
    path: str                       # subkey path, no hive prefix
    name: str                       # value name; "" == (Default)
    reg_type: RegType
    desired: Any                    # target value
    default: Any                    # stock value, or ABSENT
    create_key: bool = False        # create the subkey if missing on apply
    wow64_64: bool = True           # force 64-bit view

    kind: str = field(default="registry", init=False)

    # -- access helpers ----------------------------------------------------- #
    def _flags(self, base: int) -> int:
        return base | (winreg.KEY_WOW64_64KEY if self.wow64_64 else 0)

    def _read_raw(self) -> tuple[Any, int] | None:
        """Return (value, type) or None if key/value absent."""
        if not _WINREG:
            raise NotSupportedError("winreg unavailable")
        try:
            with winreg.OpenKey(
                _hive(self.hive), self.path, 0, self._flags(winreg.KEY_READ)
            ) as k:
                return winreg.QueryValueEx(k, self.name)
        except FileNotFoundError:
            return None
        except OSError as exc:  # pragma: no cover - permission etc.
            raise OperationError(f"read failed: {self.describe()}: {exc}") from exc

    # -- Operation interface ------------------------------------------------ #
    def describe(self) -> str:
        shown = self.name or "(Default)"
        return f"{self.hive}\\{self.path}\\{shown} = {self.desired!r}"

    def current_state(self) -> OpState:
        try:
            raw = self._read_raw()
        except NotSupportedError:
            raise
        except OperationError:
            return OpState.UNKNOWN
        if raw is None:
            if self.default is ABSENT:
                return OpState.DEFAULT
            return OpState.ABSENT
        value = raw[0]
        if _reg_eq(value, self.desired):
            return OpState.DESIRED
        if self.default is not ABSENT and _reg_eq(value, self.default):
            return OpState.DEFAULT
        return OpState.OTHER

    def snapshot(self) -> dict:
        raw = self._read_raw()
        if raw is None:
            return {"present": False}
        value, vtype = raw
        return {"present": True, "value": _ser(value), "type": int(vtype)}

    def apply(self) -> None:
        self._write(self.reg_type.to_winreg(), self.desired, self.create_key)

    def restore(self, snapshot: dict) -> None:
        if not snapshot.get("present"):
            self._delete_value()
            return
        self._write(int(snapshot["type"]), _deser(snapshot["value"]), create=True)

    def reset_default(self) -> None:
        if self.default is ABSENT:
            self._delete_value()
        else:
            self._write(self.reg_type.to_winreg(), self.default, create=True)

    # -- low level ---------------------------------------------------------- #
    def _write(self, wtype: int, value: Any, create: bool) -> None:
        if not _WINREG:
            raise NotSupportedError("winreg unavailable")
        opener = winreg.CreateKeyEx if create else winreg.OpenKey
        try:
            with opener(
                _hive(self.hive), self.path, 0, self._flags(winreg.KEY_SET_VALUE)
            ) as k:
                winreg.SetValueEx(k, self.name, 0, wtype, value)
        except OSError as exc:
            raise OperationError(f"write failed: {self.describe()}: {exc}") from exc

    def _delete_value(self) -> None:
        if not _WINREG:
            raise NotSupportedError("winreg unavailable")
        try:
            with winreg.OpenKey(
                _hive(self.hive), self.path, 0, self._flags(winreg.KEY_SET_VALUE)
            ) as k:
                winreg.DeleteValue(k, self.name)
        except FileNotFoundError:
            return
        except OSError as exc:
            raise OperationError(f"delete failed: {self.describe()}: {exc}") from exc


@dataclass
class ServiceOp(Operation):
    """
    Service start-type via the Services\\<name>\\Start value. 2=auto, 3=manual,
    4=disabled. Optionally stops the live service on apply. Backup/restore ride
    entirely on the Start value, so undo is exact.
    """

    service: str
    desired_start: int = 4          # disabled
    default_start: int = 2          # automatic
    stop_on_apply: bool = True

    kind: str = field(default="service", init=False)

    def _reg(self, start: int) -> RegistryOp:
        return RegistryOp(
            hive="HKLM",
            path=f"SYSTEM\\CurrentControlSet\\Services\\{self.service}",
            name="Start",
            reg_type=RegType.DWORD,
            desired=self.desired_start,
            default=self.default_start,
        )

    def describe(self) -> str:
        m = {2: "auto", 3: "manual", 4: "disabled"}
        return f"service {self.service} -> {m.get(self.desired_start, self.desired_start)}"

    def current_state(self) -> OpState:
        return self._reg(self.desired_start).current_state()

    def snapshot(self) -> dict:
        return self._reg(self.desired_start).snapshot()

    def apply(self) -> None:
        self._reg(self.desired_start).apply()
        if self.stop_on_apply and self.desired_start == 4:
            self._stop()

    def restore(self, snapshot: dict) -> None:
        self._reg(self.desired_start).restore(snapshot)

    def reset_default(self) -> None:
        self._reg(self.desired_start).reset_default()

    def _stop(self) -> None:
        try:
            subprocess.run(
                ["sc", "stop", self.service],
                capture_output=True, text=True, timeout=30, check=False,
            )
        except (OSError, subprocess.SubprocessError):
            pass  # non-fatal; Start=disabled takes effect next boot regardless


@dataclass
class CommandOp(Operation):
    """
    For state that has no clean single-value registry home (Defender prefs,
    power schemes). Reversal is via an explicit `revert_cmd` rather than a
    value snapshot; `detect_cmd` output is matched against `desired_signal`.
    Backup captures the raw detect output for the audit trail.
    """

    detect_cmd: list[str]
    desired_signal: str             # substring meaning "already desired"
    apply_cmd: list[str]
    revert_cmd: list[str]
    default_signal: Optional[str] = None   # substring meaning "stock/default"
    shell_note: str = ""            # human note, e.g. 'runs Defender cmdlet'

    kind: str = field(default="command", init=False)

    def describe(self) -> str:
        return self.shell_note or " ".join(self.apply_cmd)

    def _run(self, cmd: list[str]) -> str:
        if not _WINREG:  # gate command ops to Windows too
            raise NotSupportedError("command operations require Windows")
        try:
            r = subprocess.run(
                cmd, capture_output=True, text=True, timeout=60, check=False
            )
        except (OSError, subprocess.SubprocessError) as exc:
            raise OperationError(f"command failed: {cmd}: {exc}") from exc
        return (r.stdout or "") + (r.stderr or "")

    def current_state(self) -> OpState:
        try:
            out = self._run(self.detect_cmd).lower()
        except NotSupportedError:
            raise
        except OperationError:
            return OpState.UNKNOWN
        if self.desired_signal.lower() in out:
            return OpState.DESIRED
        if self.default_signal and self.default_signal.lower() in out:
            return OpState.DEFAULT
        return OpState.OTHER

    def snapshot(self) -> dict:
        try:
            return {"detect": self._run(self.detect_cmd)}
        except OperationError as exc:
            return {"detect": None, "error": str(exc)}

    def apply(self) -> None:
        self._run(self.apply_cmd)

    def restore(self, _snapshot: dict) -> None:
        self._run(self.revert_cmd)

    def reset_default(self) -> None:
        self._run(self.revert_cmd)


# --------------------------------------------------------------------------- #
#  Value (de)serialisation for snapshots / equality                           #
# --------------------------------------------------------------------------- #
def _ser(value: Any) -> Any:
    if isinstance(value, bytes):
        return {"__bytes__": value.hex()}
    return value


def _deser(value: Any) -> Any:
    if isinstance(value, dict) and "__bytes__" in value:
        return bytes.fromhex(value["__bytes__"])
    return value


def _reg_eq(a: Any, b: Any) -> bool:
    if isinstance(a, str) and isinstance(b, str):
        return a.casefold() == b.casefold()
    return a == b


# --------------------------------------------------------------------------- #
#  Parameter spec (for the handful of tweaks needing user input)              #
# --------------------------------------------------------------------------- #
@dataclass
class ParamSpec:
    key: str
    label: str
    kind: str = "path"          # "path" | "text"
    required: bool = True


# --------------------------------------------------------------------------- #
#  Tweak                                                                       #
# --------------------------------------------------------------------------- #
@dataclass
class Tweak:
    id: str
    name: str
    category: Category
    risk: RiskLevel
    summary: str                     # one line: what it does
    rationale: str                   # why it helps the stated pain
    tradeoff: str                    # honest cost (esp. security). "" == none
    operations: list[Operation]
    requires_reboot: bool = False
    requires_explorer_restart: bool = False
    requires_admin: bool = True
    params: list[ParamSpec] = field(default_factory=list)
    applies_when: Optional[Callable[[], bool]] = None  # machine relevance gate
    tags: tuple[str, ...] = ()

    # -- engine-facing composition ----------------------------------------- #
    def is_applicable(self) -> bool:
        if self.applies_when is None:
            return True
        try:
            return bool(self.applies_when())
        except Exception:
            return True

    def detect(self) -> TweakState:
        if not self.is_applicable():
            return TweakState.NOT_APPLICABLE
        states = [op.current_state() for op in self.operations]
        if OpState.UNKNOWN in states:
            return TweakState.UNKNOWN
        desired = sum(s is OpState.DESIRED for s in states)
        baseline = sum(s in (OpState.DEFAULT, OpState.ABSENT) for s in states)
        if desired == len(states):
            return TweakState.APPLIED
        if baseline == len(states):
            return TweakState.NOT_APPLIED
        return TweakState.PARTIAL

    def backup(self) -> dict:
        """Serialisable snapshot of every operation's prior state."""
        return {str(i): op.snapshot() for i, op in enumerate(self.operations)}

    def apply(self) -> None:
        for op in self.operations:
            op.apply()

    def revert(self, backup: dict) -> None:
        """Exact undo from a backup produced by `backup()`."""
        for i, op in enumerate(self.operations):
            snap = backup.get(str(i))
            if snap is not None:
                op.restore(snap)

    def reset_default(self) -> None:
        for op in self.operations:
            op.reset_default()


# --------------------------------------------------------------------------- #
#  The catalog                                                                #
# --------------------------------------------------------------------------- #
def _reg(hive, path, name, rtype, desired, default, **kw) -> RegistryOp:
    return RegistryOp(hive, path, name, rtype, desired, default, **kw)


CATALOG: list[Tweak] = [

    # ----------------------------- ISO & FILES ------------------------------ #
    Tweak(
        id="iso.icons_only",
        name="Skip thumbnail generation in Explorer",
        category=Category.ISO_FILES,
        risk=RiskLevel.LOW,
        summary="Show icons instead of live thumbnails.",
        rationale="Explorer generating thumbnails for every file inside a "
                  "mounted ISO / media folder is a common cause of long open "
                  "and browse stalls.",
        tradeoff="No image/video thumbnails in Explorer.",
        operations=[
            _reg("HKCU",
                 "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Explorer\\Advanced",
                 "IconsOnly", RegType.DWORD, 1, 0),
        ],
        requires_explorer_restart=True,
        tags=("iso", "explorer", "thumbnails"),
    ),
    Tweak(
        id="iso.smartscreen_files",
        name="Disable SmartScreen reputation check on files",
        category=Category.ISO_FILES,
        risk=RiskLevel.HIGH,
        summary="Stop the online reputation check that gates opening files.",
        rationale="SmartScreen phones home to reputation-check downloaded "
                  "files/images before they open, adding latency to launching "
                  "or mounting.",
        tradeoff="Removes a real malware guard on downloaded executables. "
                 "Only sensible if you vet your own downloads.",
        operations=[
            _reg("HKLM",
                 "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Explorer",
                 "SmartScreenEnabled", RegType.SZ, "Off", "RequireAdmin"),
            _reg("HKLM",
                 "SOFTWARE\\Policies\\Microsoft\\Windows\\System",
                 "EnableSmartScreen", RegType.DWORD, 0, ABSENT,
                 create_key=True),
        ],
        tags=("iso", "smartscreen", "security"),
    ),
    Tweak(
        id="iso.defender_exclusion_path",
        name="Add a Defender scan exclusion (path)",
        category=Category.ISO_FILES,
        risk=RiskLevel.HIGH,
        summary="Exclude a folder/drive from real-time scanning.",
        rationale="Real-time scanning of an ISO on mount and of every file read "
                  "inside it is often the single biggest cause of 'opening an "
                  "ISO takes forever'. A scoped exclusion targets just the pain.",
        tradeoff="Anything inside the excluded path is no longer scanned. Scope "
                 "it tightly (an ISO staging folder), never an entire drive you "
                 "download to.",
        operations=[
            CommandOp(
                detect_cmd=["powershell", "-NoProfile", "-Command",
                            "(Get-MpPreference).ExclusionPath -join ';'"],
                desired_signal="{path}",     # resolved at bind time (see note)
                apply_cmd=["powershell", "-NoProfile", "-Command",
                           "Add-MpPreference -ExclusionPath '{path}'"],
                revert_cmd=["powershell", "-NoProfile", "-Command",
                            "Remove-MpPreference -ExclusionPath '{path}'"],
                shell_note="Defender ExclusionPath add/remove",
            ),
        ],
        params=[ParamSpec("path", "Folder to exclude", kind="path")],
        tags=("iso", "defender", "security"),
    ),

    # ----------------------------- SECURITY --------------------------------- #
    Tweak(
        id="sec.hvci_memory_integrity",
        name="Disable Core Isolation → Memory Integrity (HVCI)",
        category=Category.SECURITY,
        risk=RiskLevel.HIGH,
        summary="Turn off hypervisor-enforced code integrity.",
        rationale="HVCI virtualises code-integrity checks and commonly costs "
                  "real frame-time; it also breaks some older anti-cheat and "
                  "unsigned/legacy drivers, which can present as games or old "
                  "programs hanging on launch.",
        tradeoff="Lowers kernel exploit resistance. This is a genuine security "
                 "downgrade — worth it for perf/compat on a trusted machine, "
                 "not something to do blindly.",
        operations=[
            _reg("HKLM",
                 "SYSTEM\\CurrentControlSet\\Control\\DeviceGuard\\Scenarios\\"
                 "HypervisorEnforcedCodeIntegrity",
                 "Enabled", RegType.DWORD, 0, 1, create_key=True),
        ],
        requires_reboot=True,
        tags=("vbs", "hvci", "security", "gaming"),
    ),
    Tweak(
        id="sec.vbs_platform",
        name="Disable Virtualization-Based Security (platform)",
        category=Category.SECURITY,
        risk=RiskLevel.HIGH,
        summary="Turn off the VBS platform itself.",
        rationale="Beyond HVCI, the VBS platform reserves a hypervisor layer "
                  "that adds overhead across the board. Disabling it recovers "
                  "that overhead where security policy allows.",
        tradeoff="Disables the foundation several isolation features build on "
                 "(Credential Guard, HVCI). Only after HVCI is already off.",
        operations=[
            _reg("HKLM",
                 "SYSTEM\\CurrentControlSet\\Control\\DeviceGuard",
                 "EnableVirtualizationBasedSecurity", RegType.DWORD, 0, 1,
                 create_key=True),
        ],
        requires_reboot=True,
        tags=("vbs", "security"),
    ),
    Tweak(
        id="sec.controlled_folder_access",
        name="Disable Controlled Folder Access",
        category=Category.SECURITY,
        risk=RiskLevel.MEDIUM,
        summary="Stop Defender ransomware guard blocking writes.",
        rationale="Controlled Folder Access silently blocks unrecognised "
                  "programs from writing to Documents/Pictures/etc. — a frequent "
                  "cause of old programs failing to save or 'not working' with "
                  "no obvious error.",
        tradeoff="Removes the anti-ransomware write guard on protected folders.",
        operations=[
            CommandOp(
                detect_cmd=["powershell", "-NoProfile", "-Command",
                            "(Get-MpPreference).EnableControlledFolderAccess"],
                desired_signal="0",          # 0/Disabled
                default_signal="1",
                apply_cmd=["powershell", "-NoProfile", "-Command",
                           "Set-MpPreference -EnableControlledFolderAccess Disabled"],
                revert_cmd=["powershell", "-NoProfile", "-Command",
                            "Set-MpPreference -EnableControlledFolderAccess Enabled"],
                shell_note="Defender Controlled Folder Access toggle",
            ),
        ],
        tags=("defender", "ransomware", "compat"),
    ),

    # ----------------------------- GAMING ----------------------------------- #
    Tweak(
        id="game.gamedvr_disable",
        name="Disable Game Bar background capture (GameDVR)",
        category=Category.GAMING,
        risk=RiskLevel.LOW,
        summary="Stop background recording overhead in games.",
        rationale="GameDVR's background capture adds CPU/GPU overhead and is a "
                  "well-known source of stutter and lower frame-rates.",
        tradeoff="Loses Game Bar clip/record features.",
        operations=[
            _reg("HKCU", "System\\GameConfigStore",
                 "GameDVR_Enabled", RegType.DWORD, 0, 1),
            _reg("HKCU",
                 "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\GameDVR",
                 "AppCaptureEnabled", RegType.DWORD, 0, 1),
            _reg("HKLM",
                 "SOFTWARE\\Policies\\Microsoft\\Windows\\GameDVR",
                 "AllowGameDVR", RegType.DWORD, 0, ABSENT, create_key=True),
        ],
        tags=("gaming", "gamedvr", "performance"),
    ),
    Tweak(
        id="game.hags",
        name="Toggle Hardware-Accelerated GPU Scheduling (HAGS)",
        category=Category.GAMING,
        risk=RiskLevel.MEDIUM,
        summary="Set HAGS on/off (this object targets OFF).",
        rationale="HAGS helps some GPU/driver combos and hurts others. It is a "
                  "labelled toggle, not a guess — flip and A/B test frame pacing.",
        tradeoff="Effect is setup-dependent; benchmark before/after rather than "
                 "assuming a direction.",
        operations=[
            _reg("HKLM",
                 "SYSTEM\\CurrentControlSet\\Control\\GraphicsDrivers",
                 "HwSchMode", RegType.DWORD, 1, 2),   # 1=off, 2=on(default)
        ],
        requires_reboot=True,
        tags=("gaming", "gpu", "hags"),
    ),
    Tweak(
        id="game.fso_disable_global",
        name="Disable Fullscreen Optimizations (global)",
        category=Category.GAMING,
        risk=RiskLevel.LOW,
        summary="Force true exclusive fullscreen behaviour.",
        rationale="FSO wraps 'fullscreen' apps in a borderless-window "
                  "compositor path that can add latency and break older games' "
                  "fullscreen handling.",
        tradeoff="A few titles prefer the FSO path; reversible per the toggle.",
        operations=[
            _reg("HKCU", "System\\GameConfigStore",
                 "GameDVR_FSEBehaviorMode", RegType.DWORD, 2, 0),
            _reg("HKCU", "System\\GameConfigStore",
                 "GameDVR_HonorUserFSEBehaviorMode", RegType.DWORD, 1, 0),
            _reg("HKCU", "System\\GameConfigStore",
                 "GameDVR_DXGIHonorFSEWindowsCompatible", RegType.DWORD, 1, 0),
            _reg("HKCU", "System\\GameConfigStore",
                 "GameDVR_EFSEFeatureFlags", RegType.DWORD, 0, 0),
        ],
        tags=("gaming", "fullscreen", "compat"),
    ),
    Tweak(
        id="game.mpo_disable",
        name="Disable Multi-Plane Overlay (MPO)",
        category=Category.GAMING,
        risk=RiskLevel.MEDIUM,
        summary="Troubleshoot flicker/black-screen/stutter from MPO.",
        rationale="MPO is a frequent culprit behind desktop flicker, brief "
                  "black screens, and video/game stutter on certain GPU driver "
                  "versions.",
        tradeoff="Slightly higher GPU power use for overlay-heavy playback; "
                 "purely a troubleshooting toggle.",
        operations=[
            _reg("HKLM", "SOFTWARE\\Microsoft\\Windows\\Dwm",
                 "OverlayTestMode", RegType.DWORD, 5, ABSENT, create_key=True),
        ],
        requires_reboot=True,
        tags=("gaming", "gpu", "mpo", "flicker"),
    ),

    # --------------------------- PERFORMANCE -------------------------------- #
    Tweak(
        id="perf.ultimate_power_plan",
        name="Enable Ultimate Performance power plan",
        category=Category.PERFORMANCE,
        risk=RiskLevel.LOW,
        summary="Duplicate + activate the Ultimate Performance scheme.",
        rationale="Removes micro-latency from aggressive core parking / power "
                  "state transitions on a desktop that is always plugged in.",
        tradeoff="Higher idle power draw. Fine for a desktop rig; not for a "
                 "battery laptop.",
        operations=[
            CommandOp(
                detect_cmd=["powercfg", "/getactivescheme"],
                desired_signal="Ultimate Performance",
                apply_cmd=["cmd", "/c",
                           "powercfg -duplicatescheme "
                           "e9a42b02-d5df-448d-aa00-03f14749eb61 && "
                           "powercfg -setactive "
                           "e9a42b02-d5df-448d-aa00-03f14749eb61"],
                revert_cmd=["cmd", "/c",
                            "powercfg -setactive SCHEME_BALANCED"],
                shell_note="powercfg Ultimate Performance activate",
            ),
        ],
        tags=("performance", "power"),
    ),
    Tweak(
        id="perf.long_paths",
        name="Enable Win32 long paths (>260 chars)",
        category=Category.PERFORMANCE,
        risk=RiskLevel.MEDIUM,
        summary="Lift the legacy MAX_PATH limit.",
        rationale="Old programs and deep project trees fail obscurely at the "
                  "260-char path limit; enabling long paths clears a whole class "
                  "of 'won't load / can't find file' errors.",
        tradeoff="A minority of very old apps assume the 260 limit; rare.",
        operations=[
            _reg("HKLM",
                 "SYSTEM\\CurrentControlSet\\Control\\FileSystem",
                 "LongPathsEnabled", RegType.DWORD, 1, 0),
        ],
        requires_reboot=True,
        tags=("compat", "filesystem"),
    ),

    # --------------------------- TELEMETRY ---------------------------------- #
    Tweak(
        id="tel.diagtrack",
        name="Disable Connected User Experiences (DiagTrack)",
        category=Category.TELEMETRY,
        risk=RiskLevel.MEDIUM,
        summary="Stop the primary telemetry service.",
        rationale="DiagTrack runs constant background telemetry collection; "
                  "disabling it frees I/O and CPU with no user-visible loss.",
        tradeoff="Some enterprise feedback/diagnostic features stop reporting.",
        operations=[ServiceOp("DiagTrack", desired_start=4, default_start=2)],
        tags=("telemetry", "service", "privacy"),
    ),
    Tweak(
        id="tel.allow_telemetry",
        name="Set telemetry level to minimum",
        category=Category.TELEMETRY,
        risk=RiskLevel.LOW,
        summary="AllowTelemetry policy → 0.",
        rationale="Caps the OS diagnostic data level at the lowest the policy "
                  "surface allows.",
        tradeoff="None functional on a personal machine.",
        operations=[
            _reg("HKLM",
                 "SOFTWARE\\Policies\\Microsoft\\Windows\\DataCollection",
                 "AllowTelemetry", RegType.DWORD, 0, ABSENT, create_key=True),
        ],
        tags=("telemetry", "privacy"),
    ),
    Tweak(
        id="tel.sysmain",
        name="Disable SysMain (Superfetch)",
        category=Category.TELEMETRY,
        risk=RiskLevel.MEDIUM,
        summary="Stop the prefetch/superfetch service.",
        rationale="On an all-SSD machine SysMain's prefetch churn gives little "
                  "benefit and can cause background disk activity spikes.",
        tradeoff="On HDD-backed systems SysMain genuinely helps — leave it on "
                 "there. Situational.",
        operations=[ServiceOp("SysMain", desired_start=4, default_start=2)],
        tags=("performance", "service", "ssd"),
    ),
    Tweak(
        id="tel.wsearch",
        name="Disable Windows Search indexing",
        category=Category.TELEMETRY,
        risk=RiskLevel.MEDIUM,
        summary="Stop the WSearch indexer service.",
        rationale="The indexer can hammer disk I/O; disabling it removes "
                  "background scanning that also touches mounted volumes.",
        tradeoff="Start-menu / Explorer search becomes slower (live scan "
                 "instead of index). Situational.",
        operations=[ServiceOp("WSearch", desired_start=4, default_start=2)],
        tags=("performance", "service", "search"),
    ),
    Tweak(
        id="tel.advertising_id",
        name="Disable advertising ID",
        category=Category.TELEMETRY,
        risk=RiskLevel.LOW,
        summary="Turn off the per-user advertising identifier.",
        rationale="Stops apps correlating activity via the advertising ID.",
        tradeoff="None.",
        operations=[
            _reg("HKCU",
                 "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\AdvertisingInfo",
                 "Enabled", RegType.DWORD, 0, 1, create_key=True),
        ],
        tags=("privacy",),
    ),

    # ---------------------------- EXPLORER / UX ----------------------------- #
    Tweak(
        id="ux.classic_context_menu",
        name="Restore classic right-click context menu",
        category=Category.EXPLORER,
        risk=RiskLevel.LOW,
        summary="Bring back the full menu (no 'Show more options').",
        rationale="The Win11 truncated menu forces a second click for common "
                  "actions; the classic menu restores immediate access.",
        tradeoff="None — purely UX.",
        operations=[
            _reg("HKCU",
                 "SOFTWARE\\Classes\\CLSID\\"
                 "{86ca1aa0-34aa-4e8b-a509-50c905bae2a2}\\InprocServer32",
                 "", RegType.SZ, "", ABSENT, create_key=True),
        ],
        requires_explorer_restart=True,
        applies_when=lambda: is_windows_11(),  # Win10 menu is already classic
        tags=("explorer", "ux", "context-menu"),
    ),
    Tweak(
        id="ux.visual_effects_perf",
        name="Trim animations / visual effects",
        category=Category.EXPLORER,
        risk=RiskLevel.LOW,
        summary="Bias visual effects toward responsiveness.",
        rationale="Menu-open delays and window animations add perceptible lag "
                  "to routine interaction; trimming them makes the desktop feel "
                  "immediate again.",
        tradeoff="Less fade/slide polish.",
        operations=[
            _reg("HKCU",
                 "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Explorer\\"
                 "VisualEffects", "VisualFXSetting", RegType.DWORD, 2, 0,
                 create_key=True),
            _reg("HKCU", "Control Panel\\Desktop",
                 "MenuShowDelay", RegType.SZ, "0", "400"),
            _reg("HKCU", "Control Panel\\Desktop\\WindowMetrics",
                 "MinAnimate", RegType.SZ, "0", "1"),
        ],
        requires_explorer_restart=True,
        tags=("explorer", "ux", "performance"),
    ),
    Tweak(
        id="ux.background_apps",
        name="Disable background apps globally",
        category=Category.EXPLORER,
        risk=RiskLevel.LOW,
        summary="Stop UWP apps running in the background.",
        rationale="Background UWP apps consume CPU/RAM/network with no window "
                  "open; disabling globally recovers idle resources.",
        tradeoff="Live tiles / push updates for Store apps stop until opened.",
        operations=[
            _reg("HKCU",
                 "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\"
                 "BackgroundAccessApplications",
                 "GlobalUserDisabled", RegType.DWORD, 1, 0, create_key=True),
        ],
        tags=("performance", "uwp"),
    ),
    Tweak(
        id="ux.startup_delay",
        name="Remove startup app delay",
        category=Category.EXPLORER,
        risk=RiskLevel.LOW,
        summary="StartupDelayInMSec → 0.",
        rationale="Win11 imposes a deliberate delay before startup apps launch; "
                  "removing it lets the desktop become usable sooner.",
        tradeoff="Marginally busier first few seconds after login.",
        operations=[
            _reg("HKCU",
                 "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Explorer\\"
                 "Serialize", "StartupDelayInMSec", RegType.DWORD, 0, ABSENT,
                 create_key=True),
        ],
        tags=("startup", "performance"),
    ),
    Tweak(
        id="ux.show_extensions",
        name="Show file extensions",
        category=Category.EXPLORER,
        risk=RiskLevel.LOW,
        summary="Reveal known file extensions.",
        rationale="Hidden extensions obscure file types and are a mild security "
                  "footgun (double-extension lures).",
        tradeoff="None.",
        operations=[
            _reg("HKCU",
                 "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Explorer\\"
                 "Advanced", "HideFileExt", RegType.DWORD, 0, 1),
        ],
        requires_explorer_restart=True,
        tags=("explorer", "ux"),
    ),
]


# --------------------------------------------------------------------------- #
#  Registry / index                                                           #
# --------------------------------------------------------------------------- #
class TweakRegistry:
    """Lookup + integrity checks over the declarative catalog."""

    def __init__(self, tweaks: list[Tweak]):
        self._by_id: dict[str, Tweak] = {}
        for t in tweaks:
            if t.id in self._by_id:
                raise ValueError(f"duplicate tweak id: {t.id}")
            self._by_id[t.id] = t
        self._tweaks = list(tweaks)

    def __len__(self) -> int:
        return len(self._tweaks)

    def __iter__(self):
        return iter(self._tweaks)

    def get(self, tweak_id: str) -> Tweak:
        return self._by_id[tweak_id]

    def all(self) -> list[Tweak]:
        return list(self._tweaks)

    def by_category(self, category: Category) -> list[Tweak]:
        return [t for t in self._tweaks if t.category is category]

    def by_risk(self, *risks: RiskLevel) -> list[Tweak]:
        s = set(risks)
        return [t for t in self._tweaks if t.risk in s]

    def by_tag(self, tag: str) -> list[Tweak]:
        return [t for t in self._tweaks if tag in t.tags]

    def categories(self) -> list[Category]:
        seen: list[Category] = []
        for t in self._tweaks:
            if t.category not in seen:
                seen.append(t.category)
        return seen

    def validate(self) -> list[str]:
        """Structural checks the UI/engine can assert on at startup."""
        problems: list[str] = []
        for t in self._tweaks:
            if not t.operations:
                problems.append(f"{t.id}: no operations")
            if t.risk is RiskLevel.HIGH and not t.tradeoff:
                problems.append(f"{t.id}: HIGH risk with empty tradeoff")
            for p in t.params:
                needs = any(
                    "{" + p.key + "}" in _op_template(op)
                    for op in t.operations
                )
                if not needs:
                    problems.append(f"{t.id}: param '{p.key}' unused")
        return problems


def _op_template(op: Operation) -> str:
    if isinstance(op, CommandOp):
        return " ".join(op.apply_cmd + op.revert_cmd + [op.desired_signal])
    if isinstance(op, RegistryOp):
        return f"{op.path} {op.desired}"
    return ""


REGISTRY = TweakRegistry(CATALOG)


__all__ = [
    "RiskLevel", "Category", "OpState", "TweakState", "RegType", "ABSENT",
    "Operation", "RegistryOp", "ServiceOp", "CommandOp", "ParamSpec",
    "Tweak", "TweakRegistry", "CATALOG", "REGISTRY",
    "NotSupportedError", "OperationError",
    "windows_build", "is_windows_11", "is_windows_10",
]


# --------------------------------------------------------------------------- #
#  Quick self-inspection (safe on any OS — no reads/writes)                    #
# --------------------------------------------------------------------------- #
if __name__ == "__main__":
    problems = REGISTRY.validate()
    print(f"MWGA catalog — {len(REGISTRY)} tweaks across "
          f"{len(REGISTRY.categories())} categories\n")
    for cat in REGISTRY.categories():
        print(f"[{cat}]")
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
    if problems:
        print("VALIDATION PROBLEMS:")
        for p in problems:
            print(f"  - {p}")
    else:
        print("validate(): clean")
