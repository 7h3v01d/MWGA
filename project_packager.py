#!/usr/bin/env python3
"""
project_packager.py

A small, safe, audit-friendly project packaging and release-checking CLI.
Version is defined once, in TOOL_VERSION below; run with --version to see it.

Copyright 2026 Leon Priest / 7h3v01d
Licensed under the Apache License, Version 2.0.

Subcommands:
    package     Create a clean, verifiable ZIP of a project (default).
    check       Run universal + per-project release sanity checks.
    verify      Verify a ZIP against its embedded manifest and sidecar hash.
    init        Write starter release_check.toml and .packagerignore files.

Backward compatible: `python project_packager.py .` still packages.

Packaging (see `package --help`):
    - Never deletes or modifies your project (unless --clean, which removes
      only disposable cache junk).
    - Never follows symlinks. Symlinked files and directories are skipped and
      reported, so a link cannot smuggle material from outside the project
      into the archive. --include cannot override this.
    - Never packages the archive it is writing, its sidecar, or its temporary
      forms, even when --output is the project root itself.
    - Reserves PACKAGE_MANIFEST.json for its own metadata and refuses to
      package a project that already contains a file of that name.
    - Excludes caches, VCS folders, virtualenvs, build output, session
      debris, and existing *.zip files.
    - Embeds PACKAGE_MANIFEST.json (per-file SHA-256 + sizes) in the ZIP
      and writes a sha256sum-compatible <zip>.sha256 sidecar.
    - Scans included text files for likely secrets; warns by default,
      blocks in --strict / --profile release.

Checking (see `check --help`):
    Built-in universal checks (no config required):
      - working-tree debris (patch_*/fix_*/add_* scripts, *.bak, *.tmp, ...)
      - secret scan of tracked text files
      - latest package inspection: junk entries + manifest hash verification
    Per-project checks come from release_check.toml (create with `init`):
      version alignment across files, forbidden strings/regex, required
      files, required/forbidden file contents, requirements.txt hygiene,
      and an optional wheel build with required-contents verification.

Standard library only. Python 3.11+ (tomllib). Windows-friendly.
"""

from __future__ import annotations

import argparse
import codecs
import fnmatch
import hashlib
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
import zipfile
from dataclasses import dataclass, field
from enum import IntEnum, StrEnum
from datetime import datetime, timezone
from pathlib import Path
from typing import Iterable

TOOL_NAME = "project_packager"
TOOL_VERSION = "3.0.1"

MANIFEST_ARCNAME = "PACKAGE_MANIFEST.json"
CHECK_CONFIG_NAME = "release_check.toml"
IGNORE_FILE_NAME = ".packagerignore"

# --------------------------------------------------------------------------
# Exit codes
# --------------------------------------------------------------------------

class Exit(IntEnum):
    """Exit codes. Part of the CLI contract — automation depends on these.

    Kept granular deliberately: a CI job should be able to distinguish "your
    project has a problem" from "your configuration is broken" from "this tool
    refused on safety grounds" without parsing output.
    """

    OK = 0
    PROBLEMS = 1          # check failures / verification problems
    BAD_PROJECT = 2       # project path missing or not a directory
    OUTPUT_EXISTS = 3     # output ZIP already exists (use --overwrite)
    OS_ERROR = 4          # OS error while writing, or no verification evidence
    SECRETS = 5           # secrets, or unscannable text, in strict/release mode
    CHECKS_FAILED = 6     # non-secret pre-package release checks failed
    PARTIAL = 7           # sidecar valid but no embedded manifest to verify
    RESERVED_NAME = 8     # project file collides with reserved internal name
    BAD_CONFIG = 9        # release_check.toml or .packagerignore present but
                          # unreadable, malformed, or structurally invalid
    CONTAINMENT = 10      # a source path escaped the project between scan and write


# Module-level aliases, so call sites stay readable.
EXIT_OK = Exit.OK
EXIT_PROBLEMS = Exit.PROBLEMS
EXIT_BAD_PROJECT = Exit.BAD_PROJECT
EXIT_OUTPUT_EXISTS = Exit.OUTPUT_EXISTS
EXIT_OS_ERROR = Exit.OS_ERROR
EXIT_SECRETS = Exit.SECRETS
EXIT_CHECKS_FAILED = Exit.CHECKS_FAILED
EXIT_PARTIAL = Exit.PARTIAL
EXIT_RESERVED_NAME = Exit.RESERVED_NAME
EXIT_BAD_CONFIG = Exit.BAD_CONFIG
EXIT_CONTAINMENT = Exit.CONTAINMENT


class ConfigError(Exception):
    """release_check.toml exists but cannot be trusted.

    Deliberately distinct from "no configuration": a broken release gate must
    never be mistaken for an absent one.
    """


class ReservedNameError(Exception):
    """A project file collides with a name the packager reserves internally."""


class ContainmentError(Exception):
    """A source path escaped the project root between scanning and writing."""

# --------------------------------------------------------------------------
# Exclusion rule data
# --------------------------------------------------------------------------

# Working-session debris — shared between packager exclusions and checker.
DEBRIS_FILE_PATTERNS = {
    "*.bak",
    "*.bak.*",
    "*.tmp",
    "*.old",
    "*.orig",
    "patch_*.py",
    "patch_*.bat",
    "fix_*.py",
    "fix_*.bat",
    "add_*.py",
    "add_*.bat",
    "*New Text Document*",
}

# Directories excluded from ZIP by default (matched by exact name).
DEFAULT_EXCLUDE_DIR_NAMES = {
    ".git",
    ".vscode",
    ".idea",
    "__pycache__",
    ".pytest_cache",
    ".mypy_cache",
    ".ruff_cache",
    ".tox",
    ".venv",
    "venv",
    "env",
    "build",
    "dist",
    "htmlcov",
    "node_modules",
    # Working-session debris folders — must never ship
    "scripts",
}

# Directory name patterns excluded from ZIP by default.
DEFAULT_EXCLUDE_DIR_PATTERNS = {
    "*.egg-info",
}

# File names/patterns excluded from ZIP by default.
# Patterns containing "/" are matched against the relative POSIX path.
DEFAULT_EXCLUDE_FILE_PATTERNS = {
    "*.pyc",
    "*.pyo",
    ".coverage",
    "*.db",
    "*.sqlite",
    "*.sqlite3",
    ".DS_Store",
    "Thumbs.db",
    "desktop.ini",
    # No packages-inside-packages (rescue with --include "*.zip" if needed)
    "*.zip",
} | DEBRIS_FILE_PATTERNS

# Extra privacy/security exclusions only when strict mode is active.
STRICT_EXCLUDE_DIR_NAMES = {
    "secrets",
    "secret",
    "private",
    "keys",
}

STRICT_EXCLUDE_FILE_PATTERNS = {
    ".env",
    ".env.*",
    "*.key",
    "*.pem",
    "*.crt",
    "*.token",
    "*.secret",
    "config.local.*",
    "secrets.json",
    "secret.json",
    "credentials.json",
    "*.keystore",
    "id_rsa*",
    "id_ed25519*",
}

# Minimal exclusions for the "backup" profile.
BACKUP_EXCLUDE_DIR_NAMES = {
    ".git",
    "__pycache__",
    ".pytest_cache",
    ".mypy_cache",
    ".ruff_cache",
}

# Things --clean is allowed to delete.
# Deliberately conservative: no venv, no build/dist, no logs, no DBs, no ZIPs.
CLEAN_DIR_NAMES = {
    "__pycache__",
    ".pytest_cache",
    ".mypy_cache",
    ".ruff_cache",
}

CLEAN_FILE_PATTERNS = {
    "*.pyc",
    "*.pyo",
}

# Directories the checker never descends into.
CHECK_PRUNE_DIR_NAMES = DEFAULT_EXCLUDE_DIR_NAMES - {"scripts"} | {"packaged"}

# Warn when a single included file exceeds this many bytes.
LARGE_FILE_WARN_BYTES = 25 * 1024 * 1024
# Only secret-scan text files up to this size.
SECRET_SCAN_MAX_BYTES = 1 * 1024 * 1024

# --------------------------------------------------------------------------
# Secret scanning
# --------------------------------------------------------------------------

SECRET_PATTERNS: list[tuple[str, re.Pattern[str]]] = [
    ("AWS access key", re.compile(r"\bAKIA[0-9A-Z]{16}\b")),
    ("Anthropic API key", re.compile(r"\bsk-ant-[A-Za-z0-9_\-]{20,}")),
    ("OpenAI-style API key", re.compile(r"\bsk-[A-Za-z0-9]{40,}\b")),
    ("GitHub token", re.compile(r"\b(?:ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9]{36}\b")),
    ("GitHub fine-grained token", re.compile(r"\bgithub_pat_[A-Za-z0-9_]{60,}")),
    ("Slack token", re.compile(r"\bxox[baprs]-[A-Za-z0-9\-]{10,}")),
    ("Google API key", re.compile(r"\bAIza[0-9A-Za-z_\-]{35}\b")),
    ("Private key block", re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----")),
]


@dataclass
class SecretFinding:
    rel_path: Path
    line: int
    label: str
    preview: str


# --------------------------------------------------------------------------
# Core data structures
# --------------------------------------------------------------------------


@dataclass
class Decision:
    path: Path
    rel_path: Path
    reason: str


@dataclass
class ScanResult:
    included_files: list[Path] = field(default_factory=list)
    excluded: list[Decision] = field(default_factory=list)
    clean_dirs: list[Path] = field(default_factory=list)
    clean_files: list[Path] = field(default_factory=list)
    force_included: list[Path] = field(default_factory=list)
    skipped_symlinks: list[Decision] = field(default_factory=list)


@dataclass
class Rules:
    """Fully resolved exclusion/inclusion rules for one packaging run."""

    dir_names: set[str] = field(default_factory=set)
    dir_patterns: set[str] = field(default_factory=set)
    file_patterns: set[str] = field(default_factory=set)      # name-based
    path_patterns: set[str] = field(default_factory=set)      # contain "/"
    include_patterns: set[str] = field(default_factory=set)   # force-include


# --------------------------------------------------------------------------
# Pattern helpers
# --------------------------------------------------------------------------


def normalise_rel(path: Path) -> str:
    """Return a stable POSIX-style relative path for ZIP entries and output."""
    return path.as_posix()


def matches_any_pattern(name: str, patterns: Iterable[str]) -> str | None:
    """Return the first matching pattern, or None."""
    for pattern in patterns:
        if fnmatch.fnmatch(name, pattern):
            return pattern
    return None


def matches_path_pattern(rel_posix: str, patterns: Iterable[str]) -> str | None:
    """Match a relative POSIX path against path-aware patterns.

    A pattern matches the path itself or anything beneath it, so
    "tests/web_app.py" and "data/raw/" style patterns both behave sensibly.
    """
    for pattern in patterns:
        clean = pattern.rstrip("/")
        if fnmatch.fnmatch(rel_posix, clean) or fnmatch.fnmatch(rel_posix, clean + "/*"):
            return pattern
    return None


def normalise_pattern(pattern: str) -> str:
    """Accept Windows-style patterns without surprising Windows users.

    Rules are matched against POSIX-style relative paths, so a pattern typed
    as `large_data\\data.csv` must mean the same thing as `large_data/data.csv`.
    """
    return pattern.replace("\\", "/").strip()


def is_force_included(file_name: str, rel_posix: str, rules: Rules) -> str | None:
    """Return the matching --include pattern, or None."""
    for pattern in rules.include_patterns:
        if "/" in pattern:
            if matches_path_pattern(rel_posix, [pattern]):
                return pattern
        elif fnmatch.fnmatch(file_name, pattern):
            return pattern
    return None


def include_may_reopen_dir(rel_posix: str, rules: Rules) -> str | None:
    """Return an include pattern that needs this directory kept open, or None.

    P0 #4: `--include ".vscode/settings.json"` cannot work if `.vscode` is
    pruned before the file loop ever sees it. Only path-style patterns reopen
    a directory, and only along their own literal prefix — a bare name pattern
    such as `*.zip` must not drag every excluded tree back into the archive.
    """
    prefix = rel_posix.rstrip("/") + "/"
    for pattern in rules.include_patterns:
        if "/" not in pattern:
            continue
        clean = pattern.rstrip("/")
        if clean.startswith(prefix) or fnmatch.fnmatch(prefix.rstrip("/"), clean):
            return pattern
        # A wildcard segment ("docs/*/notes.md") can still target this branch.
        head = clean.split("/")[0]
        if ("*" in head or "?" in head) and fnmatch.fnmatch(rel_posix.split("/")[0], head):
            return pattern
    return None


def is_inside(path: Path, possible_parent: Path) -> bool:
    """Return True if path is inside possible_parent."""
    try:
        path.resolve().relative_to(possible_parent.resolve())
        return True
    except ValueError:
        return False


def should_exclude_dir(dir_name: str, rel_posix: str, rules: Rules) -> str | None:
    """Return exclusion reason for a directory, or None."""
    if dir_name in rules.dir_names:
        return f"directory exclusion: {dir_name}"

    matched = matches_any_pattern(dir_name, rules.dir_patterns)
    if matched:
        return f"directory pattern: {matched}"

    matched = matches_path_pattern(rel_posix, rules.path_patterns)
    if matched:
        return f"path pattern: {matched}"

    return None


def should_exclude_file(file_name: str, rel_posix: str, rules: Rules) -> str | None:
    """Return exclusion reason for a file, or None."""
    matched = matches_any_pattern(file_name, rules.file_patterns)
    if matched:
        return f"file pattern: {matched}"

    matched = matches_path_pattern(rel_posix, rules.path_patterns)
    if matched:
        return f"path pattern: {matched}"

    return None


# --------------------------------------------------------------------------
# Rule building (.packagerignore + CLI + profiles)
# --------------------------------------------------------------------------


def load_ignore_file(project_dir: Path) -> tuple[list[str], int]:
    """Load .packagerignore patterns. Returns (patterns, count).

    Fails closed in every profile. An absent ignore file means no exclusions
    were asked for; a file that exists but cannot be read means exclusions
    *were* asked for and have been lost. Ordinary sharing is exactly where
    people rely on this to keep private notes and local config out of an
    archive they are about to send someone, so it is not the place to
    downgrade the failure to a warning.
    """
    ignore_path = project_dir / IGNORE_FILE_NAME
    if not ignore_path.exists():
        return [], 0
    if not ignore_path.is_file():
        raise ConfigError(f"{IGNORE_FILE_NAME} exists but is not a regular file")

    patterns: list[str] = []
    try:
        # Strict decoding, utf-8-sig so a Windows-authored BOM is fine.
        # errors="replace" silently rewrote damaged bytes, which changed the
        # patterns: an exclusion stopped matching and the file it named shipped.
        # Guessing at corruption in a safety configuration file is not helpful.
        text = ignore_path.read_text(encoding="utf-8-sig")
    except UnicodeDecodeError as exc:
        raise ConfigError(f"{IGNORE_FILE_NAME} is not valid UTF-8: {exc}") from exc
    except OSError as exc:
        raise ConfigError(f"could not read {IGNORE_FILE_NAME}: {exc}") from exc

    for raw_line in text.splitlines():
        line = raw_line.strip()
        if not line or line.startswith("#"):
            continue
        patterns.append(line)
    return patterns, len(patterns)


def build_rules(
    *,
    profile: str,
    strict: bool,
    ignore_patterns: list[str],
    extra_excludes: list[str],
    include_patterns: list[str],
) -> Rules:
    """Assemble the final rule set for this run."""
    rules = Rules()

    if profile == "backup":
        rules.dir_names |= BACKUP_EXCLUDE_DIR_NAMES
        rules.file_patterns |= {"*.pyc", "*.pyo"}
    else:
        rules.dir_names |= DEFAULT_EXCLUDE_DIR_NAMES
        rules.dir_patterns |= DEFAULT_EXCLUDE_DIR_PATTERNS
        for pattern in DEFAULT_EXCLUDE_FILE_PATTERNS:
            (rules.path_patterns if "/" in pattern else rules.file_patterns).add(pattern)

    if strict:
        rules.dir_names |= STRICT_EXCLUDE_DIR_NAMES
        for pattern in STRICT_EXCLUDE_FILE_PATTERNS:
            (rules.path_patterns if "/" in pattern else rules.file_patterns).add(pattern)

    for raw_pattern in ignore_patterns + list(extra_excludes):
        pattern = normalise_pattern(raw_pattern)
        if not pattern:
            continue

        # A leading slash anchors the pattern to the project root, as in
        # gitignore. Without this, "/docs/" became the path pattern "/docs",
        # which can never match a relative path — the rule was silently
        # discarded and the user got no exclusion and no warning.
        anchored = pattern.startswith("/")
        if anchored:
            pattern = pattern.lstrip("/")
            if not pattern:
                continue

        if pattern.endswith("/"):
            clean = pattern.rstrip("/")
            if anchored or "/" in clean:
                rules.path_patterns.add(clean)
            else:
                rules.dir_patterns.add(clean)
        elif anchored or "/" in pattern:
            rules.path_patterns.add(pattern)
        else:
            rules.file_patterns.add(pattern)
            rules.dir_patterns.add(pattern)

    rules.include_patterns |= {
        normalise_pattern(p) for p in include_patterns if normalise_pattern(p)
    }
    return rules


# --------------------------------------------------------------------------
# Scanning
# --------------------------------------------------------------------------


def reserved_output_paths(output_zip: Path | None) -> set[Path]:
    """Paths the packager is about to write, which it must never archive.

    Kept separate from ordinary exclusions because --include must not be able
    to reach them: an archive that contains itself is never what was meant.
    """
    if output_zip is None:
        return set()
    resolved = output_zip.resolve()
    return {
        resolved,
        resolved.with_name(resolved.name + ".sha256"),
        resolved.with_name(resolved.name + ".part"),
        resolved.with_name(resolved.name + ".tmp"),
    }


def scan_project(
    project_dir: Path,
    rules: Rules,
    *,
    output_dir: Path | None = None,
    output_zip: Path | None = None,
) -> ScanResult:
    """Scan the project and decide what gets included/excluded.

    Safety restrictions that --include cannot override:
      - symlinked files and directories are never followed;
      - the archive being written, its sidecar, and its temporary forms are
        never packaged.

    A separate output *directory* inside the project is still pruned whole,
    but when the output directory is the project root itself only the exact
    output files are excluded — pruning the root would produce an archive
    containing nothing but a manifest.
    """
    result = ScanResult()
    project_dir = project_dir.resolve()
    resolved_output_dir = output_dir.resolve() if output_dir else None
    reserved = reserved_output_paths(output_zip)

    # Only prune a *separate* output subdirectory. output_dir == project_dir
    # is the `--output .` case and must not remove the project from itself.
    prune_output_dir = (
        resolved_output_dir is not None and resolved_output_dir != project_dir
    )

    # Directories that an --include reopened: kept open so the wanted file can
    # be reached, but everything else beneath them stays excluded.
    reopened: dict[Path, str] = {}

    def inherited_exclusion(path: Path) -> str | None:
        current = path
        while True:
            if current in reopened:
                return reopened[current]
            if current == project_dir or current.parent == current:
                return None
            current = current.parent

    for root, dirs, files in os.walk(project_dir):
        root_path = Path(root)

        if prune_output_dir and is_inside(root_path, resolved_output_dir):
            try:
                rel = root_path.relative_to(project_dir)
            except ValueError:
                rel = root_path
            result.excluded.append(
                Decision(root_path, rel, "output directory excluded to avoid self-packaging")
            )
            dirs[:] = []
            continue

        suppressed = inherited_exclusion(root_path)

        # Mutate dirs in-place so os.walk does not descend into excluded folders.
        kept_dirs: list[str] = []
        for dir_name in sorted(dirs):
            dir_path = root_path / dir_name
            rel_path = dir_path.relative_to(project_dir)
            rel_posix = normalise_rel(rel_path)

            # Non-overridable: never follow a symlinked directory. os.walk does
            # not descend into one by default, but it would still be reported
            # as an ordinary directory, and its files would be archived.
            if dir_path.is_symlink():
                result.skipped_symlinks.append(
                    Decision(dir_path, rel_path, "symlink directory skipped")
                )
                continue

            if dir_name in CLEAN_DIR_NAMES:
                result.clean_dirs.append(dir_path)

            reason = should_exclude_dir(dir_name, rel_posix, rules)
            if reason:
                reopen_hit = include_may_reopen_dir(rel_posix, rules)
                if reopen_hit:
                    # Keep walking, but remember that everything inside is
                    # excluded unless it is itself force-included.
                    reopened[dir_path] = reason
                    kept_dirs.append(dir_name)
                    continue
                result.excluded.append(Decision(dir_path, rel_path, reason))
            else:
                kept_dirs.append(dir_name)

        dirs[:] = kept_dirs

        for file_name in sorted(files):
            file_path = root_path / file_name
            rel_path = file_path.relative_to(project_dir)
            rel_posix = normalise_rel(rel_path)

            # Non-overridable: never follow a symlinked file. Checked before
            # --include so a link cannot be forced into the archive, and before
            # clean collection so cleaning cannot follow one either.
            if file_path.is_symlink():
                result.skipped_symlinks.append(
                    Decision(file_path, rel_path, "symlink file skipped")
                )
                continue

            # Non-overridable: never archive the output we are about to write.
            if reserved and file_path.resolve() in reserved:
                result.excluded.append(
                    Decision(file_path, rel_path, "reserved output file")
                )
                continue

            if matches_any_pattern(file_name, CLEAN_FILE_PATTERNS):
                result.clean_files.append(file_path)

            include_hit = is_force_included(file_name, rel_posix, rules)
            if include_hit:
                result.included_files.append(file_path)
                result.force_included.append(file_path)
                continue

            if suppressed:
                result.excluded.append(Decision(file_path, rel_path, suppressed))
                continue

            reason = should_exclude_file(file_name, rel_posix, rules)
            if reason:
                result.excluded.append(Decision(file_path, rel_path, reason))
            else:
                result.included_files.append(file_path)

    return result


def walk_check_tree(project_dir: Path) -> list[Path]:
    """Yield project files for checking, pruning caches/VCS/venv folders."""
    found: list[Path] = []
    for root, dirs, files in os.walk(project_dir):
        dirs[:] = sorted(
            d for d in dirs
            if d not in CHECK_PRUNE_DIR_NAMES
            and not matches_any_pattern(d, DEFAULT_EXCLUDE_DIR_PATTERNS)
        )
        for file_name in sorted(files):
            found.append(Path(root) / file_name)
    return found


# --------------------------------------------------------------------------
# Secret scanning
# --------------------------------------------------------------------------


# Control bytes that appear legitimately in text: tab, LF, VT, FF, CR, ESC.
TEXT_CONTROL_BYTES = frozenset({0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x1B})

# Above this proportion of unexpected control bytes, treat data as binary.
# Real text sits near zero; a stray NUL in a config file is well under it.
BINARY_CONTROL_RATIO = 0.05


def binary_control_ratio(sample: bytes) -> float:
    """Proportion of bytes that would be surprising in text."""
    if not sample:
        return 0.0
    odd = sum(
        1
        for byte in sample
        if (byte < 0x20 and byte not in TEXT_CONTROL_BYTES) or byte == 0x7F
    )
    return odd / len(sample)


def looks_binary(sample: bytes) -> bool:
    """Last-resort heuristic, consulted only after Unicode decoding has failed.

    Density, not presence. A single NUL does not prove a file is binary — it
    may be damaged text, generated configuration, or text disguised on purpose
    — and treating one as definitive meant an otherwise printable file was
    labelled "not scanned by design" while a key inside it shipped.

    Presence was also the wrong question for another reason: UTF-16 encodes
    ASCII as alternating NULs, so this is never the first test applied.
    """
    return binary_control_ratio(sample) > BINARY_CONTROL_RATIO


# Ordered longest-first: the UTF-32LE BOM begins with the UTF-16LE BOM, so
# checking UTF-16 first would mis-detect every UTF-32LE file.
TEXT_BOMS: tuple[tuple[bytes, str], ...] = (
    (codecs.BOM_UTF32_LE, "utf-32"),
    (codecs.BOM_UTF32_BE, "utf-32"),
    (codecs.BOM_UTF8, "utf-8-sig"),
    (codecs.BOM_UTF16_LE, "utf-16"),
    (codecs.BOM_UTF16_BE, "utf-16"),
)


def sniff_utf16(sample: bytes) -> str | None:
    """Detect BOM-less UTF-16 from its alternating-NUL signature.

    PowerShell, .reg exports, and various Windows tools emit UTF-16LE without a
    BOM. Mostly-ASCII UTF-16LE puts a NUL in every odd byte position and almost
    none in even ones; UTF-16BE is the mirror image.
    """
    if len(sample) < 8:
        return None
    even, odd = sample[0::2], sample[1::2]
    pairs = min(len(even), len(odd))
    if pairs == 0:
        return None
    even_nuls = even[:pairs].count(0) / pairs
    odd_nuls = odd[:pairs].count(0) / pairs

    if odd_nuls > 0.3 and even_nuls < 0.1:
        return "utf-16-le"
    if even_nuls > 0.3 and odd_nuls < 0.1:
        return "utf-16-be"
    return None


def detect_text_encoding(sample: bytes) -> str | None:
    """Return a codec that decodes this sample as text, or None.

    Tries, in order: a Unicode BOM, strict UTF-8, then BOM-less UTF-16.
    """
    for bom, codec_name in TEXT_BOMS:
        if sample.startswith(bom):
            return codec_name

    # Before UTF-8, because UTF-16LE ASCII *is* valid UTF-8 — it decodes to the
    # right characters interleaved with NULs, which no pattern then matches.
    # Plain UTF-8 text contains no NULs, so this cannot misfire on it.
    guess = sniff_utf16(sample)
    if guess:
        try:
            sample[: len(sample) // 2 * 2].decode(guess)
            return guess
        except UnicodeDecodeError:
            pass

    try:
        sample.decode("utf-8")
    except UnicodeDecodeError as exc:
        # A sample cut mid-character is not evidence of binary content.
        if exc.start < len(sample) - 4:
            return None
    # Valid UTF-8, but genuine UTF-8 text does not contain NUL bytes. Reaching
    # here with NULs means the data resolved as UTF-8 only incidentally — it is
    # not BOM-marked and not UTF-16 — so leave it to the binary heuristic.
    if looks_binary(sample):
        return None
    return "utf-8"


def decode_text_strict(data: bytes) -> str | None:
    """Decode bytes as text, or None if they are not decodable text.

    Strict throughout: `errors="ignore"` silently discarded bytes, so a
    malformed file counted as successfully scanned when parts of it had never
    been looked at.
    """
    encoding = detect_text_encoding(data[:8192])
    if encoding is None:
        return None
    try:
        return data.decode(encoding)
    except (UnicodeDecodeError, UnicodeError):
        return None


def read_text_safe(path: Path, limit: int = SECRET_SCAN_MAX_BYTES) -> str | None:
    """Read a file as text if it is small enough and genuinely decodable."""
    try:
        if path.stat().st_size > limit:
            return None
        data = path.read_bytes()
    except OSError:
        return None
    return decode_text_strict(data)


class UnscannedKind(StrEnum):
    """Why a file was not scanned, in the terms policy cares about."""

    BINARY = "binary"        # recognised asset; never a scan candidate
    TEXT_LIKE = "text-like"  # could hold a secret; blocks strict/release
    UNREADABLE = "unreadable"  # treated conservatively as text-like


@dataclass(frozen=True)
class UnscannedFile:
    """A file the secret scanner could not read, and why.

    `kind` drives policy; `reason` is for humans. Deriving the first from the
    second is how a 1 MiB PNG came to be treated as an unscanned text file, so
    the two are kept deliberately separate and `kind` is typed.
    """

    path: Path
    reason: str
    kind: UnscannedKind


LIKELY_TEXT_SUFFIXES = {
    ".txt", ".md", ".rst", ".py", ".js", ".ts", ".jsx", ".tsx", ".json", ".yaml",
    ".yml", ".toml", ".ini", ".cfg", ".conf", ".env", ".sh", ".bat", ".ps1",
    ".sql", ".html", ".css", ".xml", ".csv", ".log", ".java", ".cs", ".go",
    ".rb", ".php", ".rs", ".c", ".h", ".cpp", ".hpp",
}

BINARY_MAGIC_SIGNATURES: tuple[bytes, ...] = (
    b"\x89PNG\r\n\x1a\n",      # PNG
    b"\xff\xd8\xff",           # JPEG
    b"GIF87a", b"GIF89a",      # GIF
    b"BM",                     # BMP
    b"RIFF",                   # WAV / AVI / WEBP
    b"%PDF-",                  # PDF
    b"PK\x03\x04", b"PK\x05\x06", b"PK\x07\x08",  # ZIP family, incl. wheels
    b"\x1f\x8b",               # gzip
    b"BZh",                    # bzip2
    b"\xfd7zXZ\x00",           # xz
    b"7z\xbc\xaf\x27\x1c",     # 7z
    b"Rar!\x1a\x07",           # RAR
    b"\x7fELF",                # ELF
    b"MZ",                     # PE / DOS
    b"\xca\xfe\xba\xbe",       # Java class / Mach-O fat
    b"\xcf\xfa\xed\xfe",       # Mach-O
    b"OggS",                   # Ogg
    b"fLaC",                   # FLAC
    b"ID3",                    # MP3 with ID3
    b"\x00\x01\x00\x00\x00",   # TrueType
    b"OTTO",                   # OpenType
    b"wOFF", b"wOF2",          # WOFF
    b"\xed\xab\xee\xdb",       # RPM
    b"SQLite format 3\x00",    # SQLite
)

# Retained only to explain a decision in the reason text. Deliberately NOT used
# to classify: a filename asserts nothing about contents, and trusting it let an
# oversized printable file named report.pdf be recorded as "binary content, not
# scanned by design" while a key inside it shipped.
BINARY_SUFFIX_HINTS = {
    ".png", ".jpg", ".jpeg", ".gif", ".webp", ".bmp", ".ico", ".tif", ".tiff",
    ".pdf", ".zip", ".gz", ".bz2", ".xz", ".7z", ".rar", ".tar", ".whl", ".exe",
    ".dll", ".so", ".dylib", ".bin", ".dat", ".mp3", ".mp4", ".mov", ".avi",
    ".wav", ".flac", ".ttf", ".otf", ".woff", ".woff2", ".pyc", ".pyd", ".class",
}


def has_binary_magic(sample: bytes) -> bool:
    """True if the sample opens with a recognised binary file signature."""
    return any(sample.startswith(sig) for sig in BINARY_MAGIC_SIGNATURES)


def classify_unscannable(file_path: Path) -> UnscannedFile | None:
    """Explain why a file cannot be secret-scanned, or None if it can be.

    Content decides. The sample is read before size is considered, so a large
    binary asset is recognised as binary rather than as an oversized text file,
    and anything not *demonstrably* binary is treated conservatively as
    text-like — including when its extension suggests otherwise, since the
    extension is the one thing an attacker or an accident controls freely.
    """
    try:
        size = file_path.stat().st_size
    except OSError as exc:
        return UnscannedFile(file_path, f"unreadable: {exc}", UnscannedKind.UNREADABLE)

    try:
        with file_path.open("rb") as handle:
            sample = handle.read(8192)
    except OSError as exc:
        return UnscannedFile(file_path, f"unreadable: {exc}", UnscannedKind.UNREADABLE)

    suffix = file_path.suffix.lower()

    # A recognised signature is definitive.
    if has_binary_magic(sample):
        detail = f", {format_bytes(size)}" if size > SECRET_SCAN_MAX_BYTES else ""
        return UnscannedFile(
            file_path,
            f"binary content{detail} — not scanned by design",
            UnscannedKind.BINARY,
        )

    # Otherwise try to read it as text before reaching for the NUL heuristic:
    # UTF-16 is mostly NULs and is ordinary on Windows.
    encoding = detect_text_encoding(sample)

    if encoding is None and looks_binary(sample):
        detail = f", {format_bytes(size)}" if size > SECRET_SCAN_MAX_BYTES else ""
        return UnscannedFile(
            file_path,
            f"binary content{detail} — not scanned by design",
            UnscannedKind.BINARY,
        )

    if size > SECRET_SCAN_MAX_BYTES:
        # Printable content with a binary-looking name is exactly the case that
        # must not be waved through, so the mismatch is called out explicitly.
        mismatch = (
            f" (despite the {suffix} extension, its contents are printable text)"
            if suffix in BINARY_SUFFIX_HINTS
            else ""
        )
        return UnscannedFile(
            file_path,
            f"too large: {format_bytes(size)} exceeds the "
            f"{format_bytes(SECRET_SCAN_MAX_BYTES)} scan limit{mismatch}",
            UnscannedKind.TEXT_LIKE,
        )

    # Not demonstrably binary and within the size limit: it should have been
    # scannable, so anything that still fails to decode is reported rather than
    # read with holes in it.
    try:
        data = file_path.read_bytes()
    except OSError as exc:
        return UnscannedFile(file_path, f"unreadable: {exc}", UnscannedKind.UNREADABLE)

    if decode_text_strict(data) is None:
        return UnscannedFile(
            file_path,
            "not decodable as UTF-8, UTF-16, or UTF-32 text",
            UnscannedKind.TEXT_LIKE,
        )
    return None


@dataclass
class SecretScanResult:
    """Findings plus, just as importantly, what could not be looked at.

    A scanner that silently drops files it cannot read reports "no secrets"
    when it means "no secrets in the part I read". Release mode needs to know
    the difference.
    """

    findings: list[SecretFinding] = field(default_factory=list)
    unscanned: list[UnscannedFile] = field(default_factory=list)

    def __iter__(self):
        # Backwards compatible with callers that treat the result as a list.
        return iter(self.findings)

    def __len__(self) -> int:
        return len(self.findings)

    def __getitem__(self, index):
        return self.findings[index]

    def __bool__(self) -> bool:
        return bool(self.findings)

    @property
    def skipped(self) -> list[Path]:
        return [entry.path for entry in self.unscanned]

    def unscanned_text_files(self) -> list[UnscannedFile]:
        """Unscanned files that could plausibly contain a key.

        Binary assets are excluded: they were never candidates, and blocking a
        release because it contains a large image helps nobody.
        """
        return [
            entry
            for entry in self.unscanned
            if entry.kind in {UnscannedKind.TEXT_LIKE, UnscannedKind.UNREADABLE}
        ]


def scan_for_secrets(project_dir: Path, files: list[Path]) -> SecretScanResult:
    """Scan text files for likely secrets. Read-only, best-effort.

    Heuristic by nature: it detects known token shapes in files it can read.
    It cannot prove a project is secret-free, so everything it could not read
    is recorded rather than dropped.
    """
    result = SecretScanResult()

    for file_path in files:
        text = read_text_safe(file_path)
        if text is None:
            unscannable = classify_unscannable(file_path) or UnscannedFile(
                file_path, "could not be read as text", UnscannedKind.TEXT_LIKE
            )
            try:
                rel = file_path.relative_to(project_dir)
            except ValueError:
                rel = file_path
            result.unscanned.append(
                UnscannedFile(rel, unscannable.reason, unscannable.kind)
            )
            continue
        rel_path = file_path.relative_to(project_dir)

        for label, pattern in SECRET_PATTERNS:
            for match in pattern.finditer(text):
                line = text.count("\n", 0, match.start()) + 1
                token = match.group(0)
                preview = token[:10] + "..." if len(token) > 10 else token
                result.findings.append(SecretFinding(rel_path, line, label, preview))

    return result


# --------------------------------------------------------------------------
# Cleaning
# --------------------------------------------------------------------------


def remove_clean_targets(scan: ScanResult, *, dry_run: bool) -> tuple[int, int]:
    """Delete cache junk collected during scan. Returns (dirs_removed, files_removed)."""
    dirs_removed = 0
    files_removed = 0

    # Delete files first, then dirs.
    for file_path in scan.clean_files:
        if not file_path.exists():
            continue
        if not dry_run:
            try:
                file_path.unlink()
            except OSError as exc:
                print(f"WARNING: could not delete file {file_path}: {exc}", file=sys.stderr)
                continue
        files_removed += 1

    # Sort deepest first for predictable cleanup.
    for dir_path in sorted(scan.clean_dirs, key=lambda p: len(p.parts), reverse=True):
        if not dir_path.exists():
            continue
        if not dry_run:
            try:
                shutil.rmtree(dir_path)
            except OSError as exc:
                print(f"WARNING: could not delete directory {dir_path}: {exc}", file=sys.stderr)
                continue
        dirs_removed += 1

    return dirs_removed, files_removed


# --------------------------------------------------------------------------
# Hashing, manifest, ZIP creation
# --------------------------------------------------------------------------


def sha256_of_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as fh:
        for chunk in iter(lambda: fh.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def build_manifest(project_dir: Path, included_files: list[Path]) -> dict:
    """Build the embedded manifest: per-file SHA-256 + sizes."""
    entries = []
    total = 0
    for file_path in sorted(included_files):
        rel = normalise_rel(file_path.relative_to(project_dir))
        try:
            size = file_path.stat().st_size
            digest = sha256_of_file(file_path)
        except OSError:
            continue
        total += size
        entries.append({"path": rel, "size": size, "sha256": digest})

    return {
        "tool": TOOL_NAME,
        "version": TOOL_VERSION,
        "created_utc": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "project": project_dir.name,
        "file_count": len(entries),
        "total_bytes": total,
        "files": entries,
    }


def build_zip_name(project_dir: Path, custom_name: str | None) -> str:
    """Build a timestamped ZIP filename."""
    timestamp = datetime.now().strftime("%Y-%m-%d_%H%M")
    base = custom_name.strip() if custom_name else project_dir.name
    base = base[:-4] if base.lower().endswith(".zip") else base
    safe_base = "".join(c if c.isalnum() or c in "._-" else "_" for c in base).strip("._")
    if not safe_base:
        safe_base = "project"
    return f"{safe_base}_{timestamp}.zip"


def assert_no_reserved_collision(project_dir: Path, included_files: list[Path]) -> None:
    """P0 #5: refuse to package a project that ships its own manifest name.

    Silently dropping the user's file would lose material; writing both
    produces two members with the same name, and the resulting archive fails
    its own verification. Neither is acceptable, so the run stops instead.
    """
    for file_path in included_files:
        if normalise_rel(file_path.relative_to(project_dir)) == MANIFEST_ARCNAME:
            raise ReservedNameError(
                f"{MANIFEST_ARCNAME} is reserved for the packager's own metadata, "
                f"but the project contains a file of that name.\n"
                f"This applies with --no-manifest too: verify would read the "
                f"project's file as the internal manifest.\n"
                f"Rename it, or exclude it with --exclude \"{MANIFEST_ARCNAME}\"."
            )


def assert_contained(project_dir: Path, file_path: Path) -> None:
    """Recheck a source immediately before it is written into the archive.

    Scanning and writing are separate passes, so a path that was safe when
    scanned may not be safe by the time it is read.
    """
    if file_path.is_symlink():
        raise ContainmentError(f"refusing to archive a symlink: {file_path}")
    try:
        resolved = file_path.resolve(strict=True)
    except OSError as exc:
        raise ContainmentError(f"could not resolve {file_path}: {exc}") from exc
    if not is_inside(resolved, project_dir):
        raise ContainmentError(
            f"refusing to archive a path outside the project: {file_path} -> {resolved}"
        )


def create_zip(
    project_dir: Path,
    included_files: list[Path],
    output_zip: Path,
    *,
    overwrite: bool,
    manifest: dict | None,
) -> tuple[int, str, bool]:
    """Create the ZIP.

    Returns (total uncompressed bytes, zip sha256, sidecar written).
    """
    if output_zip.exists() and not overwrite:
        raise FileExistsError(
            f"Output already exists: {output_zip}\n"
            "Use --overwrite or choose a different --name/--output."
        )

    # Unconditional: the name belongs to the verification protocol, not to the
    # manifest-writing path. With --no-manifest a project's own file of that
    # name would otherwise be archived and later mistaken for the internal one.
    assert_no_reserved_collision(project_dir, included_files)

    output_zip.parent.mkdir(parents=True, exist_ok=True)

    total_bytes = 0
    try:
        total_bytes = _write_members(project_dir, included_files, output_zip, manifest)
    except (ReservedNameError, ContainmentError):
        # Full atomic replacement lands in v3.1.0. Until then, at least do not
        # leave a partial archive behind for the failures introduced here.
        try:
            output_zip.unlink(missing_ok=True)
        except OSError:
            pass
        raise

    zip_digest = sha256_of_file(output_zip)

    # Sidecar hash file: "<hash>  <filename>" (sha256sum-compatible).
    sidecar = output_zip.with_name(output_zip.name + ".sha256")
    sidecar_written = True
    try:
        sidecar.write_text(f"{zip_digest}  {output_zip.name}\n", encoding="utf-8")
    except OSError as exc:
        print(f"WARNING: could not write hash sidecar: {exc}", file=sys.stderr)
        sidecar_written = False

    return total_bytes, zip_digest, sidecar_written


def _write_members(
    project_dir: Path,
    included_files: list[Path],
    output_zip: Path,
    manifest: dict | None,
) -> int:
    """Write every member into the archive. Returns uncompressed byte total."""
    total_bytes = 0
    with zipfile.ZipFile(output_zip, "w", compression=zipfile.ZIP_DEFLATED) as zf:
        written: set[str] = set()
        for file_path in sorted(included_files):
            rel_path = file_path.relative_to(project_dir)
            arcname = normalise_rel(rel_path)
            if arcname in written:
                raise ReservedNameError(f"duplicate archive member: {arcname}")
            assert_contained(project_dir, file_path)
            zf.write(file_path, arcname)
            written.add(arcname)
            try:
                total_bytes += file_path.stat().st_size
            except OSError:
                pass

        if manifest is not None:
            if MANIFEST_ARCNAME in written:
                raise ReservedNameError(
                    f"{MANIFEST_ARCNAME} is reserved for the packager's own metadata."
                )
            zf.writestr(
                MANIFEST_ARCNAME,
                json.dumps(manifest, indent=2, sort_keys=False),
            )

    return total_bytes


# --------------------------------------------------------------------------
# Archive verification
# --------------------------------------------------------------------------


def verify_archive(zip_path: Path) -> int:
    """Check a ZIP against its embedded manifest and .sha256 sidecar.

    Tracks *positive evidence*, not merely the absence of detected failures.
    An archive with no trusted hash and no manifest has been checked against
    nothing at all, and saying so is the only honest result.

    Returns:
        0  every available check passed
        1  a check failed, or nothing could be checked
        7  partial: the sidecar matched, but there is no manifest to check
           the contents against
    """
    if not zip_path.is_file():
        print(f"ERROR: not a file: {zip_path}", file=sys.stderr)
        return EXIT_PROBLEMS

    failures = 0
    sidecar_verified = False   # a trusted hash matched the archive as a whole
    manifest_verified = False  # contents matched the archive's own manifest
    print()
    print(f"Verifying: {zip_path.name}")

    # Sidecar check.
    sidecar = zip_path.with_name(zip_path.name + ".sha256")
    if sidecar.is_file():
        try:
            expected = sidecar.read_text(encoding="utf-8").split()[0].strip().lower()
            actual = sha256_of_file(zip_path)
            if expected == actual:
                print(f"  OK    sidecar hash matches ({actual[:16]}...)")
                sidecar_verified = True
            else:
                print(f"  FAIL  sidecar hash mismatch")
                print(f"        expected {expected}")
                print(f"        actual   {actual}")
                failures += 1
        except (OSError, IndexError) as exc:
            print(f"  WARN  could not read sidecar: {exc}")
    else:
        print(f"  WARN  no .sha256 sidecar found")

    # Manifest check.
    try:
        with zipfile.ZipFile(zip_path) as zf:
            names = set(zf.namelist())
            if MANIFEST_ARCNAME not in names:
                print(f"  WARN  no {MANIFEST_ARCNAME} embedded")
                print()
                if failures:
                    print(f"RESULT: FAIL — {failures} problem(s) found.")
                    return EXIT_PROBLEMS
                if not sidecar_verified:
                    print("RESULT: FAIL — nothing could be checked.")
                    print("        No trusted sidecar hash and no embedded "
                          "manifest: this archive")
                    print("        carries no evidence about its own contents.")
                    return EXIT_PROBLEMS
                print("RESULT: PARTIAL — the sidecar hash matched, so the archive "
                      "matches the")
                print("        hash it was distributed with, but it contains no "
                      "manifest to")
                print("        check its individual members against.")
                return EXIT_PARTIAL

            manifest = json.loads(zf.read(MANIFEST_ARCNAME))
            entries = manifest.get("files", [])
            print(f"  Manifest: {manifest.get('project', '?')} — "
                  f"{manifest.get('file_count', len(entries))} file(s), "
                  f"created {manifest.get('created_utc', '?')}")

            ok_count = 0
            for entry in entries:
                arcname = entry.get("path", "")
                if arcname not in names:
                    print(f"  FAIL  missing from archive: {arcname}")
                    failures += 1
                    continue
                digest = hashlib.sha256(zf.read(arcname)).hexdigest()
                if digest != entry.get("sha256"):
                    print(f"  FAIL  hash mismatch: {arcname}")
                    failures += 1
                else:
                    ok_count += 1

            extras = names - {e.get("path") for e in entries} - {MANIFEST_ARCNAME}
            extras = {n for n in extras if not n.endswith("/")}
            for extra in sorted(extras):
                print(f"  FAIL  not in manifest: {extra}")
                failures += 1

            print(f"  {ok_count}/{len(entries)} file hashes verified")
            if not failures:
                manifest_verified = True
    except (OSError, zipfile.BadZipFile, json.JSONDecodeError) as exc:
        print(f"  FAIL  could not verify archive: {exc}")
        failures += 1

    print()
    if failures:
        print(f"RESULT: FAIL — {failures} problem(s) found.")
        return EXIT_PROBLEMS
    if not (sidecar_verified or manifest_verified):
        print("RESULT: FAIL — nothing could be checked.")
        return EXIT_PROBLEMS
    if manifest_verified and not sidecar_verified:
        print("RESULT: OK — archive is internally consistent with its own manifest.")
        print("        No trusted sidecar hash was available, so this shows the "
              "archive is")
        print("        self-consistent, not that it is the archive you were sent.")
        return EXIT_OK
    print("RESULT: OK — archive verified against its sidecar hash and manifest.")
    return EXIT_OK


# --------------------------------------------------------------------------
# Release checks
# --------------------------------------------------------------------------


@dataclass
class CheckReport:
    failures: list[str] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)
    passed: int = 0

    def check(self, label: str, ok: bool, detail: str = "") -> None:
        if ok:
            print(f"  OK    {label}")
            self.passed += 1
        else:
            print(f"  FAIL  {label}" + (f": {detail}" if detail else ""))
            self.failures.append(label)

    def warn(self, label: str, ok: bool, detail: str = "") -> None:
        if ok:
            print(f"  OK    {label}")
            self.passed += 1
        else:
            print(f"  WARN  {label}" + (f": {detail}" if detail else ""))
            self.warnings.append(label)

    def section(self, name: str) -> None:
        print(f"\n-- {name} --")


CHECK_CONFIG_SCHEMA_VERSION = 1

CONFIG_SCHEMA: dict[str, dict[str, str]] = {
    "version": {"target": "str", "files": "list[str]"},
    "forbidden": {
        "allow_files": "list[str]",
        "patterns": "dict[str,regex]",
        "contains": "dict[str,list[str]]",
    },
    "required": {"files": "list[str]", "contains": "dict[str,list[str]]"},
    "banned": {"paths": "list[str]"},
    "requirements": {"file": "str", "forbidden": "list[str]"},
    "wheel": {"build": "bool", "timeout": "int", "must_contain": "list[str]"},
}


def _check_type(where: str, value: object, expected: str) -> None:
    """Validate one configuration value against the schema, or raise."""
    if expected == "str":
        if not isinstance(value, str):
            raise ConfigError(f"{where} must be a string, got {type(value).__name__}")
    elif expected == "bool":
        if not isinstance(value, bool):
            raise ConfigError(f"{where} must be true or false, got {value!r}")
    elif expected == "int":
        # bool is an int subclass, so reject it explicitly.
        if isinstance(value, bool) or not isinstance(value, int):
            raise ConfigError(f"{where} must be an integer, got {value!r}")
    elif expected == "list[str]":
        if not isinstance(value, list) or not all(isinstance(v, str) for v in value):
            raise ConfigError(f"{where} must be a list of strings, got {value!r}")
    elif expected == "dict[str,list[str]]":
        if not isinstance(value, dict):
            raise ConfigError(f"{where} must be a table, got {type(value).__name__}")
        for key, item in value.items():
            _check_type(f"{where}.{key}", item, "list[str]")
    elif expected == "dict[str,regex]":
        if not isinstance(value, dict):
            raise ConfigError(f"{where} must be a table, got {type(value).__name__}")
        for key, pattern in value.items():
            if not isinstance(pattern, str):
                raise ConfigError(f"{where}.{key} must be a string, got {pattern!r}")
            try:
                re.compile(pattern)
            except re.error as exc:
                raise ConfigError(f"{where}.{key} is not a valid regex: {exc}") from exc


def validate_check_config(config: dict) -> None:
    """Reject a structurally invalid configuration before any check runs.

    P0 #2: a type error deep in a check produces either a crash or, worse, a
    plausible-looking failure list. Validate the whole document up front so
    the operator is told the configuration is wrong, not the project.
    """
    # Optional, for backwards compatibility with configurations written before
    # the field existed. Declaring it lets a future format change fail closed
    # on older builds instead of being silently half-interpreted.
    declared = config.get("schema_version", CHECK_CONFIG_SCHEMA_VERSION)
    if isinstance(declared, bool) or not isinstance(declared, int):
        raise ConfigError(f"schema_version must be an integer, got {declared!r}")
    if declared > CHECK_CONFIG_SCHEMA_VERSION:
        raise ConfigError(
            f"schema_version {declared} is newer than this build understands "
            f"(supports up to {CHECK_CONFIG_SCHEMA_VERSION}). Upgrade "
            f"{TOOL_NAME}, or lower the declared version."
        )
    if declared < 1:
        raise ConfigError(f"schema_version must be 1 or greater, got {declared}")

    for section, value in config.items():
        if section == "schema_version":
            continue
        if section not in CONFIG_SCHEMA:
            raise ConfigError(
                f"unknown section [{section}] — expected one of: "
                + ", ".join(sorted(CONFIG_SCHEMA))
            )
        if not isinstance(value, dict):
            raise ConfigError(f"[{section}] must be a table, got {type(value).__name__}")

        known = CONFIG_SCHEMA[section]
        for key, item in value.items():
            if key not in known:
                raise ConfigError(
                    f"unknown key {section}.{key} — expected one of: "
                    + ", ".join(sorted(known))
                )
            _check_type(f"{section}.{key}", item, known[key])


def load_check_config(project_dir: Path) -> dict | None:
    """Load release_check.toml from the project root.

    Returns None only when no configuration exists. Anything present but
    untrustworthy raises ConfigError: a broken release gate must fail closed,
    never degrade quietly into "built-in checks only".
    """
    config_path = project_dir / CHECK_CONFIG_NAME

    if not config_path.exists():
        return None
    if not config_path.is_file():
        raise ConfigError(f"{CHECK_CONFIG_NAME} exists but is not a regular file")

    try:
        import tomllib
    except ImportError as exc:  # pragma: no cover - 3.11+ is a hard requirement
        raise ConfigError(
            f"{CHECK_CONFIG_NAME} found but this Python has no tomllib (needs 3.11+)"
        ) from exc

    try:
        text = config_path.read_text(encoding="utf-8-sig")
    except UnicodeDecodeError as exc:
        # UnicodeDecodeError is a ValueError, not an OSError, so it previously
        # escaped this handler entirely and surfaced as a traceback.
        raise ConfigError(f"{CHECK_CONFIG_NAME} is not valid UTF-8: {exc}") from exc
    except OSError as exc:
        raise ConfigError(f"could not read {CHECK_CONFIG_NAME}: {exc}") from exc

    try:
        config = tomllib.loads(text)
    except ValueError as exc:
        raise ConfigError(f"could not parse {CHECK_CONFIG_NAME}: {exc}") from exc

    validate_check_config(config)
    return config


def read_project_file(project_dir: Path, rel: str) -> str:
    """Read one or more '|'-joined project files, concatenated. Missing = ''."""
    parts = []
    for piece in rel.split("|"):
        piece = piece.strip()
        if not piece:
            continue
        try:
            parts.append((project_dir / piece).read_text(encoding="utf-8", errors="replace"))
        except OSError:
            parts.append("")
    return "\n".join(parts)


def run_builtin_checks(
    project_dir: Path, report: CheckReport, *, include_secret_scan: bool = True
) -> None:
    """Universal checks that apply to any project — no config needed."""
    files = walk_check_tree(project_dir)

    # Working-tree debris.
    report.section("Working-tree debris")
    debris = [
        f for f in files
        if matches_any_pattern(f.name, DEBRIS_FILE_PATTERNS)
    ]
    report.check(
        "No session debris (patch_*/fix_*/add_*, *.bak, *.tmp, ...)",
        len(debris) == 0,
        f"{len(debris)} found: "
        + ", ".join(normalise_rel(f.relative_to(project_dir)) for f in debris[:5]),
    )
    scripts_dir = project_dir / "scripts"
    report.warn(
        "No scripts/ working-session folder",
        not scripts_dir.is_dir(),
        "scripts/ exists (packager excludes it, but consider deleting)",
    )

    # Secret scan. Skipped when packaging: the package stage scans exactly the
    # files that will ship, so running both gates would ask the same question
    # twice, of different file sets, and answer with different exit codes.
    if include_secret_scan:
        report.section("Secret scan")
        secret_scan = scan_for_secrets(project_dir, files)
        findings = secret_scan.findings
        report.check(
            "No likely secrets in tracked text files",
            len(findings) == 0,
            "; ".join(
                f"{normalise_rel(f.rel_path)}:{f.line} [{f.label}]" for f in findings[:5]
            ),
        )

        if secret_scan.unscanned:
            report.check(
                "All tracked text files could be scanned",
                len(secret_scan.unscanned_text_files()) == 0,
                "; ".join(
                    f"{normalise_rel(entry.path)} ({entry.reason})"
                    for entry in secret_scan.unscanned_text_files()[:5]
                ),
            )

    # Latest package inspection.
    report.section("Latest package")
    candidates = sorted(
        list((project_dir.parent / "packaged").glob("*.zip"))
        + list(project_dir.glob("*.zip")),
        key=lambda z: z.stat().st_mtime,
        reverse=True,
    )
    if not candidates:
        report.warn("Release ZIP found", False,
                    "no *.zip in ../packaged or project root — run `package` first")
        return

    latest = candidates[0]
    print(f"  Checking: {latest.name}")
    try:
        with zipfile.ZipFile(latest) as zf:
            names = zf.namelist()
            junk = [
                n for n in names
                if matches_any_pattern(Path(n).name, DEBRIS_FILE_PATTERNS)
            ]
            report.check("ZIP contains no debris entries", len(junk) == 0,
                         ", ".join(junk[:5]))
            if MANIFEST_ARCNAME in names:
                manifest = json.loads(zf.read(MANIFEST_ARCNAME))
                bad = 0
                for entry in manifest.get("files", []):
                    arc = entry.get("path", "")
                    if arc not in names:
                        bad += 1
                        continue
                    if hashlib.sha256(zf.read(arc)).hexdigest() != entry.get("sha256"):
                        bad += 1
                report.check(
                    f"ZIP manifest hashes verify ({len(manifest.get('files', []))} files)",
                    bad == 0,
                    f"{bad} mismatch(es)",
                )
            else:
                report.warn("ZIP has embedded manifest", False,
                            f"no {MANIFEST_ARCNAME} (older package?)")
    except (OSError, zipfile.BadZipFile, json.JSONDecodeError) as exc:
        report.check("ZIP is readable", False, str(exc))


def run_config_checks(project_dir: Path, config: dict, report: CheckReport) -> None:
    """Per-project checks driven by release_check.toml."""
    files = walk_check_tree(project_dir)

    # -- Version alignment --------------------------------------------------
    version_cfg = config.get("version", {})
    target = str(version_cfg.get("target", "")).strip()
    if target:
        report.section(f"Version identity (target: {target})")
        for rel in version_cfg.get("files", []):
            report.check(
                f"{rel} contains {target}",
                target in read_project_file(project_dir, rel),
            )

    # -- Forbidden strings/regex --------------------------------------------
    forbidden_cfg = config.get("forbidden", {})
    patterns = forbidden_cfg.get("patterns", {})
    if patterns:
        report.section("Forbidden strings")
        allow_files = set(forbidden_cfg.get("allow_files", [])) | {
            CHECK_CONFIG_NAME, Path(__file__).name,
        }
        compiled: list[tuple[str, re.Pattern[str]]] = []
        for label, pattern in patterns.items():
            try:
                compiled.append((label, re.compile(pattern)))
            except re.error as exc:
                report.check(f"forbidden pattern '{label}' compiles", False, str(exc))
        for label, regex in compiled:
            hits: list[str] = []
            for file_path in files:
                if file_path.name in allow_files:
                    continue
                text = read_text_safe(file_path)
                if text is None:
                    continue
                for match in regex.finditer(text):
                    line = text.count("\n", 0, match.start()) + 1
                    rel = normalise_rel(file_path.relative_to(project_dir))
                    hits.append(f"{rel}:{line}")
                    if len(hits) >= 5:
                        break
                if len(hits) >= 5:
                    break
            report.check(f"No forbidden '{label}'", len(hits) == 0, ", ".join(hits))

    # -- Required files -----------------------------------------------------
    required_cfg = config.get("required", {})
    required_files = required_cfg.get("files", [])
    if required_files:
        report.section("Required files")
        for rel in required_files:
            report.check(f"{rel} exists", (project_dir / rel).exists())

    # -- Required file contents ----------------------------------------------
    contains = required_cfg.get("contains", {})
    if contains:
        report.section("Required file contents")
        for rel, needles in contains.items():
            src = read_project_file(project_dir, rel)
            for needle in needles:
                report.check(f"{rel} contains '{needle}'", needle in src)

    # -- Forbidden file contents ----------------------------------------------
    not_contains = forbidden_cfg.get("contains", {})
    if not_contains:
        report.section("Forbidden file contents")
        for rel, needles in not_contains.items():
            src = read_project_file(project_dir, rel)
            for needle in needles:
                report.check(f"{rel} does not contain '{needle}'", needle not in src)

    # -- Banned paths ----------------------------------------------------------
    banned = config.get("banned", {}).get("paths", [])
    if banned:
        report.section("Banned paths")
        for rel in banned:
            clean = rel.rstrip("/")
            report.check(f"{clean} does not exist", not (project_dir / clean).exists())

    # -- requirements hygiene ---------------------------------------------------
    req_cfg = config.get("requirements", {})
    req_forbidden = req_cfg.get("forbidden", [])
    if req_forbidden:
        report.section("requirements hygiene")
        req_file = req_cfg.get("file", "requirements.txt")
        req_src = read_project_file(project_dir, req_file)
        heavy = [dep for dep in req_forbidden if dep in req_src]
        report.check(
            f"{req_file} has no forbidden deps",
            len(heavy) == 0,
            f"move to extras: {heavy}",
        )

    # -- Wheel build --------------------------------------------------------------
    wheel_cfg = config.get("wheel", {})
    if wheel_cfg.get("build", False):
        report.section("Wheel build")
        timeout = int(wheel_cfg.get("timeout", 300))
        with tempfile.TemporaryDirectory() as tmpdir:
            try:
                result = subprocess.run(
                    [sys.executable, "-m", "pip", "wheel", ".", "--no-deps",
                     "-w", tmpdir, "--quiet"],
                    capture_output=True, text=True, cwd=project_dir, timeout=timeout,
                )
            except subprocess.TimeoutExpired:
                report.check("Wheel builds successfully", False,
                             f"timed out after {timeout}s")
                return
            if result.returncode != 0:
                report.check("Wheel builds successfully", False,
                             (result.stderr or result.stdout)[:200].strip())
                return
            wheels = sorted(Path(tmpdir).glob("*.whl"))
            if not wheels:
                report.check("Wheel found after build", False, "no .whl produced")
                return
            report.check("Wheel builds successfully", True)
            with zipfile.ZipFile(wheels[0]) as zf:
                wheel_names = set(zf.namelist())
            for member in wheel_cfg.get("must_contain", []):
                present = member in wheel_names or any(
                    n.endswith("/" + member) for n in wheel_names
                )
                report.check(f"Wheel contains {member}", present)


# --------------------------------------------------------------------------
# Starter config templates (init)
# --------------------------------------------------------------------------

CHECK_CONFIG_TEMPLATE = """\
# release_check.toml — per-project rules for `project_packager.py check`.
# Delete any section you do not need. Built-in checks (debris, secrets,
# latest-package manifest verification) always run and need no config.
#
# Unknown sections and keys are rejected: a misspelled gate that silently does
# nothing is more dangerous than a stale config that fails visibly.

# Format version. A build that does not understand a newer version refuses the
# file rather than half-interpreting it.
schema_version = 1

[version]
# All listed files must contain the target version string.
target = "1.0.0"
files = ["pyproject.toml", "CHANGELOG.md"]

[forbidden]
# Regex patterns that must not appear anywhere in tracked text files.
# allow_files lists filenames exempt from the scan.
allow_files = ["CHANGELOG.md"]

[forbidden.patterns]
"personal IP" = "192\\\\.168\\\\.\\\\d+\\\\.\\\\d+"
# "legacy brand" = "(?i)old_project_name"

# Per-file substrings that must NOT appear. Key may join several files with |.
# [forbidden.contains]
# "main.py" = ["TODO: remove before release"]

[required]
# Files that must exist before releasing.
files = ["LICENSE", "README.md"]

# Per-file substrings that MUST appear. Key may join several files with |.
# [required.contains]
# "core.py|routes/api.py" = ["validate_request"]

# [banned]
# Paths that must not exist in the working tree.
# paths = ["tests/stale_copy.py", "old_stuff/"]

# [requirements]
# file = "requirements.txt"
# forbidden = ["heavy-optional-dep"]

# [wheel]
# build = true
# timeout = 300
# must_contain = ["mypackage/__init__.py", "static/app.css"]
"""

IGNORE_TEMPLATE = """\
# .packagerignore — extra exclusions for project_packager.py
# One pattern per line. Trailing / marks a directory. Patterns containing /
# match against the relative path.
#
# docs/
# *.log
# data/raw/
"""


def cmd_init(args: argparse.Namespace) -> int:
    project_dir = Path(args.project).expanduser().resolve()
    if not project_dir.is_dir():
        print(f"ERROR: not a directory: {project_dir}", file=sys.stderr)
        return 2

    wrote = []
    for name, template in ((CHECK_CONFIG_NAME, CHECK_CONFIG_TEMPLATE),
                           (IGNORE_FILE_NAME, IGNORE_TEMPLATE)):
        target = project_dir / name
        if target.exists():
            print(f"SKIP  {name} already exists")
            continue
        try:
            target.write_text(template, encoding="utf-8")
            wrote.append(name)
            print(f"WROTE {name}")
        except OSError as exc:
            print(f"ERROR: could not write {name}: {exc}", file=sys.stderr)
            return 4

    if wrote:
        print(f"\nEdit {', '.join(wrote)} to fit this project, then run:")
        print(f"  python {Path(sys.argv[0]).name} check {project_dir}")
    return 0


# --------------------------------------------------------------------------
# Reporting (packager)
# --------------------------------------------------------------------------


def format_bytes(num: int) -> str:
    """Human-readable byte formatting."""
    value = float(num)
    for unit in ("B", "KB", "MB", "GB", "TB"):
        if value < 1024 or unit == "TB":
            if unit == "B":
                return f"{int(value)} {unit}"
            return f"{value:.2f} {unit}"
        value /= 1024
    return f"{num} B"


def group_exclusions(excluded: list[Decision]) -> list[tuple[str, int]]:
    counts: dict[str, int] = {}
    for item in excluded:
        counts[item.reason.split(":", 1)[0]] = counts.get(item.reason.split(":", 1)[0], 0) + 1
    return sorted(counts.items(), key=lambda kv: kv[1], reverse=True)


def largest_files(project_dir: Path, included_files: list[Path], top: int = 5) -> list[tuple[Path, int]]:
    sized: list[tuple[Path, int]] = []
    for file_path in included_files:
        try:
            sized.append((file_path.relative_to(project_dir), file_path.stat().st_size))
        except OSError:
            continue
    sized.sort(key=lambda item: item[1], reverse=True)
    return sized[:top]


def print_summary(
    *,
    project_dir: Path,
    output_zip: Path | None,
    scan: ScanResult,
    profile: str,
    strict: bool,
    dry_run: bool,
    clean: bool,
    ignore_count: int,
    findings: list[SecretFinding],
    unscanned: list[UnscannedFile] | None = None,
    cleaned_dirs: int = 0,
    cleaned_files: int = 0,
    zip_uncompressed_bytes: int = 0,
    zip_sha256: str = "",
    manifest_embedded: bool = True,
    sidecar_written: bool = True,
) -> None:
    """Print a concise packaging report."""
    print()
    print("=" * 72)
    print(f"Project Packager v{TOOL_VERSION} — Summary")
    print("=" * 72)
    print(f"Project:       {project_dir}")
    print(f"Profile:       {profile}")
    print(f"Mode:          {'DRY RUN' if dry_run else 'WRITE'}")
    print(f"Strict mode:   {'on' if strict else 'off'}")
    print(f"Clean mode:    {'on' if clean else 'off'}")
    if ignore_count:
        print(f"{IGNORE_FILE_NAME}: {ignore_count} pattern(s) loaded")
    if output_zip:
        print(f"Output ZIP:    {output_zip}")

    print()
    print(f"Included files:          {len(scan.included_files)}")
    if scan.force_included:
        print(f"Force-included:          {len(scan.force_included)}")
    print(f"Excluded items:          {len(scan.excluded)}")
    if scan.skipped_symlinks:
        print(f"Skipped symlinks:        {len(scan.skipped_symlinks)}")
    print(f"Cleanable cache dirs:    {len(scan.clean_dirs)}")
    print(f"Cleanable cache files:   {len(scan.clean_files)}")

    if clean:
        action = "Would remove" if dry_run else "Removed"
        print(f"{action} cache dirs:      {cleaned_dirs}")
        print(f"{action} cache files:     {cleaned_files}")

    if scan.excluded:
        print()
        print("Exclusions by reason:")
        for reason, count in group_exclusions(scan.excluded):
            print(f"  {count:>5}  {reason}")

    top = largest_files(project_dir, scan.included_files)
    if top:
        print()
        print("Largest included files:")
        for rel, size in top:
            marker = "  <-- large!" if size > LARGE_FILE_WARN_BYTES else ""
            print(f"  {format_bytes(size):>12}  {normalise_rel(rel)}{marker}")

    if findings:
        print()
        print(f"!! POSSIBLE SECRETS DETECTED ({len(findings)}):")
        for finding in findings[:20]:
            print(
                f"  - {normalise_rel(finding.rel_path)}:{finding.line}"
                f"  [{finding.label}]  {finding.preview}"
            )
        if len(findings) > 20:
            print(f"  ... plus {len(findings) - 20} more finding(s)")

    if unscanned:
        print()
        print(f"NOT SCANNED for secrets ({len(unscanned)}) — these ship unexamined:")
        for entry in unscanned[:20]:
            print(f"  - {normalise_rel(entry.path)}  ({entry.reason})  "
                  f"[{entry.kind.value}]")
        if len(unscanned) > 20:
            print(f"  ... plus {len(unscanned) - 20} more file(s)")

    if output_zip and output_zip.exists() and not dry_run:
        print()
        try:
            print(f"ZIP file size:           {format_bytes(output_zip.stat().st_size)}")
        except OSError:
            pass
        print(f"Uncompressed included:   {format_bytes(zip_uncompressed_bytes)}")
        if zip_sha256:
            print(f"ZIP SHA-256:             {zip_sha256}")
            if sidecar_written:
                print(f"Hash sidecar:            {output_zip.name}.sha256")
            else:
                print("Hash sidecar:            NOT WRITTEN — recipients have "
                      "no trusted hash")
        if manifest_embedded and sidecar_written:
            print(f"Manifest embedded:       {MANIFEST_ARCNAME}")
        elif manifest_embedded:
            print(f"Manifest embedded:       {MANIFEST_ARCNAME}")
            print("Verification:            self-consistency only — no sidecar "
                  "hash was written")
        elif sidecar_written:
            print("Manifest embedded:       disabled (--no-manifest)")
            print("Verification:            partial — sidecar hash only, no "
                  "per-file manifest")
        else:
            print("Manifest embedded:       disabled (--no-manifest)")
            print("Verification:            NO VERIFICATION EVIDENCE — no "
                  "manifest and no sidecar")

    if dry_run:
        print()
        print("Dry run only: no ZIP was created and no files were deleted.")

    print("=" * 72)
    print()


def open_folder(path: Path) -> None:
    """Open a folder in the OS file manager. Best-effort."""
    try:
        if sys.platform.startswith("win"):
            os.startfile(str(path))  # type: ignore[attr-defined]
        elif sys.platform == "darwin":
            subprocess.Popen(["open", str(path)])
        else:
            subprocess.Popen(["xdg-open", str(path)])
    except OSError as exc:
        print(f"WARNING: could not open folder: {exc}", file=sys.stderr)


# --------------------------------------------------------------------------
# Subcommand: check
# --------------------------------------------------------------------------


def run_all_checks(project_dir: Path, *, include_secret_scan: bool = True) -> CheckReport:
    """Run the built-in checks, plus any configured in release_check.toml.

    `include_secret_scan` is disabled when packaging: the package stage scans
    exactly the files that will ship, which is both the honest question and a
    narrower one than scanning the whole working tree. Running both gates gave
    two different exit codes for the same problem and could block a release
    over a secret in a file the release profile excludes anyway.
    """
    report = CheckReport()
    config = load_check_config(project_dir)

    print()
    print("=" * 72)
    header = f"Release checks — {project_dir.name}"
    if config and str(config.get("version", {}).get("target", "")).strip():
        header += f" (target: {config['version']['target']})"
    print(header)
    print("=" * 72)

    run_builtin_checks(project_dir, report, include_secret_scan=include_secret_scan)
    if config:
        run_config_checks(project_dir, config, report)
    else:
        print(f"\n(No {CHECK_CONFIG_NAME} — built-in checks only. "
              f"Run `init` to create one.)")

    print()
    if report.failures:
        print(f"RESULT: FAIL — {len(report.failures)} failed, "
              f"{len(report.warnings)} warning(s), {report.passed} passed.")
    else:
        print(f"RESULT: OK — all checks passed "
              f"({report.passed} passed, {len(report.warnings)} warning(s)).")
    print()
    return report


def report_config_error(exc: ConfigError) -> None:
    print(
        f"ERROR: invalid release configuration in {CHECK_CONFIG_NAME}: {exc}\n"
        "Release gates fail closed: fix the configuration, or remove the file "
        "to run built-in checks only.",
        file=sys.stderr,
    )


def cmd_check(args: argparse.Namespace) -> int:
    project_dir = Path(args.project).expanduser().resolve()
    if not project_dir.is_dir():
        print(f"ERROR: not a directory: {project_dir}", file=sys.stderr)
        return EXIT_BAD_PROJECT
    try:
        report = run_all_checks(project_dir)
    except ConfigError as exc:
        report_config_error(exc)
        return EXIT_BAD_CONFIG
    return EXIT_PROBLEMS if report.failures else EXIT_OK


# --------------------------------------------------------------------------
# Subcommand: verify
# --------------------------------------------------------------------------


def cmd_verify(args: argparse.Namespace) -> int:
    return verify_archive(Path(args.zip).expanduser().resolve())


# --------------------------------------------------------------------------
# Subcommand: package
# --------------------------------------------------------------------------


def cmd_package(args: argparse.Namespace) -> int:
    # Apply profile presets.
    strict = args.strict
    clean = args.clean
    scan_secrets = not args.no_scan
    fail_on_secrets = args.strict
    run_checks_first = args.check
    if args.profile == "release":
        strict = True
        clean = True
        fail_on_secrets = True
        run_checks_first = True
    elif args.profile == "backup":
        scan_secrets = False
        fail_on_secrets = False

    project_dir = Path(args.project).expanduser().resolve()
    if not project_dir.exists():
        print(f"ERROR: project path does not exist: {project_dir}", file=sys.stderr)
        return EXIT_BAD_PROJECT
    if not project_dir.is_dir():
        print(f"ERROR: project path is not a directory: {project_dir}", file=sys.stderr)
        return EXIT_BAD_PROJECT

    if run_checks_first:
        try:
            report = run_all_checks(project_dir, include_secret_scan=False)
        except ConfigError as exc:
            report_config_error(exc)
            return EXIT_BAD_CONFIG
        if report.failures and not args.force:
            print(
                "ERROR: release checks failed — not packaging.\n"
                "Fix the failures or re-run with --force.",
                file=sys.stderr,
            )
            return EXIT_CHECKS_FAILED

    if args.output:
        output_dir = Path(args.output).expanduser().resolve()
    else:
        output_dir = project_dir.parent / "packaged"

    output_zip = output_dir / build_zip_name(project_dir, args.name)

    try:
        ignore_patterns, ignore_count = load_ignore_file(project_dir)
    except ConfigError as exc:
        # Deliberately not overridable by --force: --force is for judgement
        # calls about findings, not for proceeding with unusable configuration.
        print(
            f"ERROR: invalid packaging configuration in {IGNORE_FILE_NAME}: {exc}\n"
            "Packaging fails closed rather than silently dropping every "
            "project-specific exclusion. Repair, rename, or remove the file.",
            file=sys.stderr,
        )
        return EXIT_BAD_CONFIG
    rules = build_rules(
        profile=args.profile,
        strict=strict,
        ignore_patterns=ignore_patterns,
        extra_excludes=args.exclude,
        include_patterns=args.include,
    )

    scan = scan_project(
        project_dir, rules, output_dir=output_dir, output_zip=output_zip
    )

    if args.list_included:
        print()
        print("Included files:")
        for file_path in sorted(scan.included_files):
            print(f"  + {normalise_rel(file_path.relative_to(project_dir))}")

    if args.list_excluded:
        print()
        print("Excluded items:")
        for item in scan.excluded:
            print(f"  - {normalise_rel(item.rel_path)}  ({item.reason})")

    cleaned_dirs = 0
    cleaned_files = 0

    # Replacement is not atomic until v3.1.0, so a failed write can destroy a
    # good archive. Refused where that matters most, unless stated explicitly.
    if args.overwrite and fail_on_secrets and not args.force:
        print(
            "ERROR: --overwrite is refused in strict/release mode because archive "
            "replacement\nis not yet atomic (scheduled for v3.1.0): a failed write "
            "can destroy the\nexisting archive. Use a new --name, or accept the "
            "risk with --force.",
            file=sys.stderr,
        )
        return EXIT_OUTPUT_EXISTS

    if not scan_secrets and fail_on_secrets and not args.force:
        print(
            "ERROR: --no-scan disables the secret gate that strict/release mode "
            "exists to enforce.\nDrop --no-scan, or state the override "
            "explicitly with --force.",
            file=sys.stderr,
        )
        return EXIT_SECRETS

    secret_scan = SecretScanResult()
    if scan_secrets:
        secret_scan = scan_for_secrets(project_dir, scan.included_files)
    findings = secret_scan.findings

    # Release mode claims to refuse shipping secrets. It cannot honour that
    # claim for files it never read, so an unscanned text file blocks too.
    blocking_unscanned = (
        secret_scan.unscanned_text_files() if fail_on_secrets and scan_secrets else []
    )

    if (findings or blocking_unscanned) and fail_on_secrets and not args.force:
        print_summary(
            project_dir=project_dir,
            output_zip=output_zip,
            scan=scan,
            profile=args.profile,
            strict=strict,
            dry_run=args.dry_run,
            clean=clean,
            ignore_count=ignore_count,
            findings=findings,
            unscanned=secret_scan.unscanned,
            cleaned_dirs=cleaned_dirs,
            cleaned_files=cleaned_files,
            manifest_embedded=not args.no_manifest,
        )
        if findings:
            print(
                "ERROR: possible secrets found and strict/release mode is active.\n"
                "Fix the findings, exclude the files, or re-run with --force.",
                file=sys.stderr,
            )
        if blocking_unscanned:
            print(
                "ERROR: text files could not be secret-scanned and strict/release "
                "mode is active:",
                file=sys.stderr,
            )
            for entry in blocking_unscanned[:10]:
                print(f"  - {normalise_rel(entry.path)} ({entry.reason})", file=sys.stderr)
            print(
                "These files ship unexamined. Exclude them, reduce their size, "
                "or re-run with --force.",
                file=sys.stderr,
            )
        return EXIT_SECRETS

    # Preflight the reserved-name collision here, where it is already known
    # from the scan, rather than discovering it inside create_zip() after
    # cleaning has already deleted things. create_zip() checks again as
    # defence in depth.
    try:
        assert_no_reserved_collision(project_dir, scan.included_files)
    except ReservedNameError as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return EXIT_RESERVED_NAME

    # The most common refusal of all: the output already exists. Checked here,
    # before anything mutates the project. create_zip() checks again as defence
    # in depth against a race, but by then cleaning has already run.
    if output_zip.exists() and not args.overwrite and not args.dry_run:
        print(
            f"ERROR: Output already exists: {output_zip}\n"
            "Use --overwrite or choose a different --name/--output.",
            file=sys.stderr,
        )
        return EXIT_OUTPUT_EXISTS

    # Cleaning deletes files, so it happens only once every blocking condition
    # has passed. Previously it ran before the --no-scan, secret, and overwrite
    # refusals, so a command that packaged nothing still mutated the project.
    # A failed package must not change anything it was not asked to change.
    if clean:
        cleaned_dirs, cleaned_files = remove_clean_targets(scan, dry_run=args.dry_run)

        # Rescan so deleted junk no longer appears in the manifest or summary.
        if not args.dry_run and (cleaned_dirs or cleaned_files):
            scan = scan_project(
                project_dir, rules, output_dir=output_dir, output_zip=output_zip
            )

    zip_uncompressed_bytes = 0
    zip_sha256 = ""
    sidecar_written = True
    if not args.dry_run:
        manifest = None if args.no_manifest else build_manifest(project_dir, scan.included_files)
        try:
            zip_uncompressed_bytes, zip_sha256, sidecar_written = create_zip(
                project_dir,
                scan.included_files,
                output_zip,
                overwrite=args.overwrite,
                manifest=manifest,
            )
        except FileExistsError as exc:
            print(f"ERROR: {exc}", file=sys.stderr)
            return EXIT_OUTPUT_EXISTS
        except ReservedNameError as exc:
            print(f"ERROR: {exc}", file=sys.stderr)
            return EXIT_RESERVED_NAME
        except ContainmentError as exc:
            print(f"ERROR: {exc}", file=sys.stderr)
            return EXIT_CONTAINMENT
        except OSError as exc:
            print(f"ERROR: could not create ZIP: {exc}", file=sys.stderr)
            return EXIT_OS_ERROR

    print_summary(
        project_dir=project_dir,
        output_zip=output_zip,
        scan=scan,
        profile=args.profile,
        strict=strict,
        dry_run=args.dry_run,
        clean=clean,
        ignore_count=ignore_count,
        findings=findings,
        unscanned=secret_scan.unscanned,
        cleaned_dirs=cleaned_dirs,
        cleaned_files=cleaned_files,
        zip_uncompressed_bytes=zip_uncompressed_bytes,
        zip_sha256=zip_sha256,
        manifest_embedded=not args.no_manifest,
        sidecar_written=sidecar_written,
    )

    # An archive with neither a manifest nor a sidecar carries no evidence
    # about its own contents at all. That is a failure in any profile.
    if not sidecar_written and args.no_manifest and not args.dry_run:
        print(
            "ERROR: this archive has no embedded manifest and no hash sidecar, "
            "so nothing\ncan ever be verified about its contents. "
            "Fix the output location and re-run.",
            file=sys.stderr,
        )
        return EXIT_OS_ERROR

    # A release with no sidecar has no trusted hash for its recipient to check
    # against, which removes the point of shipping it as a verified artifact.
    if not sidecar_written and fail_on_secrets and not args.force:
        print(
            "ERROR: the hash sidecar could not be written, so this release has "
            "no trusted\nhash to verify against. Fix the output location, or "
            "re-run with --force.",
            file=sys.stderr,
        )
        return EXIT_OS_ERROR

    if args.open and not args.dry_run:
        open_folder(output_dir)

    return 0


# --------------------------------------------------------------------------
# CLI
# --------------------------------------------------------------------------

KNOWN_COMMANDS = {"package", "check", "verify", "init"}


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog=TOOL_NAME,
        description="Package, check, and verify project releases.",
    )
    parser.add_argument("--version", action="version",
                        version=f"{TOOL_NAME} {TOOL_VERSION}")
    sub = parser.add_subparsers(dest="command", required=True)

    # -- package --------------------------------------------------------------
    p = sub.add_parser(
        "package",
        help="Create a clean, verifiable ZIP of a project (default command).",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
    )
    p.add_argument("project", nargs="?", default=".",
                   help="Project directory to package.")
    p.add_argument("--profile", choices=("share", "release", "backup"),
                   default="share",
                   help="share (default), release (strict+clean+checks, fails "
                        "on secrets), backup (keep almost everything).")
    p.add_argument("--output", "-o", default=None,
                   help="Output folder. Defaults to ./packaged beside the project.")
    p.add_argument("--name", "-n", default=None,
                   help="Custom ZIP base name. Timestamp is still appended.")
    p.add_argument("--dry-run", action="store_true",
                   help="Show what would happen; write and delete nothing.")
    p.add_argument("--clean", action="store_true",
                   help="Delete only safe cache junk before packaging.")
    p.add_argument("--strict", action="store_true",
                   help="Extra privacy exclusions; secrets block packaging.")
    p.add_argument("--check", action="store_true",
                   help="Run release checks first; abort if any fail.")
    p.add_argument("--exclude", action="append", default=[], metavar="PATTERN",
                   help="Extra exclusion (repeatable; '/' in pattern = path match).")
    p.add_argument("--include", action="append", default=[], metavar="PATTERN",
                   help="Force-include (repeatable; overrides all exclusions).")
    p.add_argument("--no-scan", action="store_true",
                   help="Disable the secret scanner.")
    p.add_argument("--no-manifest", action="store_true",
                   help="Do not embed PACKAGE_MANIFEST.json in the ZIP.")
    p.add_argument("--force", action="store_true",
                   help="Package anyway despite secret findings or failed checks.")
    p.add_argument("--overwrite", action="store_true",
                   help="Allow overwriting an existing ZIP of the same name.")
    p.add_argument("--open", action="store_true",
                   help="Open the output folder when done.")
    p.add_argument("--list-included", action="store_true",
                   help="Print every included file.")
    p.add_argument("--list-excluded", action="store_true",
                   help="Print every excluded item with its reason.")
    p.set_defaults(func=cmd_package)

    # -- check --------------------------------------------------------------
    c = sub.add_parser(
        "check",
        help="Run universal + per-project release checks (release_check.toml).",
    )
    c.add_argument("project", nargs="?", default=".",
                   help="Project directory to check.")
    c.set_defaults(func=cmd_check)

    # -- verify --------------------------------------------------------------
    v = sub.add_parser(
        "verify",
        help="Verify a ZIP against its embedded manifest and .sha256 sidecar.",
    )
    v.add_argument("zip", help="Path to the ZIP to verify.")
    v.set_defaults(func=cmd_verify)

    # -- init --------------------------------------------------------------
    i = sub.add_parser(
        "init",
        help="Write starter release_check.toml and .packagerignore files.",
    )
    i.add_argument("project", nargs="?", default=".",
                   help="Project directory to initialise.")
    i.set_defaults(func=cmd_init)

    return parser


def main(argv: list[str] | None = None) -> int:
    # Guard against cp1252 console crashes on Windows.
    for stream in (sys.stdout, sys.stderr):
        try:
            stream.reconfigure(encoding="utf-8", errors="replace")  # type: ignore[union-attr]
        except (AttributeError, OSError):
            pass

    raw = list(argv) if argv is not None else sys.argv[1:]

    # Backward compatibility: `project_packager.py .` still packages.
    if raw and raw[0] not in KNOWN_COMMANDS and not raw[0].startswith("-"):
        raw = ["package"] + raw
    elif not raw:
        raw = ["package"]

    args = build_parser().parse_args(raw)
    return args.func(args)


if __name__ == "__main__":
    raise SystemExit(main())
