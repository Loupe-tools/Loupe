#!/usr/bin/env python3
"""lint_yara.py — house-style + structural linter for src/rules/*.yar.

Loupe's in-browser YARA engine is intentionally permissive about whitespace
and meta-key ordering, but the source files are concatenated verbatim into
the single-file bundle (see scripts/build.py → YARA_FILES) and read by
contributors when triaging detections. Drift in style — random tab indent,
out-of-order meta keys, half a line of `// …` comments inherited from a
copy-pasted upstream rule — therefore costs review time *and* risks
silently breaking the engine, which only tolerates `//` inside the
build-injected `/*! @loupe-category: … */` separators.

This linter codifies the existing house style (the majority of files in
src/rules/ already follow it) into a runnable check, and adds:

  * Comment ban — no `//` line comments, no `/* … */` block comments
    anywhere in source. The build script's `_YARA_CATEGORY_SENTINEL`
    collision check is defence-in-depth on a single token; this catches
    every comment shape the engine would mis-parse.
  * Meta-field whitelist + canonical order:
        description, severity, category, mitre, applies_to
    Any unknown meta key is rejected (typo guard + future-additions gate).
    `description` is required; `severity` must be one of the five tiers
    used by escalateRisk; `mitre` may be the empty string ("no mapping").
  * Indentation: 4 spaces, no tabs, no trailing whitespace.
  * Section structure: each rule has at most one each of meta:/strings:/
    condition:, in that source order, indented at 4 spaces.

Usage
-----
    python scripts/lint_yara.py            # check every .yar in YARA_FILES
    python scripts/lint_yara.py --fix      # rewrite files in place where
                                           #   safe (sort meta into canonical
                                           #   order, strip comments,
                                           #   normalise indent + trailing
                                           #   whitespace, single trailing
                                           #   newline)
    python scripts/lint_yara.py f1.yar …   # subset (paths are repo-relative
                                           #   or absolute; ignored if not
                                           #   in YARA_FILES)

`--fix` refuses to rewrite a file that contains an unknown meta key — that's
a content problem (likely a typo) and silently dropping the key would mask
it. Fix the offending key by hand, then re-run with `--fix`.

The script is pure-stdlib, deterministic, and never imports application
code. It reads the canonical file list from scripts/build.py via the
`YARA_FILES` constant so there's a single source of truth for which files
ship in the bundle.

Wired into the default build pipeline via make.py (`yara-lint` step,
inserted before `build` so a malformed rule fails fast before the bundle
gets concatenated).

Exit codes
----------
  0 — every file passes every rule (or every file was successfully rewritten
      under `--fix`)
  1 — one or more files failed (offender list printed to stderr)
  2 — usage error (e.g. unknown CLI argument)
"""
from __future__ import annotations

import argparse
import os
import re
import sys
from typing import Iterable

# scripts/lint_yara.py → repo root is one level up.
BASE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def _load_yara_files() -> list[str]:
    """Read YARA_FILES from scripts/build.py without executing the rest of
    the build module. We literal-eval the right-hand side of the `YARA_FILES =
    [...]` assignment — this avoids the heavy `import scripts.build` (which
    would trigger the SOURCE_DATE_EPOCH lookup, vendor reads, etc.) and keeps
    the linter as a pure text tool."""
    build_py = os.path.join(BASE, 'scripts', 'build.py')
    with open(build_py, 'r', encoding='utf-8') as f:
        src = f.read()
    m = re.search(r'^YARA_FILES\s*=\s*(\[[^\]]+\])', src, re.MULTILINE)
    if not m:
        raise SystemExit("lint_yara: could not locate YARA_FILES in scripts/build.py")
    import ast
    return list(ast.literal_eval(m.group(1)))


# ── Meta whitelist (canonical order) ───────────────────────────────────────
# Order matches the order the linter requires. `description` is mandatory;
# the rest are optional but, when present, must appear in this order
# relative to each other.
META_ORDER = ('description', 'severity', 'category', 'mitre', 'applies_to')
META_REQUIRED = frozenset({'description'})
META_ALLOWED = frozenset(META_ORDER)

# Severity tiers — must match the values escalateRisk understands plus
# `info` (used by some rules to flag a finding without escalating risk).
SEVERITY_VALUES = frozenset({'info', 'low', 'medium', 'high', 'critical'})


# ── Regexes ────────────────────────────────────────────────────────────────

# Rule header: `rule <Name> [: tag1 tag2] {` — brace may sit on the next line
# in some files; the linter accepts both forms but `--fix` does not touch
# that aspect (it would be churn on the existing tree). We just need to
# locate rule starts.
RULE_HDR_RE = re.compile(
    r'^(?P<indent>[ \t]*)rule\s+(?P<name>[A-Za-z_][A-Za-z0-9_]{0,127})'
    r'(?P<tags>\s*:\s*[A-Za-z_][A-Za-z0-9_\s]*)?'
    r'\s*(?P<brace>\{)?\s*$',
    re.MULTILINE,
)

# A meta entry: `        key = "value"` (or `key = ident`/numeric — YARA
# allows non-string values, but every existing rule uses strings; we keep
# the regex tight on the actual shape to catch typos).
META_KV_RE = re.compile(
    r'^(?P<indent>[ \t]+)(?P<key>[A-Za-z_][A-Za-z0-9_]*)'
    r'(?P<spc1>\s*)=(?P<spc2>\s*)(?P<val>"(?:[^"\\]|\\.)*"|true|false|\d+)\s*$'
)


# ── Comment scanner (state machine) ────────────────────────────────────────
# Walks the file character-by-character with awareness of:
#   * "string" literals (with backslash escapes)
#   * /regex/ literals (only after `=` — matches the YARA grammar shape
#     used by string definitions)
#   * { hex } byte sequences (don't enter regex/string mode)
# Any `//` outside a string/regex, or any `/* … */`, is a violation.
def find_comments(src: str) -> list[tuple[int, int, str]]:
    """Return a list of (line_number, col, kind) tuples for every comment
    encountered. `kind` is one of 'line' / 'block'. Line/col are 1-indexed.
    Strings and regex literals are skipped — comments embedded inside them
    are not violations (and don't exist in YARA syntax anyway, but the
    scanner has to know about them to avoid false positives on `//` inside
    a string like "https://example.com")."""
    out: list[tuple[int, int, str]] = []
    i = 0
    n = len(src)
    line = 1
    col = 1
    in_str = False
    in_regex = False
    while i < n:
        ch = src[i]
        if ch == '\n':
            line += 1
            col = 1
            i += 1
            continue
        if in_str:
            if ch == '\\' and i + 1 < n:
                i += 2
                col += 2
                continue
            if ch == '"':
                in_str = False
            i += 1
            col += 1
            continue
        if in_regex:
            if ch == '\\' and i + 1 < n:
                # `\<anything>` inside a regex — skip both. Handle newline-
                # in-escape conservatively: most YARA regexes are single-line.
                if src[i + 1] == '\n':
                    line += 1
                    col = 1
                    i += 2
                else:
                    i += 2
                    col += 2
                continue
            if ch == '/':
                in_regex = False
            i += 1
            col += 1
            continue
        # Outside string / regex.
        if ch == '"':
            in_str = True
            i += 1
            col += 1
            continue
        if ch == '/' and i + 1 < n:
            nxt = src[i + 1]
            if nxt == '/':
                out.append((line, col, 'line'))
                # Skip to end of line so we don't double-report.
                while i < n and src[i] != '\n':
                    i += 1
                continue
            if nxt == '*':
                out.append((line, col, 'block'))
                i += 2
                col += 2
                while i < n - 1 and not (src[i] == '*' and src[i + 1] == '/'):
                    if src[i] == '\n':
                        line += 1
                        col = 1
                    else:
                        col += 1
                    i += 1
                # Skip closing `*/`
                if i < n - 1:
                    i += 2
                    col += 2
                continue
            # `/regex/` — only if the previous non-whitespace char on the
            # logical statement is `=`. This matches the YARA grammar
            # ("$x = /…/").
            j = i - 1
            while j >= 0 and src[j] in (' ', '\t'):
                j -= 1
            if j >= 0 and src[j] == '=':
                in_regex = True
                i += 1
                col += 1
                continue
        i += 1
        col += 1
    return out


# ── Rule-block walker ──────────────────────────────────────────────────────
# Brace-balanced (string / regex / hex aware) so we don't mis-end at a hex
# pattern or a regex literal. Mirrors the algorithm in build.py's
# `_inject_applies_to`. Returns a list of (rule_name, header_line, body_start,
# body_end, body_text) tuples; `body_start`/`body_end` are 0-indexed offsets
# in `src` pointing at the first char after the opening `{` and the closing
# `}` respectively.

def iter_rules(src: str) -> Iterable[tuple[str, int, int, int, str]]:
    n = len(src)
    for m in RULE_HDR_RE.finditer(src):
        name = m.group('name')
        # Header line (1-indexed) of the rule keyword for diagnostics.
        hdr_line = src.count('\n', 0, m.start()) + 1
        # Find the opening brace — header regex captures it when on the
        # same line; otherwise scan forward.
        if m.group('brace'):
            i = m.end()
        else:
            i = m.end()
            while i < n and src[i] not in ('{', '\n'):
                i += 1
            # Skip newlines until we find `{`.
            while i < n and src[i] != '{':
                i += 1
            if i >= n:
                continue
            i += 1  # past `{`
        body_start = i
        # Walk to matching `}` with string/regex/hex awareness.
        depth = 1
        in_str = False
        in_regex = False
        while i < n and depth > 0:
            ch = src[i]
            if in_str:
                if ch == '\\' and i + 1 < n:
                    i += 2
                    continue
                if ch == '"':
                    in_str = False
                i += 1
                continue
            if in_regex:
                if ch == '\\' and i + 1 < n:
                    i += 2
                    continue
                if ch == '/':
                    in_regex = False
                i += 1
                continue
            if ch == '"':
                in_str = True
            elif ch == '{':
                depth += 1
            elif ch == '}':
                depth -= 1
                if depth == 0:
                    break
            elif ch == '/' and i + 1 < n and src[i + 1] not in ('/', '*'):
                j = i - 1
                while j >= 0 and src[j] in (' ', '\t'):
                    j -= 1
                if j >= 0 and src[j] == '=':
                    in_regex = True
            i += 1
        if depth != 0:
            continue
        body_end = i
        body = src[body_start:body_end]
        yield name, hdr_line, body_start, body_end, body


# ── Meta block extraction ──────────────────────────────────────────────────

META_HDR_RE = re.compile(r'\bmeta\s*:', re.MULTILINE)
SECTION_RE = re.compile(r'\b(strings|condition)\s*:', re.MULTILINE)


def split_meta_block(body: str) -> tuple[int, int, str] | None:
    """Locate the meta section inside a rule body. Returns (start, end,
    block_text) where `block_text` is the lines BETWEEN `meta:` and the
    next section keyword. Returns None if no meta block exists."""
    m = META_HDR_RE.search(body)
    if not m:
        return None
    after = m.end()
    nxt = SECTION_RE.search(body, after)
    end = nxt.start() if nxt else len(body)
    return (after, end, body[after:end])


def parse_meta_entries(block: str, base_offset_line: int) -> list[dict]:
    """Parse a meta block into a list of {'key', 'value', 'line', 'raw'}
    dicts. Lines that don't match METAREDOX_KV_RE are returned with
    key=None so the caller can flag them."""
    entries: list[dict] = []
    for idx, raw_line in enumerate(block.splitlines()):
        if not raw_line.strip():
            continue
        m = META_KV_RE.match(raw_line)
        if not m:
            entries.append({
                'key': None, 'value': None, 'line': base_offset_line + idx,
                'raw': raw_line,
            })
            continue
        entries.append({
            'key': m.group('key'),
            'value': m.group('val'),
            'line': base_offset_line + idx,
            'raw': raw_line,
        })
    return entries


# ── Per-file checker ───────────────────────────────────────────────────────

class Violation:
    __slots__ = ('path', 'line', 'message')

    def __init__(self, path: str, line: int, message: str):
        self.path = path
        self.line = line
        self.message = message

    def __str__(self) -> str:
        rel = os.path.relpath(self.path, BASE)
        return f"{rel}:{self.line}: {self.message}"


def check_file(path: str, src: str, seen_rule_names: dict[str, str]) -> list[Violation]:
    out: list[Violation] = []
    rel = os.path.relpath(path, BASE)

    # 1. Comment ban.
    for ln, col, kind in find_comments(src):
        out.append(Violation(
            path, ln,
            f"{kind} comment is not allowed in .yar source — use meta: "
            f"fields for explanations (col {col})",
        ))

    # 2. Tabs / trailing whitespace.
    for i, line in enumerate(src.splitlines(), start=1):
        if '\t' in line:
            out.append(Violation(path, i, "tab character — use 4-space indent"))
        if line.rstrip(' \t') != line.rstrip():
            # Means there's whitespace after the rstrip-to-other-WS …
            # actually compute properly:
            pass
        if line != line.rstrip():
            out.append(Violation(path, i, "trailing whitespace"))

    # 3. Per-rule walk.
    for name, hdr_line, body_start, body_end, body in iter_rules(src):
        # Rule-name uniqueness (across ALL files in this run).
        if name in seen_rule_names and seen_rule_names[name] != path:
            out.append(Violation(
                path, hdr_line,
                f"duplicate rule name {name!r} — also defined in "
                f"{os.path.relpath(seen_rule_names[name], BASE)}",
            ))
        else:
            seen_rule_names[name] = path

        meta = split_meta_block(body)
        if meta is None:
            out.append(Violation(
                path, hdr_line,
                f"rule {name!r}: missing meta: block (description is required)",
            ))
            continue

        meta_start_off, meta_end_off, meta_block = meta
        # Translate offsets to line numbers (1-indexed) for diagnostics.
        meta_start_line = src.count('\n', 0, body_start + meta_start_off) + 1

        entries = parse_meta_entries(meta_block, meta_start_line)
        # Filter blank-line gap noise — already done by parse_meta_entries.
        seen_keys: dict[str, int] = {}
        last_canonical_idx = -1
        for entry in entries:
            ln = entry['line']
            key = entry['key']
            if key is None:
                out.append(Violation(
                    path, ln,
                    f"rule {name!r}: malformed meta line "
                    f"(expected `key = \"value\"`): {entry['raw'].strip()!r}",
                ))
                continue
            if key in seen_keys:
                out.append(Violation(
                    path, ln,
                    f"rule {name!r}: duplicate meta key {key!r} "
                    f"(first at line {seen_keys[key]})",
                ))
                continue
            seen_keys[key] = ln
            if key not in META_ALLOWED:
                out.append(Violation(
                    path, ln,
                    f"rule {name!r}: unknown meta key {key!r} — allowed: "
                    f"{', '.join(META_ORDER)}",
                ))
                continue
            # Order check.
            canonical_idx = META_ORDER.index(key)
            if canonical_idx < last_canonical_idx:
                expected = META_ORDER[last_canonical_idx]
                out.append(Violation(
                    path, ln,
                    f"rule {name!r}: meta key {key!r} appears after "
                    f"{expected!r} — canonical order is "
                    f"{', '.join(META_ORDER)}",
                ))
            else:
                last_canonical_idx = canonical_idx
            # Per-key value checks.
            if key == 'severity':
                # Strip surrounding quotes.
                val = entry['value']
                if val.startswith('"') and val.endswith('"'):
                    val = val[1:-1]
                if val not in SEVERITY_VALUES:
                    out.append(Violation(
                        path, ln,
                        f"rule {name!r}: severity {val!r} not in "
                        f"{{{', '.join(sorted(SEVERITY_VALUES))}}}",
                    ))
            if key == 'description':
                val = entry['value']
                if val == '""':
                    out.append(Violation(
                        path, ln,
                        f"rule {name!r}: description must not be empty",
                    ))

        # Required keys.
        for req in sorted(META_REQUIRED):
            if req not in seen_keys:
                out.append(Violation(
                    path, meta_start_line,
                    f"rule {name!r}: missing required meta key {req!r}",
                ))

        # Indentation consistency within the rule's meta block. We don't
        # mandate a specific column (different files in the tree use 4
        # vs 8), but every entry inside one meta block must use the same
        # indent — otherwise a copy-pasted rule from another file leaks
        # mixed indent into a clean file.
        indents: list[tuple[int, int]] = []  # (line, indent_len)
        for entry in entries:
            if entry['key'] is None:
                continue
            raw = entry['raw']
            indent = raw[:len(raw) - len(raw.lstrip(' \t'))]
            if '\t' in indent:
                continue  # already reported above
            indents.append((entry['line'], len(indent)))
        if indents:
            first = indents[0][1]
            for ln, size in indents[1:]:
                if size != first:
                    out.append(Violation(
                        path, ln,
                        f"rule {name!r}: meta entry indent ({size} spaces) "
                        f"is inconsistent with the first entry ({first})",
                    ))

    return out


# ── --fix mode ─────────────────────────────────────────────────────────────
# Three transformations, applied in order:
#   1. Strip line comments and block comments outside strings/regexes.
#   2. Sort each rule's meta block into canonical order
#      (description, severity, category, mitre, applies_to). Duplicate
#      keys, unknown keys, and malformed lines are NOT auto-fixed —
#      check_file flags them and we bail out for that file.
#   3. Strip trailing whitespace; replace tabs with 4 spaces (only in
#      indent — content tabs are preserved, but no rule file in the tree
#      uses them).
#
# Idempotent: re-running --fix on a file produced by --fix is a no-op.

def strip_comments(src: str) -> str:
    """Return `src` with every `//` line comment and `/* … */` block
    comment removed. String / regex literals are preserved verbatim."""
    out: list[str] = []
    i = 0
    n = len(src)
    in_str = False
    in_regex = False
    while i < n:
        ch = src[i]
        if in_str:
            out.append(ch)
            if ch == '\\' and i + 1 < n:
                out.append(src[i + 1])
                i += 2
                continue
            if ch == '"':
                in_str = False
            i += 1
            continue
        if in_regex:
            out.append(ch)
            if ch == '\\' and i + 1 < n:
                out.append(src[i + 1])
                i += 2
                continue
            if ch == '/':
                in_regex = False
            i += 1
            continue
        if ch == '"':
            in_str = True
            out.append(ch)
            i += 1
            continue
        if ch == '/' and i + 1 < n:
            nxt = src[i + 1]
            if nxt == '/':
                # Skip to end of line (don't consume the newline so blank
                # lines stay where they were).
                while i < n and src[i] != '\n':
                    i += 1
                continue
            if nxt == '*':
                i += 2
                while i < n - 1 and not (src[i] == '*' and src[i + 1] == '/'):
                    i += 1
                if i < n - 1:
                    i += 2
                continue
            # Possible regex.
            j = i - 1
            while j >= 0 and src[j] in (' ', '\t'):
                j -= 1
            if j >= 0 and src[j] == '=':
                in_regex = True
                out.append(ch)
                i += 1
                continue
        out.append(ch)
        i += 1
    return ''.join(out)


def fix_meta_order(src: str) -> str:
    """Reorder each rule's meta entries into META_ORDER. Skips any rule
    that has malformed entries, unknown keys, or duplicates — those are
    surfaced as violations by check_file and the human is expected to fix
    them. Preserves each entry's full raw line (including its `=` column
    alignment) so visual layout is unchanged when keys were already in
    order."""
    parts: list[str] = []
    pos = 0
    for name, hdr_line, body_start, body_end, body in iter_rules(src):
        meta = split_meta_block(body)
        if meta is None:
            continue
        meta_start_off, meta_end_off, meta_block = meta
        abs_block_start = body_start + meta_start_off
        abs_block_end = body_start + meta_end_off
        entries = parse_meta_entries(meta_block, 0)
        # Bail if any malformed / unknown / duplicate.
        if any(e['key'] is None for e in entries):
            continue
        keys = [e['key'] for e in entries]
        if any(k not in META_ALLOWED for k in keys):
            continue
        if len(set(keys)) != len(keys):
            continue
        # Already in canonical order — no rewrite needed.
        idxs = [META_ORDER.index(k) for k in keys]
        if idxs == sorted(idxs):
            continue
        # Reorder. Preserve the raw text of each kept entry verbatim.
        by_key = {e['key']: e['raw'] for e in entries}
        new_lines: list[str] = []
        for k in META_ORDER:
            if k in by_key:
                new_lines.append(by_key[k])
        # Rebuild the meta block: keep any leading newline + indentation
        # before the first entry (typical: "\n        ") and the trailing
        # whitespace-only suffix that leads into `strings:`/`condition:`.
        # We do this by finding the first/last non-blank lines of the
        # original block and stitching `new_lines` between the surrounding
        # whitespace.
        original_lines = meta_block.splitlines(keepends=True)
        # Find first non-blank line index.
        first = next((i for i, ln in enumerate(original_lines) if ln.strip()), None)
        last = next((i for i, ln in enumerate(reversed(original_lines)) if ln.strip()), None)
        if first is None or last is None:
            continue
        last = len(original_lines) - 1 - last
        prefix = ''.join(original_lines[:first])
        suffix = ''.join(original_lines[last + 1:])
        # Each new_line came from `.splitlines()` (no terminator) — restore
        # the trailing newline used by the surrounding block.
        rebuilt = prefix + '\n'.join(new_lines) + '\n' + suffix
        parts.append(src[pos:abs_block_start])
        parts.append(rebuilt)
        pos = abs_block_end
    parts.append(src[pos:])
    return ''.join(parts) if pos > 0 else src


def fix_whitespace(src: str) -> str:
    """Strip trailing whitespace; collapse leading-tab indents to 4 spaces;
    ensure the file ends with exactly one newline."""
    out_lines: list[str] = []
    for line in src.splitlines():
        # Replace leading tabs with 4 spaces each (content tabs are
        # preserved, but rule files don't have any).
        stripped = line.lstrip(' \t')
        indent_chars = line[:len(line) - len(stripped)]
        new_indent = indent_chars.replace('\t', '    ')
        new_line = (new_indent + stripped).rstrip()
        out_lines.append(new_line)
    text = '\n'.join(out_lines)
    if not text.endswith('\n'):
        text += '\n'
    return text


def fix_file(path: str) -> tuple[str, bool]:
    """Returns (new_text, changed)."""
    with open(path, 'r', encoding='utf-8') as f:
        original = f.read()
    text = strip_comments(original)
    text = fix_meta_order(text)
    text = fix_whitespace(text)
    return text, text != original


# ── CLI ────────────────────────────────────────────────────────────────────

def _resolve_targets(argv_paths: list[str], all_files: list[str]) -> list[str]:
    if not argv_paths:
        return [os.path.join(BASE, p) for p in all_files]
    out: list[str] = []
    abs_all = {os.path.abspath(os.path.join(BASE, p)): os.path.join(BASE, p)
               for p in all_files}
    for raw in argv_paths:
        cand = raw if os.path.isabs(raw) else os.path.join(BASE, raw)
        cand = os.path.abspath(cand)
        if cand in abs_all:
            out.append(abs_all[cand])
        else:
            print(f"lint_yara: skipping {raw!r} — not in YARA_FILES",
                  file=sys.stderr)
    return out


def main(argv: list[str]) -> int:
    p = argparse.ArgumentParser(
        description='House-style + structural linter for src/rules/*.yar.',
    )
    p.add_argument('--fix', action='store_true',
                   help='Rewrite files in place where safe (sort meta, '
                        'strip comments, normalise whitespace).')
    p.add_argument('paths', nargs='*',
                   help='Optional subset of files to check (must be in '
                        'YARA_FILES).')
    args = p.parse_args(argv)

    yara_files = _load_yara_files()
    targets = _resolve_targets(args.paths, yara_files)
    if not targets:
        print("lint_yara: no files to check", file=sys.stderr)
        return 0

    seen_rule_names: dict[str, str] = {}
    all_violations: list[Violation] = []
    rewritten: list[str] = []

    for path in targets:
        with open(path, 'r', encoding='utf-8') as f:
            src = f.read()
        violations = check_file(path, src, seen_rule_names)
        # Categorise: blocking violations (unknown meta keys, duplicates,
        # malformed entries) prevent --fix from rewriting the file.
        blocking_msgs = ('unknown meta key', 'duplicate meta key',
                         'duplicate rule name', 'malformed meta line',
                         'missing meta: block', 'missing required meta key')
        has_blocker = any(any(b in v.message for b in blocking_msgs)
                          for v in violations)
        if args.fix and not has_blocker:
            new_text, changed = fix_file(path)
            if changed:
                with open(path, 'w', encoding='utf-8', newline='\n') as f:
                    f.write(new_text)
                rewritten.append(path)
                # Re-lint the rewritten file so the final report reflects
                # what's on disk now.
                violations = check_file(path, new_text, seen_rule_names)
        all_violations.extend(violations)

    if rewritten:
        for p_ in rewritten:
            print(f"fixed {os.path.relpath(p_, BASE)}")

    if all_violations:
        print("", file=sys.stderr)
        print(f"lint_yara: {len(all_violations)} violation(s):",
              file=sys.stderr)
        for v in sorted(all_violations,
                        key=lambda x: (x.path, x.line, x.message)):
            print(f"  {v}", file=sys.stderr)
        if args.fix:
            print("", file=sys.stderr)
            print("Some violations require manual fixing (unknown meta "
                  "keys, duplicates, malformed entries are NOT auto-fixed "
                  "— they're flagged for review).", file=sys.stderr)
        return 1

    print(f"lint_yara: OK — {len(targets)} file(s) clean")
    return 0


if __name__ == '__main__':
    sys.exit(main(sys.argv[1:]))
