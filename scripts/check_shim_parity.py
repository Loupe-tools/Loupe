#!/usr/bin/env python3
"""
check_shim_parity.py — Diff the mirrored declarations across canonical
constants.js (and a handful of other host modules) and the worker shims,
fail the build on drift.

Workers don't share globals with the host bundle, so a small subset of
constants and helpers has to be re-declared inside each worker shim. Those
mirrored blocks must stay byte-equivalent (after whitespace normalisation)
with their canonical source — silent drift is a known footgun (Risk #3 of
plans/2026-04-27-loupe-perf-redos-followup-finish-v1.md).

Each shim declares its own manifest in MIRRORS below, naming the canonical
host file plus the constants / functions it mirrors. The IOC shim mirrors a
narrow IOC-extract surface (no safeRegex); the timeline + encoded shims
mirror the safeRegex / looksRedosProne block (their detector code calls
safeRegex on user-supplied regex). All three mirror `_trimPathExtGarbage`
because every worker that touches a Windows-style path needs it.

Stdlib-only, deterministic. Invoked by `python make.py verify`.
"""
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
CANON = ROOT / "src" / "constants.js"

# Per-shim parity manifest. Each entry names the mirror file plus the
# constants / functions whose bodies must stay byte-equivalent (modulo
# whitespace) with the canonical host source.
#
# `consts` and `fns` are checked against `src/constants.js` unless the
# entry overrides `canon` to a different path.
MIRRORS = [
    {
        "path": ROOT / "src" / "workers" / "encoded-worker-shim.js",
        "consts": [
            "SAFE_REGEX_MAX_PATTERN_LEN",
            "_REDOS_NESTED_QUANT_RE",
            "_REDOS_DUPLICATE_GROUP_RE",
            "_KNOWN_EXT_RE",
        ],
        "fns": [
            "looksRedosProne",
            "safeRegex",
            "_trimPathExtGarbage",
        ],
    },
    {
        "path": ROOT / "src" / "workers" / "timeline-worker-shim.js",
        "consts": [
            "SAFE_REGEX_MAX_PATTERN_LEN",
            "_REDOS_NESTED_QUANT_RE",
            "_REDOS_DUPLICATE_GROUP_RE",
        ],
        "fns": [
            "looksRedosProne",
            "safeRegex",
        ],
    },
    {
        # IOC mass-extract worker shim. Mirrors the regex-only subset of
        # constants.js the IOC core reads at module load. No safeRegex —
        # every regex literal in `extractInterestingStringsCore` is a
        # `/* safeRegex: builtin */` builtin, not a user-supplied pattern.
        "path": ROOT / "src" / "workers" / "ioc-extract-worker-shim.js",
        "consts": [
            "_KNOWN_EXT_RE",
        ],
        "fns": [
            "looksLikeIpVersionString",
            "stripDerTail",
            "_trimPathExtGarbage",
        ],
    },
]


def _extract_const(src: str, name: str):
    # Match `const NAME = <expr>;` where <expr> may span multiple lines but
    # never crosses another top-level `const`/`function` keyword.
    pat = re.compile(
        r"^const\s+" + re.escape(name) + r"\s*=\s*([\s\S]*?);[ \t]*\n",
        re.MULTILINE,
    )
    m = pat.search(src)
    return m.group(1).strip() if m else None


def _extract_fn(src: str, name: str):
    # Match `function NAME(...args) { ... }` with brace-balanced body.
    head = re.compile(
        r"^function\s+" + re.escape(name) + r"\s*\([^)]*\)\s*\{",
        re.MULTILINE,
    )
    m = head.search(src)
    if not m:
        return None
    i = m.end()
    depth = 1
    while i < len(src) and depth:
        c = src[i]
        if c == "{":
            depth += 1
        elif c == "}":
            depth -= 1
        i += 1
    return src[m.start():i]


def _normalise(s: str) -> str:
    # Collapse runs of whitespace, drop full-line `//` comments and
    # end-of-line `//` comments to keep the diff focused on semantic
    # content. The end-of-line strip is conservative — it only fires when
    # `//` is preceded by whitespace AND is not part of a URL-like
    # `://` token, which is the only `//` substring that legitimately
    # appears inside the mirrored bodies (string literals containing
    # `://` would otherwise be truncated).
    out = []
    for line in s.splitlines():
        stripped = line.strip()
        if stripped.startswith("//"):
            continue
        # Strip trailing `// …` only when preceded by whitespace and
        # NOT immediately preceded by `:` (which would mark a URL).
        m = re.search(r"(?<!:)\s+//.*$", stripped)
        if m:
            stripped = stripped[: m.start()].rstrip()
        out.append(stripped)
    joined = " ".join(out)
    return re.sub(r"\s+", " ", joined).strip()


def _check(canon_path: Path, manifest: dict) -> list[str]:
    mirror_path = manifest["path"]
    canon_src = canon_path.read_text(encoding="utf-8")
    mirror_src = mirror_path.read_text(encoding="utf-8")
    errors = []
    for name in manifest.get("consts", []):
        a = _extract_const(canon_src, name)
        b = _extract_const(mirror_src, name)
        if a is None:
            errors.append(f"{canon_path}: missing const {name}")
            continue
        if b is None:
            errors.append(f"{mirror_path}: missing const {name}")
            continue
        if _normalise(a) != _normalise(b):
            errors.append(
                f"shim drift: const {name}\n"
                f"  canonical ({canon_path}): {_normalise(a)}\n"
                f"  mirror    ({mirror_path}): {_normalise(b)}"
            )
    for name in manifest.get("fns", []):
        a = _extract_fn(canon_src, name)
        b = _extract_fn(mirror_src, name)
        if a is None:
            errors.append(f"{canon_path}: missing function {name}")
            continue
        if b is None:
            errors.append(f"{mirror_path}: missing function {name}")
            continue
        if _normalise(a) != _normalise(b):
            errors.append(
                f"shim drift: function {name}\n"
                f"  canonical ({canon_path}): {_normalise(a)[:200]}...\n"
                f"  mirror    ({mirror_path}): {_normalise(b)[:200]}..."
            )
    return errors


def main():
    all_errors = []
    # Sort by mirror path for deterministic output.
    for manifest in sorted(MIRRORS, key=lambda m: str(m["path"])):
        all_errors.extend(_check(CANON, manifest))
    if all_errors:
        sys.stderr.write("FAIL  check_shim_parity:\n")
        for e in all_errors:
            sys.stderr.write("  " + e + "\n")
        sys.stderr.write(
            "\nMirrored constant / function blocks in the worker shims must\n"
            "stay byte-equivalent (modulo whitespace) with src/constants.js.\n"
            "Each shim's manifest in scripts/check_shim_parity.py names the\n"
            "subset it mirrors. Update the offending shim(s) to match the\n"
            "canonical source.\n"
        )
        sys.exit(1)
    print(f"OK  check_shim_parity: {len(MIRRORS)} shim(s) match src/constants.js")


if __name__ == "__main__":
    main()
