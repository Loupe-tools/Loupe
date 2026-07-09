"""Dispatch manifest ↔ registry ↔ dispatch ↔ caps sync gate."""
from __future__ import annotations

import os
import re
import sys

BASE = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
REPO = os.path.dirname(BASE)

# Allow importing build.manifest when invoked as a script.
if BASE not in sys.path:
    sys.path.insert(0, BASE)

from build.manifest import load_manifest, MANIFEST_PATH  # noqa: E402


def _read(rel: str) -> str:
    with open(os.path.join(REPO, rel), encoding='utf-8') as fh:
        return fh.read()


def _parse_registry_ids() -> set[str]:
    text = _read('src/renderer-registry.js')
    return set(re.findall(r"id:\s*'([^']+)'", text))


def _parse_dispatch_keys() -> set[str]:
    text = _read('src/app/app-load.js')
    block = re.search(r'_rendererDispatch:\s*\{', text)
    if not block:
        raise RuntimeError('_rendererDispatch block not found')
    start = block.end()
    depth = 1
    i = start
    while i < len(text) and depth:
        if text[i] == '{':
            depth += 1
        elif text[i] == '}':
            depth -= 1
        i += 1
    body = text[start:i - 1]
    return set(re.findall(r'^\s{4}(?:async\s+)?([a-z][a-z0-9]*)\s*\(', body, re.M))


def _parse_cap_keys() -> set[str]:
    text = _read('src/constants.js')
    block = re.search(
        r'MAX_FILE_BYTES_BY_DISPATCH:\s*Object\.freeze\(\{([\s\S]*?)\n\s*\}\)',
        text,
    )
    if not block:
        raise RuntimeError('MAX_FILE_BYTES_BY_DISPATCH not found')
    return set(re.findall(r'^\s*(\w+):', block.group(1), re.M))


def _parse_app_js_files() -> set[str]:
    text = _read('scripts/build.py')
    files: set[str] = set()
    in_app = False
    for line in text.splitlines():
        if line.strip() == 'APP_JS_FILES = [':
            in_app = True
            continue
        if in_app:
            if line.strip() == ']':
                break
            m = re.search(r"'(src/[^']+)'", line)
            if m:
                files.add(m.group(1))
    return files


def check_dispatch_sync() -> list[str]:
    """Return human-readable violation strings. Empty list means OK."""
    violations: list[str] = []
    entries = load_manifest()
    manifest_ids_set = {e.id for e in entries}
    registry_ids = _parse_registry_ids()
    dispatch_keys = _parse_dispatch_keys()
    cap_keys = _parse_cap_keys()
    app_files = _parse_app_js_files()

    missing_dispatch = sorted(registry_ids - dispatch_keys)
    extra_dispatch = sorted(dispatch_keys - registry_ids)
    if missing_dispatch:
        violations.append(
            'registry ids missing from _rendererDispatch: ' + ', '.join(missing_dispatch)
        )
    if extra_dispatch:
        violations.append(
            '_rendererDispatch keys missing from registry: ' + ', '.join(extra_dispatch)
        )

    if manifest_ids_set != registry_ids:
        only_manifest = sorted(manifest_ids_set - registry_ids)
        only_registry = sorted(registry_ids - manifest_ids_set)
        if only_manifest:
            violations.append('manifest ids not in registry: ' + ', '.join(only_manifest))
        if only_registry:
            violations.append('registry ids not in manifest: ' + ', '.join(only_registry))

    unlimited = {'plaintext', 'folder'}
    for e in entries:
        if e.id in unlimited:
            continue
        if e.id not in cap_keys:
            violations.append(
                f'{e.id}: no MAX_FILE_BYTES_BY_DISPATCH row in constants.js'
            )
        if e.module and e.module not in app_files:
            violations.append(
                f'{e.id}: module {e.module} not listed in APP_JS_FILES (build.py)'
            )

    orphan_caps = sorted(cap_keys - registry_ids - {'_DEFAULT'})
    if orphan_caps:
        violations.append(
            'orphan MAX_FILE_BYTES_BY_DISPATCH keys (not in registry): '
            + ', '.join(orphan_caps)
        )

    return violations


def main() -> int:
    if not os.path.isfile(MANIFEST_PATH):
        print(f'ERROR  manifest not found: {MANIFEST_PATH}', file=sys.stderr)
        return 2
    try:
        violations = check_dispatch_sync()
    except (ValueError, RuntimeError) as exc:
        print(f'ERROR  {exc}', file=sys.stderr)
        return 2

    if not violations:
        entries = load_manifest()
        print(
            f'OK    dispatch sync: {len(entries)} manifest entries; '
            f'registry, dispatch, and caps aligned.'
        )
        return 0

    print(f'FAIL  dispatch sync: {len(violations)} issue(s)', file=sys.stderr)
    for v in violations:
        print(f'  • {v}', file=sys.stderr)
    print(
        '\nSee scripts/dispatch-manifest.toml and scripts/gen_dispatch_manifest.py.',
        file=sys.stderr,
    )
    return 1


if __name__ == '__main__':
    sys.exit(main())