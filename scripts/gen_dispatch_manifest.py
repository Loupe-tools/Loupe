#!/usr/bin/env python3
"""Generate ``scripts/dispatch-manifest.toml`` from live source tables.

Reads ``RendererRegistry.ENTRIES``, ``App._rendererDispatch``, and
``MAX_FILE_BYTES_BY_DISPATCH`` and emits a manifest that mirrors the
current bundle. Run after adding a format handler to refresh the
manifest, then commit the TOML alongside registry/dispatch edits.

Usage:
    python scripts/gen_dispatch_manifest.py            # write manifest
    python scripts/gen_dispatch_manifest.py --check    # diff vs on-disk
"""
from __future__ import annotations

import argparse
import os
import re
import sys

BASE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
MANIFEST_PATH = os.path.join(BASE, 'scripts', 'dispatch-manifest.toml')

CLASS_MODULE = {
    'FolderRenderer': 'src/renderers/folder-renderer.js',
    'MsgRenderer': 'src/renderers/msg-renderer.js',
    'MsiRenderer': 'src/renderers/msi-renderer.js',
    'DocBinaryRenderer': 'src/renderers/doc-renderer.js',
    'XlsxRenderer': 'src/renderers/xlsx-renderer.js',
    'PptBinaryRenderer': 'src/renderers/ppt-renderer.js',
    'MsixRenderer': 'src/renderers/msix-renderer.js',
    'BrowserExtRenderer': 'src/renderers/browserext-renderer.js',
    'JarRenderer': 'src/renderers/jar-renderer.js',
    'DocxParser': 'src/docx-parser.js',
    'PptxRenderer': 'src/renderers/pptx-renderer.js',
    'OdtRenderer': 'src/renderers/odt-renderer.js',
    'OdpRenderer': 'src/renderers/odp-renderer.js',
    'SqliteRenderer': 'src/renderers/sqlite-renderer.js',
    'EvtxRenderer': 'src/renderers/evtx-renderer.js',
    'LnkRenderer': 'src/renderers/lnk-renderer.js',
    'PdfRenderer': 'src/renderers/pdf-renderer.js',
    'OneNoteRenderer': 'src/renderers/onenote-renderer.js',
    'IsoRenderer': 'src/renderers/iso-renderer.js',
    'DmgRenderer': 'src/renderers/dmg-renderer.js',
    'PkgRenderer': 'src/renderers/pkg-renderer.js',
    'OsascriptRenderer': 'src/renderers/osascript-renderer.js',
    'PlistRenderer': 'src/renderers/plist-renderer.js',
    'PgpRenderer': 'src/renderers/pgp-renderer.js',
    'X509Renderer': 'src/renderers/x509-renderer.js',
    'PeRenderer': 'src/renderers/pe-renderer.js',
    'ElfRenderer': 'src/renderers/elf-renderer.js',
    'MachoRenderer': 'src/renderers/macho-renderer.js',
    'ImageRenderer': 'src/renderers/image-renderer.js',
    'CabRenderer': 'src/renderers/cab-renderer.js',
    'RarRenderer': 'src/renderers/rar-renderer.js',
    'SevenZRenderer': 'src/renderers/seven7-renderer.js',
    'NpmRenderer': 'src/renderers/npm-renderer.js',
    'ZipRenderer': 'src/renderers/zip-renderer.js',
    'RtfRenderer': 'src/renderers/rtf-renderer.js',
    'SvgRenderer': 'src/renderers/svg-renderer.js',
    'HtaRenderer': 'src/renderers/hta-renderer.js',
    'HtmlRenderer': 'src/renderers/html-renderer.js',
    'EmlRenderer': 'src/renderers/eml-renderer.js',
    'UrlShortcutRenderer': 'src/renderers/url-renderer.js',
    'IcsRenderer': 'src/renderers/ics-renderer.js',
    'RegRenderer': 'src/renderers/reg-renderer.js',
    'InfSctRenderer': 'src/renderers/inf-renderer.js',
    'IqySlkRenderer': 'src/renderers/iqy-slk-renderer.js',
    'ScfRenderer': 'src/renderers/scf-renderer.js',
    'LibraryMsRenderer': 'src/renderers/library-ms-renderer.js',
    'MofRenderer': 'src/renderers/mof-renderer.js',
    'XsltRenderer': 'src/renderers/xslt-renderer.js',
    'WasmRenderer': 'src/renderers/wasm-renderer.js',
    'PcapRenderer': 'src/renderers/pcap-renderer.js',
    'WsfRenderer': 'src/renderers/wsf-renderer.js',
    'ClickOnceRenderer': 'src/renderers/clickonce-renderer.js',
    'CsvRenderer': 'src/renderers/csv-renderer.js',
    'JsonRenderer': 'src/renderers/json-renderer.js',
    'PlainTextRenderer': 'src/renderers/plaintext-renderer.js',
}

# Registry id → primary dispatch alias (handler delegates).
DISPATCH_ALIASES = {
    'xls': 'xlsx',
    'ods': 'xlsx',
}


def _read(rel: str) -> str:
    with open(os.path.join(BASE, rel), encoding='utf-8') as fh:
        return fh.read()


def _parse_registry() -> list[tuple[str, str]]:
    text = _read('src/renderer-registry.js')
    # Order-preserving scan: every ENTRIES object carries id + className.
    entries = []
    seen: set[str] = set()
    for m in re.finditer(
        r"id:\s*'([^']+)'[\s\S]*?className:\s*'([^']+)'",
        text,
    ):
        id_, cls = m.group(1), m.group(2)
        if id_ in seen:
            continue
        seen.add(id_)
        entries.append((id_, cls))
    return entries


def _parse_dispatch_keys() -> set[str]:
    text = _read('src/app/app-load.js')
    block = re.search(r'_rendererDispatch:\s*(?:Object\.assign\s*\([^,]+,\s*)?\{', text)
    if not block:
        raise SystemExit('Could not find _rendererDispatch block')
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
    keys = set()
    for m in re.finditer(r'^\s{4}(?:async\s+)?([a-z][a-z0-9]*)\s*\(', body, re.M):
        keys.add(m.group(1))
    return keys


def _parse_caps() -> dict[str, int]:
    text = _read('src/constants.js')
    block = re.search(
        r'MAX_FILE_BYTES_BY_DISPATCH:\s*Object\.freeze\(\{([\s\S]*?)\n\s*\}\)',
        text,
    )
    if not block:
        raise SystemExit('Could not find MAX_FILE_BYTES_BY_DISPATCH')
    caps: dict[str, int] = {}
    for m in re.finditer(
        r'(\w+):\s*(Number\.POSITIVE_INFINITY|'
        r'((?:\d+_?\d*)(?:\s*\*\s*1024\s*\*\s*1024)+))',
        block.group(1),
    ):
        if m.group(2) == 'Number.POSITIVE_INFINITY':
            caps[m.group(1)] = 2**63 - 1
        else:
            expr = m.group(3).replace('_', '')
            caps[m.group(1)] = eval(expr, {'__builtins__': {}})  # noqa: S307
    return caps


def _format_max_bytes(val: int) -> str:
    if val >= 2**62:
        return 'inf'
    return str(val)


def generate_toml() -> str:
    registry = _parse_registry()
    caps = _parse_caps()
    override_keys = _parse_dispatch_keys()
    lines = [
        '# Loupe dispatch manifest — single source of truth for format handlers.',
        '# Generated by scripts/gen_dispatch_manifest.py — edit registry/dispatch',
        '# in src/ first, then regenerate and commit this file.',
        '#',
        '# Fields:',
        '#   id              — dispatch key (RendererRegistry.ENTRIES[].id)',
        '#   class           — global renderer class name',
        '#   module          — primary source file under src/',
        '#   max_bytes       — PARSER_LIMITS.MAX_FILE_BYTES_BY_DISPATCH cap',
        '#   alias_of        — optional; dispatch handler delegates to this id',
        '#   dispatch_override — true when app-load.js uses a bespoke handler',
        '',
    ]
    for id_, cls in registry:
        module = CLASS_MODULE.get(cls, '')
        cap = caps.get(id_)
        if cap is None and id_ not in ('plaintext', 'folder'):
            cap = caps.get('_DEFAULT', 128 * 1024 * 1024)
        alias = DISPATCH_ALIASES.get(id_)
        override = id_ in override_keys
        lines.append('[[dispatch]]')
        lines.append(f'id = "{id_}"')
        lines.append(f'class = "{cls}"')
        lines.append(f'module = "{module}"')
        if cap is not None:
            lines.append(f'max_bytes = {_format_max_bytes(cap)}')
        if alias:
            lines.append(f'alias_of = "{alias}"')
        if override:
            lines.append('dispatch_override = true')
        lines.append('')
    return '\n'.join(lines).rstrip() + '\n'


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument('--check', action='store_true',
                        help='Exit 1 if on-disk manifest differs from generated')
    args = parser.parse_args()

    generated = generate_toml()
    if args.check:
        if not os.path.isfile(MANIFEST_PATH):
            print(f'FAIL  {MANIFEST_PATH} missing', file=sys.stderr)
            return 1
        on_disk = open(MANIFEST_PATH, encoding='utf-8').read()
        if on_disk != generated:
            print('FAIL  dispatch-manifest.toml is stale — run:', file=sys.stderr)
            print('        python scripts/gen_dispatch_manifest.py', file=sys.stderr)
            return 1
        print('OK    dispatch-manifest.toml matches generated output')
        return 0

    with open(MANIFEST_PATH, 'w', encoding='utf-8') as fh:
        fh.write(generated)
    print(f'Wrote {MANIFEST_PATH} ({len(generated)} bytes)')
    return 0


if __name__ == '__main__':
    sys.exit(main())