"""Shared JS source lists for build gates — parsed from scripts/build.py."""
from __future__ import annotations

import ast
import os

_SCRIPTS = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
REPO = os.path.dirname(_SCRIPTS)
BUILD_PY = os.path.join(_SCRIPTS, 'build.py')


def _extract_str_list(node: ast.AST) -> list[str]:
    if not isinstance(node, ast.List):
        return []
    out: list[str] = []
    for elt in node.elts:
        if isinstance(elt, ast.Constant) and isinstance(elt.value, str):
            out.append(elt.value)
    return out


def _parse_build_lists() -> tuple[list[str], list[str]]:
    with open(BUILD_PY, encoding='utf-8') as fh:
        tree = ast.parse(fh.read(), filename=BUILD_PY)
    early: list[str] = []
    app: list[str] = []
    for stmt in tree.body:
        if not isinstance(stmt, ast.Assign):
            continue
        for target in stmt.targets:
            if not isinstance(target, ast.Name):
                continue
            if target.id == 'EARLY_JS_FILES':
                early = _extract_str_list(stmt.value)
            elif target.id == 'APP_JS_FILES':
                app = _extract_str_list(stmt.value)
    if not early or not app:
        raise RuntimeError(
            'gate_sources: failed to parse EARLY_JS_FILES / APP_JS_FILES from build.py'
        )
    return early, app


_TEST_API_FILE = 'src/app/app-test-api.js'


def gate_js_files(*, test_api: bool = False) -> list[str]:
    """Return EARLY_JS_FILES + APP_JS_FILES (optionally with test-api mixin)."""
    early, app = _parse_build_lists()
    files = early + list(app)
    if (test_api or os.path.isfile(os.path.join(REPO, _TEST_API_FILE))) and (
        _TEST_API_FILE not in files
    ):
        files.append(_TEST_API_FILE)
    return files


def read_js(rel: str) -> str:
    with open(os.path.join(REPO, rel), encoding='utf-8') as fh:
        return fh.read()


def is_comment_line(line: str) -> bool:
    stripped = line.lstrip()
    return stripped.startswith('//') or stripped.startswith('*')