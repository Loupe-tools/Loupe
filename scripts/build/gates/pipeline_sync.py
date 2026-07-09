"""Pipeline orchestration sync gate — make.py STEPS vs on-disk scripts."""
from __future__ import annotations

import importlib.util
import os

_REPO = os.path.dirname(os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))
_MAKE_PY = os.path.join(_REPO, 'make.py')

_POST_BUILD_STEP_IDS = frozenset({
    'build', 'release-test-api', 'fuzz-path-leak', 'contract',
})


def _load_make():
    spec = importlib.util.spec_from_file_location('loupe_make', _MAKE_PY)
    if spec is None or spec.loader is None:
        raise RuntimeError(f'failed to load make.py spec from {_MAKE_PY}')
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def check_pipeline_sync() -> list[str]:
    violations: list[str] = []
    make = _load_make()

    for step_id in make.DEFAULT_STEPS:
        if step_id not in make.STEPS:
            violations.append(f'DEFAULT_STEPS entry {step_id!r} missing from STEPS')

    for step_id in make.TEST_PIPELINE_GATES:
        if step_id in _POST_BUILD_STEP_IDS:
            violations.append(f'TEST_PIPELINE_GATES must not include post-build step {step_id!r}')
        if step_id not in make.STEPS:
            violations.append(f'TEST_PIPELINE_GATES entry {step_id!r} missing from STEPS')
            continue
        _label, script, _extra = make.STEPS[step_id]
        path = os.path.join(_REPO, script)
        if not os.path.isfile(path):
            violations.append(f'{step_id}: script not found: {script}')

    expected = tuple(make.TEST_PIPELINE_GATES)
    from build.pipeline import pre_build_step_ids  # noqa: WPS433

    if pre_build_step_ids() != expected:
        violations.append(
            'pipeline.py pre_build_step_ids() drifted from make.py TEST_PIPELINE_GATES'
        )

    from build.pipeline import gate_script_path, pre_build_gates  # noqa: WPS433

    for step_id, script, _extra in pre_build_gates():
        if not gate_script_path(script).is_file():
            violations.append(
                f'pipeline.py cannot resolve {step_id} script: {script}'
            )

    return violations