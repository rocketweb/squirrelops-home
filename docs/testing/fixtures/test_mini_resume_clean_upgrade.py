"""Non-root verification of exact failed-run recovery admission."""
import copy
import importlib.util
import json
from pathlib import Path
import subprocess
import sys

import pytest

spec = importlib.util.spec_from_file_location('resume', Path(__file__).with_name('mini_resume_clean_upgrade.py'))
resume = importlib.util.module_from_spec(spec)
spec.loader.exec_module(resume)


def failure():
    return dict(command=['/bin/bash', '/Library/SquirrelOps/sensor/uninstall.sh', '--remove-data'],
                exit=1, stdout='[!] Could not safely remove the sensor service identity.\n')


def test_recognizes_only_reviewed_failed_uninstall():
    resume.validate_failed_records([failure()])
    for records in ([], [failure(), failure()], [{**failure(), 'exit': 0}],
                    [{**failure(), 'stdout': 'different failure'}],
                    [failure(), dict(command=['/usr/sbin/installer', '-pkg', 'old.pkg'])]):
        with pytest.raises(RuntimeError):
            resume.validate_failed_records(records)


def test_original_archive_scope_and_content_are_rechecked(tmp_path):
    saved = {}
    for index, source in enumerate(resume.EXPECTED_SOURCES):
        payload = tmp_path / f'payload-{index:02}'
        payload.mkdir()
        (payload / 'synthetic').write_text(f'original-{index}')
        saved[source] = resume.base.manifest(payload)
    resume.verify_saved_payloads(tmp_path, saved)
    with pytest.raises(RuntimeError):
        resume.verify_saved_payloads(tmp_path, dict(reversed(list(saved.items()))))
    with pytest.raises(RuntimeError):
        resume.verify_saved_payloads(tmp_path, {**saved, '/unapproved': {}})
    changed = copy.deepcopy(saved)
    changed[next(iter(changed))]['synthetic']['sha256'] = 'wrong'
    with pytest.raises(RuntimeError):
        resume.verify_saved_payloads(tmp_path, changed)
    (tmp_path / 'payload-00' / 'synthetic').write_text('changed')
    with pytest.raises(RuntimeError):
        resume.verify_saved_payloads(tmp_path, saved)


def test_plan_has_no_side_effects_and_no_upgrade_claim():
    result = subprocess.run([sys.executable, spec.origin], capture_output=True, text=True, check=True)
    plan = json.loads(result.stdout)
    assert plan['mode'] == 'plan_only'
    assert plan['original_archive'] == str(resume.PRIOR)
    assert plan['upgrade_run'] is False


def test_resume_pins_all_code_and_reuses_original_install_path():
    root = Path(spec.origin).parents[3]
    fixtures = Path(spec.origin).parent
    wrapper = (fixtures / 'resume-mini-clean-upgrade.sh').read_text()
    for name in ('mini_clean_upgrade.py', 'mini_resume_clean_upgrade.py'):
        assert f'verify_digest {name} {resume.base.digest(fixtures / name)}\n' in wrapper
    assert resume.FIX_SHA == resume.base.digest(root / 'scripts/pkg/uninstall.sh')
    assert f'verify_digest uninstall-fixed.sh {resume.FIX_SHA}\n' in wrapper
    source = Path(spec.origin).read_text()
    assert source.index('verify_saved_payloads(PRIOR, snapshots)') < source.index('self.mutated = True')
    assert source.index('validate_failed_records(records)') < source.index('self.mutated = True')
    assert "open('x')" in source
    assert 'self.finish_uninstall_and_install(snapshots, baseline)' in source
    assert 'self.installing' not in source  # main uses session.installing to avoid racing PackageKit
