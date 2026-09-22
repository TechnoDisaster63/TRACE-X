from pathlib import Path
import re

WORKFLOW = Path('.github/workflows/ci.yml')
LOCK = Path('requirements-ci.txt')


def test_ci_workflow_has_safe_bounded_gates():
    text = WORKFLOW.read_text(encoding='utf-8')
    assert 'pull_request:' in text and 'push:' in text
    assert 'contents: read' in text
    assert 'timeout-minutes: 10' in text
    assert 'pip install --require-hashes --only-binary=:all:' in text
    assert 'python -m pip check' in text
    assert 'python -m compileall -q core modules cli.py tests' in text
    assert 'python -m pytest -q' in text
    assert 'pull_request_target:' not in text
    assert 'permissions: write' not in text


def test_ci_actions_are_pinned_to_full_commit_shas():
    text = WORKFLOW.read_text(encoding='utf-8')
    action_refs = re.findall(r'^\s*uses:\s*[^@\s]+@([^\s]+)', text, re.MULTILINE)
    assert action_refs
    assert all(re.fullmatch(r'[0-9a-f]{40}', ref) for ref in action_refs)


def test_ci_dependency_file_is_exact_and_hash_locked():
    lines = LOCK.read_text(encoding='utf-8').splitlines()
    requirements = [line for line in lines if line and not line.startswith(('#', ' '))]
    hashes = [line.strip().removesuffix(' \\').strip() for line in lines if line.strip().startswith('--hash=sha256:')]
    assert requirements
    assert all(re.fullmatch(r'[A-Za-z0-9_.-]+==[^ ;\\]+ \\', line) for line in requirements)
    assert all(re.fullmatch(r'--hash=sha256:[0-9a-f]{64}', value) for value in hashes)
    # Every requirement carries at least one verified hash; platform/version-specific
    # wheels may add more hashes under the same requirement so the lock installs
    # across CPython versions, not only on the CI runner.
    current = None
    counts = dict.fromkeys(requirements, 0)
    for line in lines:
        if line and not line.startswith(('#', ' ')):
            current = line
        elif line.strip().startswith('--hash=sha256:'):
            assert current is not None
            counts[current] += 1
    assert all(count >= 1 for count in counts.values())
    assert len(hashes) == sum(counts.values())
