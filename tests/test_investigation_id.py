"""
Regression tests for the Investigation ID architecture fix.

Bug fixed: investigation_id was generated from an in-memory, module-level
counter that reset to 0 every time a new Python process started. Since the
CLI is a fresh process per invocation, every separate `python cli.py
analyze <file>` call produced the same ID (TX-000001).

Fix: core.utils.next_investigation_id() persists the counter to a small
state file (output/.tx_investigation_counter) guarded by a simple
cross-platform lock file, so IDs stay unique across separate process runs
without requiring a database.
"""
import glob
import os
import subprocess
import sys

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from core.pipeline import analyze_email, analyze_campaign, save_investigation, save_report_text
from core.utils import next_investigation_id

DATA = os.path.join(os.path.dirname(__file__), "..", "test_data")
PROJECT_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))


def p(rel):
    return os.path.join(DATA, rel)


def _isolated_state_dir(tmp_path):
    """Each test gets its own counter-state directory so tests never
    interfere with each other or with a developer's real output/ dir."""
    d = str(tmp_path / "output")
    os.makedirs(d, exist_ok=True)
    return d


# ---------------------------------------------------------------------
# 1. Two different emails -> different Investigation IDs
# ---------------------------------------------------------------------

def test_two_different_emails_get_different_ids(tmp_path):
    state_dir = _isolated_state_dir(tmp_path)
    id1 = next_investigation_id(state_dir=state_dir)
    id2 = next_investigation_id(state_dir=state_dir)
    assert id1 != id2


# ---------------------------------------------------------------------
# 2. Same email analyzed twice -> different Investigation IDs
# ---------------------------------------------------------------------

def test_same_email_analyzed_twice_gets_different_ids():
    r1 = analyze_email(p("legitimate/legit_newsletter.eml"))
    r2 = analyze_email(p("legitimate/legit_newsletter.eml"))
    assert r1["investigation_id"] != r2["investigation_id"]
    # Content should be identical except for the ID / timing fields
    assert r1["file_sha256"] == r2["file_sha256"]


# ---------------------------------------------------------------------
# 3. analyze-folder equivalent -> every email gets a unique ID
# ---------------------------------------------------------------------

def test_batch_analysis_every_email_gets_unique_id():
    eml_files = sorted(glob.glob(os.path.join(DATA, "**", "*.eml"), recursive=True))
    assert len(eml_files) >= 10
    ids = []
    for path in eml_files:
        result = analyze_email(path)
        ids.append(result["investigation_id"])
    assert len(ids) == len(set(ids)), "duplicate investigation_id found across a batch run"


# ---------------------------------------------------------------------
# 4. Same pipeline execution -> M01-M10 preserve the same Investigation ID
# ---------------------------------------------------------------------

def test_investigation_id_propagates_through_entire_pipeline():
    result = analyze_email(p("phishing/lookalike_domain.eml"))
    inv_id = result["investigation_id"]
    # The ID must appear, unchanged, in the M10 report section too.
    assert result["report"]["investigation_id"] == inv_id
    assert result["report"]["header"]["investigation_id"] == inv_id


# ---------------------------------------------------------------------
# 5. Report ID matches the investigation ID (propagation into saved output)
# ---------------------------------------------------------------------

def test_saved_json_and_report_filenames_match_investigation_id(tmp_path):
    result = analyze_email(p("phishing/replyto_mismatch.eml"))
    inv_id = result["investigation_id"]
    json_path = save_investigation(result, output_dir=str(tmp_path / "output"))
    text_path = save_report_text(result, reports_dir=str(tmp_path / "reports"))
    assert os.path.basename(json_path) == f"{inv_id}.json"
    assert os.path.basename(text_path) == f"{inv_id}.txt"


# ---------------------------------------------------------------------
# 6. Repeated executions -> no collision, across many calls
# ---------------------------------------------------------------------

def test_many_repeated_calls_never_collide(tmp_path):
    state_dir = _isolated_state_dir(tmp_path)
    ids = [next_investigation_id(state_dir=state_dir) for _ in range(50)]
    assert len(ids) == len(set(ids))


def test_id_persists_and_increments_across_separate_process_invocations(tmp_path):
    """This is the EXACT bug scenario: separate OS processes (like separate
    CLI invocations) must not reset the counter to zero."""
    state_dir = str(tmp_path / "output")
    os.makedirs(state_dir, exist_ok=True)

    script = (
        "import sys; sys.path.insert(0, %r); "
        "from core.utils import next_investigation_id; "
        "print(next_investigation_id(state_dir=%r))"
    ) % (PROJECT_ROOT, state_dir)

    ids = []
    for _ in range(3):
        proc = subprocess.run([sys.executable, "-c", script], capture_output=True, text=True, cwd=PROJECT_ROOT)
        assert proc.returncode == 0, proc.stderr
        ids.append(proc.stdout.strip())

    assert ids == ["TX-000001", "TX-000002", "TX-000003"]
    assert len(set(ids)) == 3


def test_cli_separate_invocations_produce_different_ids(tmp_path):
    """End-to-end reproduction of the originally-reported bug via the real
    CLI, run as three separate OS processes against an isolated output dir."""
    work_dir = tmp_path / "cli_run"
    work_dir.mkdir()
    os.makedirs(work_dir / "output", exist_ok=True)
    os.makedirs(work_dir / "reports", exist_ok=True)

    samples = [
        p("phishing/lookalike_domain.eml"),
        p("phishing/phishing_paypal_lookalike.eml"),
        p("phishing/replyto_mismatch.eml"),
    ]

    found_ids = []
    for sample in samples:
        proc = subprocess.run(
            [sys.executable, os.path.join(PROJECT_ROOT, "cli.py"), "analyze", sample],
            capture_output=True, text=True, cwd=str(work_dir),
        )
        assert proc.returncode == 0, proc.stderr
        for line in proc.stdout.splitlines():
            if line.startswith("TX-"):
                found_ids.append(line.strip())
                break

    assert len(found_ids) == 3
    assert len(set(found_ids)) == 3, f"duplicate investigation IDs across separate CLI processes: {found_ids}"


# ---------------------------------------------------------------------
# Existing-behaviour regression: campaign batch analysis also yields
# unique IDs and each investigation's report still carries its own ID.
# ---------------------------------------------------------------------

def test_analyze_campaign_assigns_unique_ids_and_correct_report_linkage():
    files = sorted(glob.glob(os.path.join(DATA, "campaign", "*.eml")))
    batch = analyze_campaign(files)
    ids = [inv["investigation_id"] for inv in batch["investigations"]]
    assert len(ids) == len(set(ids))
    for inv in batch["investigations"]:
        assert inv["report"]["investigation_id"] == inv["investigation_id"]
