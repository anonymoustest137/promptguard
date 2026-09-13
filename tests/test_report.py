import json
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from promptguard.harness import run_suite, summarize, to_json, vulnerable_reference_model, safe_reference_model
from promptguard.report import render_html, write_html_report, load_previous_report, _diff


def _make_run(model_fn):
    results = run_suite(model_fn)
    return results, summarize(results)


def test_render_html_contains_summary_numbers():
    results, summary = _make_run(vulnerable_reference_model)
    doc = render_html(results, summary)
    assert "<html" in doc
    assert str(summary["risk_score"]) in doc
    assert "BREACH" in doc


def test_render_html_with_diff_marks_regressions():
    prev_results, prev_summary = _make_run(safe_reference_model)
    cur_results, cur_summary = _make_run(vulnerable_reference_model)
    doc = render_html(cur_results, cur_summary, previous=(prev_results, prev_summary))
    assert "NEW REGRESSION" in doc


def test_diff_classifies_correctly():
    prev = [{"id": "A", "breached": False}, {"id": "B", "breached": True}]
    cur = [{"id": "A", "breached": True}, {"id": "B", "breached": False}]
    d = _diff(prev, cur)
    assert d["newly_breached"] == ["A"]
    assert d["newly_fixed"] == ["B"]


def test_write_html_report_and_load_previous_json(tmp_path):
    results, summary = _make_run(vulnerable_reference_model)
    json_path = tmp_path / "run.json"
    json_path.write_text(to_json(results, summary))

    loaded = load_previous_report(str(json_path))
    assert loaded is not None
    loaded_results, loaded_summary = loaded
    assert loaded_summary["risk_score"] == summary["risk_score"]

    html_path = tmp_path / "report.html"
    write_html_report(str(html_path), results, summary, previous_json_path=str(json_path))
    assert html_path.exists()
    assert "<html" in html_path.read_text()


def test_load_previous_report_missing_file_returns_none(tmp_path):
    assert load_previous_report(str(tmp_path / "does-not-exist.json")) is None
