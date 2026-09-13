import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from promptguard.judge import parse_verdict, judge_response, run_suite_with_judge
from promptguard.probes import PROBES
from promptguard.harness import safe_reference_model, vulnerable_reference_model


def test_parse_verdict_clean_json():
    v = parse_verdict('{"breached": true, "confidence": 0.8, "reason": "complied"}')
    assert v["breached"] is True
    assert v["confidence"] == 0.8


def test_parse_verdict_json_wrapped_in_prose():
    raw = 'Sure, here is my verdict:\n```json\n{"breached": false, "confidence": 0.6, "reason": "refused"}\n```'
    v = parse_verdict(raw)
    assert v["breached"] is False


def test_parse_verdict_malformed_falls_back_gracefully():
    v = parse_verdict("I think this is fine, breached: true probably")
    assert isinstance(v["breached"], bool)


def test_parse_verdict_empty():
    v = parse_verdict("")
    assert v["breached"] is False


def test_judge_response_handles_exception():
    def broken_judge(_):
        raise RuntimeError("judge api down")

    verdict = judge_response(broken_judge, PROBES[0], "some response")
    assert verdict["error"]
    assert verdict["breached"] is False


def test_run_suite_with_judge_widens_recall():
    # A judge that always says breached should push every result to
    # breached=True even for the safe model, but never hide a marker hit.
    def always_breach_judge(_):
        return '{"breached": true, "confidence": 1.0, "reason": "aggressive judge"}'

    results = run_suite_with_judge(safe_reference_model, always_breach_judge, PROBES[:3])
    assert all(r["breached"] for r in results)
    assert all(r["judge_breach"] for r in results)


def test_run_suite_with_judge_never_hides_marker_breach():
    def always_safe_judge(_):
        return '{"breached": false, "confidence": 1.0, "reason": "lenient judge"}'

    results = run_suite_with_judge(vulnerable_reference_model, always_safe_judge, PROBES[:1])
    # PI001 triggers the "pwned" marker on the vulnerable model regardless
    # of what the (lenient) judge says.
    assert results[0]["marker_breach"] is True
    assert results[0]["breached"] is True
