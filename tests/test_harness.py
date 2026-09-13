import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from promptguard.harness import (run_suite, summarize, evaluate,
                                 safe_reference_model, vulnerable_reference_model)
from promptguard.probes import PROBES, by_category, categories


def test_probe_library_loaded():
    assert len(PROBES) >= 10
    assert all(p.id and p.prompt for p in PROBES)


def test_safe_model_passes_everything():
    results = run_suite(safe_reference_model)
    s = summarize(results)
    assert s["breaches"] == 0
    assert s["pass_rate"] == 100
    assert s["risk_score"] == 0


def test_vulnerable_model_is_caught():
    results = run_suite(vulnerable_reference_model)
    s = summarize(results)
    assert s["breaches"] > 0
    assert s["risk_score"] > 0


def test_evaluate_marker_matching():
    probe = PROBES[0]
    assert evaluate(probe, "PWNED") is True
    assert evaluate(probe, "I cannot do that") is False


def test_category_filter():
    cats = categories()
    assert "direct-injection" in cats
    assert len(by_category("direct-injection")) >= 1


def test_model_exception_is_handled():
    def broken(_):
        raise RuntimeError("api down")
    results = run_suite(broken, PROBES[:2])
    assert all(r["error"] for r in results)
    assert all(not r["breached"] for r in results)
