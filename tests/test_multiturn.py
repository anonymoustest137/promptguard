import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from promptguard.multiturn import (MULTITURN_PROBES, run_chat_suite,
                                   stateless_to_chat, by_category, categories)
from promptguard.harness import safe_reference_model, vulnerable_reference_model


def test_multiturn_probe_library_loaded():
    assert len(MULTITURN_PROBES) >= 5
    assert all(p.id and p.turns for p in MULTITURN_PROBES)


def test_safe_model_survives_multiturn():
    chat_fn = stateless_to_chat(safe_reference_model)
    results = run_chat_suite(chat_fn)
    assert all(not r["breached"] for r in results)


def test_vulnerable_model_breaches_some_multiturn_probes():
    chat_fn = stateless_to_chat(vulnerable_reference_model)
    results = run_chat_suite(chat_fn)
    assert any(r["breached"] for r in results)


def test_history_accumulates_across_turns():
    seen_histories = []

    def recorder(history):
        seen_histories.append(list(history))
        return "ack"

    probe = MULTITURN_PROBES[0]
    run_chat_suite(recorder, [probe])
    # the history passed on the last turn should contain all prior turns
    assert len(seen_histories[-1]) == (len(probe.turns) - 1) * 2 + 1


def test_chat_fn_exception_is_handled():
    def broken(history):
        raise RuntimeError("down")

    results = run_chat_suite(broken, MULTITURN_PROBES[:1])
    assert results[0]["error"]
    assert results[0]["breached"] is False


def test_category_helpers():
    cats = categories()
    assert "crescendo" in cats
    assert len(by_category("crescendo")) >= 1
