import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from promptguard.probes import PROBES
from promptguard.mutate import mutate_probe, mutate_all, expand_suite, MUTATIONS


def test_all_mutations_registered_and_callable():
    probe = PROBES[0]
    for name in MUTATIONS:
        mutated = mutate_probe(probe, name, seed=42)
        assert mutated.prompt
        assert mutated.parent_id == probe.id
        assert mutated.mutation == name
        assert mutated.severity == probe.severity
        assert mutated.success_markers == probe.success_markers


def test_unknown_mutation_raises():
    try:
        mutate_probe(PROBES[0], "not-a-real-mutation")
        assert False, "expected ValueError"
    except ValueError:
        pass


def test_mutate_all_produces_cartesian_product():
    subset = PROBES[:2]
    names = ["leetspeak", "base64-wrap"]
    out = mutate_all(subset, mutation_names=names)
    assert len(out) == len(subset) * len(names)


def test_expand_suite_includes_originals_by_default():
    subset = PROBES[:2]
    out = expand_suite(subset, mutation_names=["leetspeak"])
    assert len(out) == len(subset) * 2  # originals + 1 mutation each
    ids = {p.id for p in out}
    assert subset[0].id in ids


def test_expand_suite_can_exclude_originals():
    subset = PROBES[:2]
    out = expand_suite(subset, mutation_names=["leetspeak"], include_originals=False)
    assert len(out) == len(subset)
    assert all(p.parent_id for p in out)


def test_base64_wrap_roundtrips_content():
    import base64
    probe = PROBES[0]
    mutated = mutate_probe(probe, "base64-wrap")
    # the original prompt should be recoverable from the encoded payload
    encoded = mutated.prompt.split(": ")[-1]
    assert base64.b64decode(encoded).decode() == probe.prompt
