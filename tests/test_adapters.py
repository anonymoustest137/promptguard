import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from promptguard import adapters


def test_openai_adapter_raises_clear_error_without_sdk():
    try:
        adapters.openai_model()
        assert False, "expected ImportError when openai isn't installed"
    except ImportError as exc:
        assert "openai" in str(exc)


def test_anthropic_adapter_raises_clear_error_without_sdk():
    try:
        adapters.anthropic_model()
        assert False, "expected ImportError when anthropic isn't installed"
    except ImportError as exc:
        assert "anthropic" in str(exc)


def test_ollama_adapter_is_pure_stdlib_and_returns_callable():
    # Doesn't hit the network - just verifies construction doesn't need
    # any third-party package and returns a plain callable.
    model_fn = adapters.ollama_model(model="llama3", host="http://localhost:11434")
    assert callable(model_fn)


def test_http_json_model_is_pure_stdlib_and_returns_callable():
    model_fn = adapters.http_json_model("http://localhost:9999/generate")
    assert callable(model_fn)
