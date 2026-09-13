"""Built-in adapters for popular model providers.

These wrap each provider's SDK/HTTP API behind the plain
`callable(prompt) -> str` interface run_suite expects, and a
`callable(history) -> str` interface for run_chat_suite. The provider SDKs
are optional - promptguard's core has zero runtime dependencies, so these
imports are deferred into each factory function and raise a clear error if
the SDK isn't installed, rather than being imported at module load time.

Usage:
    from promptguard.adapters import openai_model
    my_model = openai_model(system_prompt="You are a support agent.")
    results = run_suite(my_model)
"""


def _missing(package, extra_hint=""):
    raise ImportError(
        f"The '{package}' package is required for this adapter. "
        f"Install it with: pip install {package}{extra_hint}"
    )


def openai_model(model="gpt-4o-mini", system_prompt=None, client=None, **kwargs):
    """Return a callable(prompt) -> str backed by the OpenAI Chat Completions API."""
    try:
        from openai import OpenAI
    except ImportError:
        _missing("openai")

    client = client or OpenAI()

    def _call(prompt):
        messages = []
        if system_prompt:
            messages.append({"role": "system", "content": system_prompt})
        messages.append({"role": "user", "content": prompt})
        r = client.chat.completions.create(model=model, messages=messages, **kwargs)
        return r.choices[0].message.content

    return _call


def openai_chat_model(model="gpt-4o-mini", system_prompt=None, client=None, **kwargs):
    """Return a callable(history) -> str for multiturn.run_chat_suite."""
    try:
        from openai import OpenAI
    except ImportError:
        _missing("openai")

    client = client or OpenAI()

    def _chat(history):
        messages = []
        if system_prompt:
            messages.append({"role": "system", "content": system_prompt})
        messages.extend(history)
        r = client.chat.completions.create(model=model, messages=messages, **kwargs)
        return r.choices[0].message.content

    return _chat


def anthropic_model(model="claude-sonnet-4-5", system_prompt=None, max_tokens=1024,
                     client=None, **kwargs):
    """Return a callable(prompt) -> str backed by the Anthropic Messages API."""
    try:
        import anthropic
    except ImportError:
        _missing("anthropic")

    client = client or anthropic.Anthropic()

    def _call(prompt):
        r = client.messages.create(
            model=model,
            max_tokens=max_tokens,
            system=system_prompt or "",
            messages=[{"role": "user", "content": prompt}],
            **kwargs,
        )
        return r.content[0].text

    return _call


def anthropic_chat_model(model="claude-sonnet-4-5", system_prompt=None,
                          max_tokens=1024, client=None, **kwargs):
    """Return a callable(history) -> str for multiturn.run_chat_suite."""
    try:
        import anthropic
    except ImportError:
        _missing("anthropic")

    client = client or anthropic.Anthropic()

    def _chat(history):
        r = client.messages.create(
            model=model,
            max_tokens=max_tokens,
            system=system_prompt or "",
            messages=history,
            **kwargs,
        )
        return r.content[0].text

    return _chat


def ollama_model(model="llama3", host="http://localhost:11434", system_prompt=None,
                  timeout=60):
    """Return a callable(prompt) -> str backed by a local Ollama server.
    Uses urllib so no extra dependency is needed beyond the stdlib."""
    import json
    import urllib.request

    def _call(prompt):
        full_prompt = f"{system_prompt}\n\n{prompt}" if system_prompt else prompt
        payload = json.dumps({
            "model": model, "prompt": full_prompt, "stream": False,
        }).encode()
        req = urllib.request.Request(
            f"{host}/api/generate", data=payload,
            headers={"Content-Type": "application/json"},
        )
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            data = json.loads(resp.read().decode())
        return data.get("response", "")

    return _call


def http_json_model(url, prompt_field="prompt", response_path=("response",),
                     extra_payload=None, headers=None, timeout=60):
    """Generic adapter for any self-hosted HTTP endpoint that accepts
    {prompt_field: prompt} JSON and returns a JSON body containing the
    response somewhere. response_path is a tuple of keys/indices walked
    to pull the string out, e.g. ("choices", 0, "text")."""
    import json
    import urllib.request

    def _call(prompt):
        payload = dict(extra_payload or {})
        payload[prompt_field] = prompt
        req = urllib.request.Request(
            url, data=json.dumps(payload).encode(),
            headers={"Content-Type": "application/json", **(headers or {})},
        )
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            data = json.loads(resp.read().decode())
        cur = data
        for key in response_path:
            cur = cur[key]
        return cur

    return _call
