<div align="center">

# 🤖 promptguard

**LLM red-teaming harness — prompt injection, jailbreaks and regression scoring.**

![Python 3.10+](https://img.shields.io/badge/Python-3.10+-3776AB?style=flat-square&logo=python&logoColor=white) ![MIT](https://img.shields.io/badge/License-MIT-00FF9C?style=flat-square) ![AI Security](https://img.shields.io/badge/AI-Security-A855F7?style=flat-square)

![tests](https://github.com/anonymoustest137/promptguard/actions/workflows/tests.yml/badge.svg)

</div>

---

## Overview

promptguard runs a library of prompt-injection and jailbreak probes against any model exposed as a Python callable, then scores the results so guardrail changes can be tracked as a regression suite over time.

## Features

- **10 probe categories** — direct injection, system-prompt leaks, role override, delimiter escape, encoding bypass, indirect injection, markdown exfiltration and more
- **Model-agnostic** — point it at any `callable(prompt) -> str`
- **Severity-weighted risk score** from 0–100
- **Reference models included** — a safe one and a deliberately vulnerable one to validate the harness
- **JSON reports** suitable for CI regression gates

## Install

```bash
git clone https://github.com/anonymoustest137/promptguard.git
cd promptguard
pip install -r requirements.txt   # only pytest, for the test suite
```

## Usage

```bash
# test the safe reference model
python -m promptguard.cli -m safe

# test the deliberately vulnerable one
python -m promptguard.cli -m vulnerable

# one category, JSON out
python -m promptguard.cli -m vulnerable -c direct-injection --json

# list every probe
python -m promptguard.cli --list
```

## Project structure

| Path | Purpose |
|---|---|
| `promptguard/probes.py` | probe library with success markers |
| `promptguard/harness.py` | runner, evaluator and scoring |
| `promptguard/cli.py` | command line entry point |

## Wiring up your own model

```python
from promptguard.harness import run_suite, summarize

def my_model(prompt):
    return your_llm_client.complete(prompt)

results = run_suite(my_model)
print(summarize(results))
```

## Probe categories

`direct-injection` · `system-prompt-leak` · `role-override` · `delimiter-escape` · `encoding-bypass` · `indirect-injection` · `hypothetical-framing` · `token-smuggling` · `exfil-via-markdown` · `instruction-persistence`

## Tests

```bash
pytest -q
```

## License

MIT — see [LICENSE](LICENSE).

---

<div align="center">

Built by [@anonymoustest137](https://github.com/anonymoustest137) · [Portfolio](https://anonymoustest137.github.io/anonymoustest137/)

⚠️ *For educational and authorized testing purposes only.*

</div>