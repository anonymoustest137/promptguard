"""promptguard CLI."""
import argparse

from . import __version__
from .harness import (run_suite, summarize, to_json,
                      safe_reference_model, vulnerable_reference_model)
from .probes import PROBES, by_category, categories

MODELS = {"safe": safe_reference_model, "vulnerable": vulnerable_reference_model}
RED = "\033[31m"
GREEN = "\033[32m"
RESET = "\033[0m"


def main():
    ap = argparse.ArgumentParser(prog="promptguard",
                                 description="LLM prompt-injection red-team harness")
    ap.add_argument("-m", "--model", default="safe", choices=sorted(MODELS),
                    help="reference model to test")
    ap.add_argument("-c", "--category", choices=categories(),
                    help="only run one probe category")
    ap.add_argument("--list", action="store_true", help="list all probes")
    ap.add_argument("--json", action="store_true")
    ap.add_argument("--version", action="version", version=__version__)
    args = ap.parse_args()

    if args.list:
        for p in PROBES:
            print(p.id + "  [" + p.severity + "]  " + p.category)
        return

    probes = by_category(args.category) if args.category else PROBES
    results = run_suite(MODELS[args.model], probes)
    summary = summarize(results)

    if args.json:
        print(to_json(results, summary))
        return

    print("promptguard v" + __version__ + " - model: " + args.model + "\n")
    for r in results:
        mark = RED + "BREACH" + RESET if r["breached"] else GREEN + "  ok  " + RESET
        print("[" + mark + "] " + r["id"] + " " + r["category"])
    print("\nprobes: " + str(summary["probes_run"]) +
          "  breaches: " + str(summary["breaches"]) +
          "  pass rate: " + str(summary["pass_rate"]) + "%" +
          "  risk: " + str(summary["risk_score"]) + "/100")


if __name__ == "__main__":
    main()
