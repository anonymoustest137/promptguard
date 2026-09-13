"""promptguard CLI."""
import argparse
import sys

from . import __version__
from .harness import (run_suite, summarize, to_json,
                      safe_reference_model, vulnerable_reference_model)
from .probes import PROBES, by_category, categories
from .mutate import expand_suite, MUTATIONS
from .report import write_html_report

MODELS = {"safe": safe_reference_model, "vulnerable": vulnerable_reference_model}
RED = "\033[31m"
GREEN = "\033[32m"
YELLOW = "\033[33m"
RESET = "\033[0m"


def _resolve_model(args):
    """Resolve -m into a callable(prompt) -> str. Supports the two built-in
    reference models, or dotted-path 'module:function' / 'module.function'
    for a user-supplied model (including adapters in promptguard.adapters)."""
    if args.model in MODELS:
        return MODELS[args.model]

    spec = args.model
    if ":" in spec:
        module_name, attr = spec.split(":", 1)
    elif "." in spec:
        module_name, attr = spec.rsplit(".", 1)
    else:
        raise SystemExit(
            f"Unknown model '{spec}'. Use 'safe', 'vulnerable', or "
            f"'module.path:callable_name' pointing at your own model function."
        )
    import importlib
    mod = importlib.import_module(module_name)
    fn = getattr(mod, attr)
    return fn() if getattr(fn, "_promptguard_factory", False) else fn


def _print_text_report(results, summary, version_label):
    print("promptguard v" + __version__ + " - " + version_label + "\n")
    for r in results:
        mark = RED + "BREACH" + RESET if r["breached"] else GREEN + "  ok  " + RESET
        extra = ""
        if r.get("judge_verdict") and r.get("marker_breach") != r.get("judge_breach"):
            extra = YELLOW + "  (judge disagreed with markers)" + RESET
        print("[" + mark + "] " + r["id"] + " " + r["category"] + extra)
    print("\nprobes: " + str(summary["probes_run"]) +
          "  breaches: " + str(summary["breaches"]) +
          "  pass rate: " + str(summary["pass_rate"]) + "%" +
          "  risk: " + str(summary["risk_score"]) + "/100")


def main(argv=None):
    ap = argparse.ArgumentParser(prog="promptguard",
                                 description="LLM prompt-injection red-team harness")
    ap.add_argument("-m", "--model", default="safe",
                    help="reference model ('safe'/'vulnerable'), or "
                         "'module.path:function' for your own model")
    ap.add_argument("-c", "--category", choices=categories(),
                    help="only run one probe category")
    ap.add_argument("--list", action="store_true", help="list all probes")
    ap.add_argument("--json", action="store_true", help="print full JSON report")
    ap.add_argument("--out", metavar="PATH", help="write the JSON report to a file")
    ap.add_argument("--html", metavar="PATH", help="write an HTML report to a file")
    ap.add_argument("--diff", metavar="PATH",
                    help="compare against a previous --out JSON report; "
                         "used to render regressions in the HTML report and "
                         "to fail on new breaches (see --fail-on-regression)")
    ap.add_argument("--mutate", metavar="NAME", nargs="*",
                    help="expand the suite with mutated variants of every "
                         f"probe; choices: {', '.join(sorted(MUTATIONS))} "
                         "(omit a value to apply all mutations)")
    ap.add_argument("--multiturn", action="store_true",
                    help="also run the multi-turn probe suite (requires a "
                         "chat-shaped model; stateless models are adapted "
                         "automatically but won't have real memory)")
    ap.add_argument("--judge", metavar="MODEL",
                    help="enable LLM-as-judge evaluation using this model "
                         "spec ('module.path:function'), in addition to "
                         "marker matching")
    ap.add_argument("--fail-above", type=int, metavar="N", default=None,
                    help="exit with status 1 if risk_score > N (for CI gates)")
    ap.add_argument("--fail-on-regression", action="store_true",
                    help="exit with status 1 if --diff shows any newly "
                         "breached probe versus the previous run")
    ap.add_argument("--version", action="version", version=__version__)
    args = ap.parse_args(argv)

    if args.list:
        for p in PROBES:
            tag = f" (mutation of {p.parent_id})" if p.parent_id else ""
            print(p.id + "  [" + p.severity + "]  " + p.category + tag)
        return 0

    probes = by_category(args.category) if args.category else list(PROBES)
    if args.mutate is not None:
        names = args.mutate or None
        probes = expand_suite(probes, mutation_names=names)

    model_fn = _resolve_model(args)

    if args.judge:
        from .judge import run_suite_with_judge
        judge_fn = _resolve_model(argparse.Namespace(model=args.judge))
        results = run_suite_with_judge(model_fn, judge_fn, probes)
    else:
        results = run_suite(model_fn, probes)

    summary = summarize(results)

    mt_results, mt_summary = None, None
    if args.multiturn:
        from .multiturn import MULTITURN_PROBES, run_chat_suite, stateless_to_chat
        chat_fn = stateless_to_chat(model_fn)
        mt_results = run_chat_suite(chat_fn, MULTITURN_PROBES)
        mt_summary = summarize([
            {**r, "severity": r["severity"]} for r in mt_results
        ])

    if args.out or args.json:
        payload = to_json(results, summary)
        if args.out:
            with open(args.out, "w", encoding="utf-8") as f:
                f.write(payload)
        if args.json:
            print(payload)

    if args.html:
        write_html_report(args.html, results, summary, previous_json_path=args.diff,
                          title=f"promptguard report - {args.model}")
        print(f"HTML report written to {args.html}", file=sys.stderr)

    if not args.json:
        _print_text_report(results, summary, "model: " + args.model)
        if mt_summary:
            print("\n-- multi-turn probes --")
            _print_text_report(mt_results, mt_summary, "model: " + args.model)

    exit_code = 0
    if args.fail_above is not None and summary["risk_score"] > args.fail_above:
        print(f"\nGuardrail regression: risk {summary['risk_score']} > "
              f"threshold {args.fail_above}. Failed: {summary['failed_ids']}",
              file=sys.stderr)
        exit_code = 1

    if args.fail_on_regression and args.diff:
        from .report import load_previous_report, _diff
        previous = load_previous_report(args.diff)
        if previous:
            d = _diff(previous[0], results)
            if d["newly_breached"]:
                print(f"\nNew regressions vs {args.diff}: {d['newly_breached']}",
                      file=sys.stderr)
                exit_code = 1

    return exit_code


if __name__ == "__main__":
    sys.exit(main())
