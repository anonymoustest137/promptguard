import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from promptguard.cli import main


def test_cli_safe_model_exits_zero(capsys):
    code = main(["-m", "safe"])
    assert code == 0
    out = capsys.readouterr().out
    assert "risk: 0/100" in out


def test_cli_vulnerable_model_reports_breaches(capsys):
    code = main(["-m", "vulnerable"])
    assert code == 0
    out = capsys.readouterr().out
    assert "BREACH" in out


def test_cli_fail_above_gates_exit_code(capsys):
    code = main(["-m", "vulnerable", "--fail-above", "0"])
    assert code == 1
    code = main(["-m", "safe", "--fail-above", "0"])
    assert code == 0


def test_cli_list(capsys):
    code = main(["--list"])
    assert code == 0
    out = capsys.readouterr().out
    assert "PI001" in out


def test_cli_category_filter(capsys):
    code = main(["-m", "vulnerable", "-c", "direct-injection", "--json"])
    assert code == 0
    out = capsys.readouterr().out
    assert '"probes_run": 1' in out


def test_cli_mutate_expands_suite(capsys):
    code = main(["-m", "vulnerable", "--mutate", "leetspeak", "--json"])
    assert code == 0
    out = capsys.readouterr().out
    assert '"probes_run": 40' in out  # 20 originals + 20 leetspeak mutants


def test_cli_html_and_out_write_files(tmp_path):
    out_path = tmp_path / "run.json"
    html_path = tmp_path / "run.html"
    code = main(["-m", "vulnerable", "--out", str(out_path), "--html", str(html_path)])
    assert code == 0
    assert out_path.exists()
    assert html_path.exists()


def test_cli_dotted_model_resolution(tmp_path, capsys):
    module_path = tmp_path / "custom_model.py"
    module_path.write_text(
        "def my_model(prompt):\n    return 'PWNED' if 'pwned' in prompt.lower() else 'no'\n"
    )
    sys.path.insert(0, str(tmp_path))
    try:
        code = main(["-m", "custom_model:my_model", "--json"])
        assert code == 0
        out = capsys.readouterr().out
        assert '"breaches": 1' in out
    finally:
        sys.path.remove(str(tmp_path))
        sys.modules.pop("custom_model", None)


def test_cli_unknown_model_exits_with_message():
    try:
        main(["-m", "not-a-real-model-spec-without-dots"])
        assert False, "expected SystemExit"
    except SystemExit:
        pass
