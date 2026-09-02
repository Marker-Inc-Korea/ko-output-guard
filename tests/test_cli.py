import json

import pytest

from ko_output_guard import GuardPolicy
from ko_output_guard.cli import main


def dlp_policy_path(tmp_path):
    path = tmp_path / "dlp-policy.json"
    path.write_text(GuardPolicy.dlp(detect_pii=False).model_dump_json(), "utf-8")
    return path


def test_cli_text_output_excludes_source_by_default(capsys) -> None:
    secret = "sk-" + "proj-aB3dEfGhIjKlMnOpQrStUvWx"
    assert main(["check", secret, "--pack", "dlp"]) == 2
    payload = json.loads(capsys.readouterr().out)
    assert payload["verdict"] == "block"
    assert secret not in json.dumps(payload)


def test_cli_structured_returns_content_free_finding_metadata(tmp_path, capsys) -> None:
    secret = "sk-" + "proj-aB3dEfGhIjKlMnOpQrStUvWx"
    source = json.dumps({"arguments": {"token": secret}})
    policy = dlp_policy_path(tmp_path)
    assert main(["structured", source, "--policy", str(policy)]) == 2
    payload = json.loads(capsys.readouterr().out)
    assert payload["findings"][0]["finding_index"] == 0
    assert payload["findings"][0]["path_depth"] == 2
    assert secret not in json.dumps(payload)


def test_cli_structured_includes_paths_only_when_requested(tmp_path, capsys) -> None:
    secret = "sk-" + "proj-aB3dEfGhIjKlMnOpQrStUvWx"
    source = json.dumps({"arguments": {"token": secret}})
    policy = dlp_policy_path(tmp_path)
    assert main(
        ["structured", source, "--policy", str(policy), "--include-text"]
    ) == 2
    payload = json.loads(capsys.readouterr().out)
    assert payload["finding_paths"] == ["/arguments/token"]
    assert secret not in json.dumps(payload)


def test_cli_rejects_malformed_structured_json_without_stdout(capsys) -> None:
    with pytest.raises(SystemExit) as exc_info:
        main(["structured", "{"])
    assert exc_info.value.code == 2
    captured = capsys.readouterr()
    assert captured.out == ""
    assert "Traceback" not in captured.err
