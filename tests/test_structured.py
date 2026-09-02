from ko_output_guard import Guard, GuardPolicy, Verdict

SECRET = "sk-" + "proj-aB3dEfGhIjKlMnOpQrStUvWx"


def guard() -> Guard:
    return Guard(GuardPolicy.dlp(detect_pii=False))


def test_nested_secret_is_replaced_and_path_is_reported() -> None:
    result = guard().check_structured(
        {"tool": "send_email", "arguments": {"body": f"운영 키: {SECRET}"}}
    )

    assert result.verdict is Verdict.BLOCK
    assert result.forward_safe is False
    assert result.findings[0].path == "/arguments/body"
    assert SECRET not in result.safe_value["arguments"]["body"]
    telemetry = result.to_safe_telemetry().model_dump(mode="json")
    assert SECRET not in str(telemetry)
    assert telemetry["findings"][0]["finding_index"] == 0
    assert telemetry["findings"][0]["path_depth"] == 2
    assert "path" not in telemetry["findings"][0]


def test_safe_structure_preserves_shape() -> None:
    value = {"answer": "처리가 완료되었습니다", "count": 3, "items": [True, None]}
    result = guard().check_structured(value)
    assert result.forward_safe is True
    assert result.safe_value == value
    assert result.scanned_strings == 4


def test_secret_in_mapping_key_fails_closed_without_telemetry_leak() -> None:
    result = guard().check_structured({SECRET: "value"})
    assert result.verdict is Verdict.BLOCK
    assert result.failure_code == "structure_unsafe_key"
    assert result.safe_value == "[BLOCKED: structured output could not be inspected safely]"
    telemetry = result.to_safe_telemetry().model_dump(mode="json")
    assert SECRET not in str(telemetry)


def test_cycles_fail_closed_without_recursion() -> None:
    value: list[object] = []
    value.append(value)
    result = guard().check_structured(value)
    assert result.verdict is Verdict.BLOCK
    assert result.failure_code == "structure_cycle"


def test_node_limit_fails_closed() -> None:
    policy = GuardPolicy.dlp(detect_pii=False, max_structure_nodes=2)
    result = Guard(policy).check_structured(["one", "two"])
    assert result.verdict is Verdict.BLOCK
    assert result.failure_code == "structure_too_many_nodes"
