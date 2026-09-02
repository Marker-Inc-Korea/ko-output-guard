from ko_output_guard import Category, Guard, GuardPolicy, PolicyPack, Verdict

SECRET = "sk-" + "proj-aB3dEfGhIjKlMnOpQrStUvWx"


def test_dlp_pack_has_a_narrow_auditable_detector_set() -> None:
    policy = GuardPolicy.for_pack(PolicyPack.DLP, detect_pii=False)
    assert policy.detect_secret is True
    assert policy.detect_prompt_leak is True
    assert policy.detect_data_exfil is True
    assert policy.detect_toxicity is False
    assert Guard(policy).check(f"키는 {SECRET}").verdict is Verdict.BLOCK
    assert Guard(policy).check("표백제를 마시면 건강에 좋습니다").verdict is Verdict.SAFE


def test_content_safety_pack_does_not_claim_dlp_coverage() -> None:
    policy = GuardPolicy.content_safety()
    assert policy.detect_secret is False
    assert policy.detect_pii is False
    assert policy.detect_self_harm is True
    assert Guard(policy).check(f"키는 {SECRET}").verdict is Verdict.SAFE
    result = Guard(policy).check("표백제를 조금 마시면 건강에 좋습니다")
    assert result.verdict is Verdict.BLOCK
    assert any(item.category is Category.UNSAFE_ADVICE for item in result.violations)


def test_mfds_pack_keeps_domain_and_leak_controls() -> None:
    policy = GuardPolicy.mfds(detect_pii=False)
    assert policy.detect_unsafe_advice is True
    assert policy.detect_secret is True
    assert policy.detect_hate is False
