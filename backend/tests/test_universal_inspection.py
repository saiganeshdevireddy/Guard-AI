from app.services.universal_inspection import normalize_verdict


def test_shared_inspection_verdict_never_equates_no_indicators_with_safe():
    assert normalize_verdict(0) == "Unknown"
    assert normalize_verdict(1) == "Suspicious"
    assert normalize_verdict(69) == "Suspicious"
    assert normalize_verdict(70) == "Malicious"
    assert normalize_verdict(0, detected_malicious=True) == "Malicious"
