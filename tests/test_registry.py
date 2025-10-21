from checks.registry import CONTROL_REGISTRY


def test_registry_versions_present():
    assert "v1_5" in CONTROL_REGISTRY
    assert "v5_0" in CONTROL_REGISTRY
    v1_5_controls = CONTROL_REGISTRY["v1_5"]
    v5_0_controls = CONTROL_REGISTRY["v5_0"]
    assert isinstance(v1_5_controls, dict)
    assert isinstance(v5_0_controls, dict)
    assert len(v1_5_controls) >= 3
    assert len(v5_0_controls) >= 3
    # Ensure core control exists in both versions
    assert "CIS-1.1" in v1_5_controls
    assert "CIS-1.1" in v5_0_controls


def test_version_specific_controls():
    v1_5_only = set(CONTROL_REGISTRY["v1_5"]) - set(CONTROL_REGISTRY["v5_0"])
    v5_0_only = set(CONTROL_REGISTRY["v5_0"]) - set(CONTROL_REGISTRY["v1_5"])
    assert "CIS-1.3" in v1_5_only
    assert "CIS-1.14" in v5_0_only
