from shorewall_nft_stagelab import dos_safety
from shorewall_nft_stagelab.config import _is_dos_target_allowed


def test_allowlist_accepts_subnet():
    assert _is_dos_target_allowed("10.0.0.5", ["10.0.0.0/24"]) is True
    assert _is_dos_target_allowed("10.0.0.0/28", ["10.0.0.0/24"]) is True


def test_allowlist_rejects_outside():
    assert _is_dos_target_allowed("10.0.1.5", ["10.0.0.0/24"]) is False
    assert _is_dos_target_allowed("10.0.0.5", []) is False  # empty = nothing allowed


def test_rate_cap_env_override(monkeypatch):
    monkeypatch.setenv("STAGELAB_DOS_RATE_CAP_PPS", "5000000")
    assert dos_safety.rate_cap_pps() == 5_000_000
    monkeypatch.setenv("STAGELAB_DOS_RATE_CAP_PPS", "not-an-int")
    assert dos_safety.rate_cap_pps() == dos_safety.DOS_DEFAULT_RATE_CAP_PPS
    monkeypatch.delenv("STAGELAB_DOS_RATE_CAP_PPS", raising=False)
    assert dos_safety.rate_cap_pps() == dos_safety.DOS_DEFAULT_RATE_CAP_PPS
