"""Unit tests for shorewall_nft_stagelab.tuning — no root, no real /proc."""

from unittest.mock import MagicMock, call, mock_open, patch

import pytest

from shorewall_nft_stagelab.tuning import apply_rss, apply_sysctls, set_irq_affinity

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

_PROC_INTERRUPTS_WITH_ETH0 = """\
           CPU0       CPU1
  42:          0          0   PCI-MSI 524288-edge      eth0-TxRx-0
  43:          0          0   PCI-MSI 524289-edge      eth0-TxRx-1
  44:         12          0   PCI-MSI 524290-edge      eth1-TxRx-0
"""

_PROC_INTERRUPTS_NO_ETH0 = """\
           CPU0       CPU1
  44:         12          0   PCI-MSI 524290-edge      eth1-TxRx-0
"""


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------


def test_apply_rss_invokes_ethtool():
    with patch("subprocess.run") as mock_run:
        mock_run.return_value = MagicMock(returncode=0, stderr="")
        apply_rss("eth0", 8)
    mock_run.assert_called_once_with(
        ["ethtool", "-L", "eth0", "combined", "8"],
        check=True,
        text=True,
        capture_output=True,
    )


def test_apply_rss_rejects_invalid_iface():
    with pytest.raises(ValueError):
        apply_rss("bad iface", 8)


def test_set_irq_affinity_parses_proc_and_writes():
    write_calls = []

    def fake_write_text(self, content):
        write_calls.append((str(self), content))

    with (
        patch("builtins.open", mock_open(read_data=_PROC_INTERRUPTS_WITH_ETH0)),
        patch("pathlib.Path.write_text", fake_write_text),
    ):
        set_irq_affinity("eth0", [4, 5])

    assert len(write_calls) == 2
    for _path, content in write_calls:
        assert content == "4,5"


def test_set_irq_affinity_no_matching_iface():
    with (
        patch("builtins.open", mock_open(read_data=_PROC_INTERRUPTS_NO_ETH0)),
        pytest.raises(RuntimeError, match="No IRQ lines found"),
    ):
        set_irq_affinity("eth0", [0])


def test_apply_sysctls_iterates():
    settings = {
        "net.netfilter.nf_conntrack_max": "4194304",
        "net.core.rmem_max": "134217728",
        "net.core.wmem_max": "134217728",
    }
    with patch("subprocess.run") as mock_run:
        mock_run.return_value = MagicMock(returncode=0, stderr="")
        apply_sysctls(settings)

    assert mock_run.call_count == 3
    expected_calls = [
        call(
            ["sysctl", "-w", f"{k}={v}"],
            check=True,
            text=True,
            capture_output=True,
        )
        for k, v in settings.items()
    ]
    mock_run.assert_has_calls(expected_calls, any_order=False)
