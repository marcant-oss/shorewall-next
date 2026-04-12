"""Configuration validation."""

from __future__ import annotations

from shorewall_nft.config.parser import ShorewalConfig


def validate_config(config: ShorewalConfig) -> list[str]:
    """Validate a parsed config and return a list of warnings."""
    warnings: list[str] = []

    if not config.zones:
        warnings.append("No zones defined")

    if not config.interfaces:
        warnings.append("No interfaces defined")

    if not config.policy:
        warnings.append("No policies defined")

    # Check that all interface zones exist
    zone_names = {line.columns[0] for line in config.zones if line.columns}
    for line in config.interfaces:
        if line.columns and line.columns[0] not in zone_names:
            warnings.append(f"Interface {line.columns[1]} references unknown zone {line.columns[0]} at {line.file}:{line.lineno}")

    return warnings
