"""Shared seed-domain validation."""

from __future__ import annotations

from typing import Any


MIN_SEED = -(2**63)
MAX_SEED = 2**63 - 1


def is_seed(value: Any) -> bool:
    """Return whether ``value`` is a non-Boolean signed 64-bit integer."""

    return (
        isinstance(value, int)
        and not isinstance(value, bool)
        and MIN_SEED <= value <= MAX_SEED
    )


def require_seed(value: Any, *, label: str = "seed") -> int:
    """Return a valid seed or raise a boundary-friendly error."""

    if not is_seed(value):
        raise ValueError(f"{label} must be a signed 64-bit integer")
    return value
