"""Deterministic delta debugging utilities."""

from __future__ import annotations

import math
from copy import deepcopy
from collections.abc import Callable, Sequence
from typing import Any, Mapping, TypeVar


T = TypeVar("T")


def ddmin(items: Sequence[T], predicate: Callable[[list[T]], bool]) -> list[T]:
    """Return a 1-minimal ordered subsequence that still satisfies ``predicate``.

    The caller's sequence is never modified. The initial sequence must satisfy
    the predicate; this prevents a misleading "reduction" of a non-failure.
    """

    current = list(items)
    if not predicate(list(current)):
        raise ValueError("initial input does not satisfy the reduction predicate")
    granularity = 2
    while len(current) >= 2:
        chunk_size = math.ceil(len(current) / granularity)
        reduced = False
        for start in range(0, len(current), chunk_size):
            complement = current[:start] + current[start + chunk_size :]
            if predicate(list(complement)):
                current = complement
                granularity = max(2, granularity - 1)
                reduced = True
                break
        if reduced:
            continue
        if granularity >= len(current):
            break
        granularity = min(len(current), granularity * 2)
    if current and predicate([]):
        return []
    return current


def reduce_graph(
    graph: Mapping[str, Any],
    predicate: Callable[[dict[str, Any]], bool],
    *,
    fields: Sequence[str] = (
        "requests",
        "grants",
        "approved_grants",
        "effects",
        "services",
    ),
) -> dict[str, Any]:
    """Reduce graph record arrays while preserving a caller-supplied predicate."""

    working = deepcopy(dict(graph))
    if not predicate(deepcopy(working)):
        raise ValueError("initial graph does not satisfy the reduction predicate")
    for field in fields:
        records = working.get(field)
        if not isinstance(records, list) or not records:
            continue

        def field_predicate(candidate: list[Any]) -> bool:
            trial = deepcopy(working)
            trial[field] = deepcopy(candidate)
            return predicate(trial)

        working[field] = ddmin(records, field_predicate)
    if not predicate(deepcopy(working)):  # defensive assertion at the public boundary
        raise RuntimeError("graph reducer failed to preserve its predicate")
    return working
