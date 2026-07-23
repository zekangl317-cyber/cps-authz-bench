"""Seeded generation of internally consistent service/effect graphs."""

from __future__ import annotations

import random
from typing import Any

from .oracle import MAX_EFFECTS, MAX_REQUESTS, MAX_SERVICES
from .seeds import require_seed


_OPERATIONS = ("activate", "calibrate", "read", "reset", "write")
_SAFETY_CLASSES = ("operational", "safety-critical", "telemetry")


def _bounded_integer(name: str, value: Any, minimum: int, maximum: int) -> int:
    if isinstance(value, bool) or not isinstance(value, int):
        raise ValueError(f"{name} must be an integer")
    if not minimum <= value <= maximum:
        raise ValueError(f"{name} must be between {minimum} and {maximum}")
    return value


def generate_graph(
    *,
    seed: int,
    service_count: int = 5,
    effect_count: int = 8,
    request_count: int = 10,
) -> dict[str, Any]:
    """Generate a deterministic, authorization-consistent benchmark graph."""

    seed = require_seed(seed)
    service_count = _bounded_integer(
        "service_count", service_count, 1, MAX_SERVICES
    )
    effect_count = _bounded_integer("effect_count", effect_count, 1, MAX_EFFECTS)
    request_count = _bounded_integer(
        "request_count", request_count, 0, MAX_REQUESTS
    )

    rng = random.Random(seed)
    services = [
        {
            "id": f"service-{index:03d}",
            "version": 1 + rng.randrange(1, 4),
            "zone": f"zone-{rng.randrange(3):02d}",
        }
        for index in range(service_count)
    ]
    effects = []
    for index in range(effect_count):
        owner = services[index % service_count]["id"]
        effects.append(
            {
                "id": f"effect-{index:03d}",
                "owner": owner,
                "resource": f"device-{index:03d}",
                "operation": _OPERATIONS[rng.randrange(len(_OPERATIONS))],
                "safety_class": _SAFETY_CLASSES[rng.randrange(len(_SAFETY_CLASSES))],
            }
        )

    grants: set[tuple[str, str]] = set()
    requests = []
    services_by_id = {item["id"]: item for item in services}
    for index in range(request_count):
        effect = effects[rng.randrange(len(effects))]
        caller = services[rng.randrange(len(services))]["id"]
        grants.add((caller, effect["id"]))
        requests.append(
            {
                "id": f"request-{index:03d}",
                "caller": caller,
                "service": effect["owner"],
                "effect": effect["id"],
                "service_version": services_by_id[effect["owner"]]["version"],
            }
        )

    grant_records = [
        {"principal": principal, "effect": effect}
        for principal, effect in sorted(grants)
    ]
    return {
        "schema_version": "cps-authz-graph/v1",
        "seed": seed,
        "services": services,
        "effects": effects,
        "approved_grants": grant_records,
        "grants": [dict(item) for item in grant_records],
        "requests": requests,
        "ground_truth": {
            "schema_version": "cps-authz-oracle/v1",
            "findings": [],
        },
    }
