"""Named, deterministic graph mutations."""

from __future__ import annotations

import json
import random
from copy import deepcopy
from typing import Any, Mapping

from .model import BenchmarkCase, _canonical_case_id
from .oracle import MAX_VERSION, evaluate_oracle, require_graph
from .seeds import require_seed


MUTATION_NAMES = (
    "privilege_expansion",
    "confused_deputy",
    "stale_version",
    "orphan_effect",
    "parser_corruption",
)
_EXPECTED_RULES = {
    "privilege_expansion": "PRIVILEGE_EXPANSION",
    "confused_deputy": "CONFUSED_DEPUTY",
    "stale_version": "STALE_VERSION",
    "orphan_effect": "ORPHAN_EFFECT",
    "parser_corruption": "PARSER_CORRUPTION",
}


def _canonical_payload(graph: Mapping[str, Any]) -> bytes:
    return (
        json.dumps(graph, ensure_ascii=False, allow_nan=False, sort_keys=True, separators=(",", ":"))
        + "\n"
    ).encode("utf-8")


def _allocate_identifier(preferred: str, occupied: set[str]) -> str:
    """Return a deterministic identifier unused in one record namespace."""

    if preferred not in occupied:
        return preferred
    for collision_index in range(1, len(occupied) + 2):
        candidate = f"{preferred}-{collision_index:03d}"
        if candidate not in occupied:
            return candidate
    raise AssertionError("identifier allocation exhausted unexpectedly")


def _require_mutation_postcondition(case: BenchmarkCase) -> None:
    """Require exactly the one oracle finding promised by ``case.mutation``."""

    expected_rule = _EXPECTED_RULES.get(case.mutation)
    if expected_rule is None:
        raise ValueError(f"unknown mutation postcondition for {case.mutation!r}")
    try:
        actual = case._verified_oracle_findings()
    except (TypeError, ValueError) as error:
        raise ValueError(
            f"{case.mutation} mutation must produce exactly one "
            f"{expected_rule} finding"
        ) from error
    if tuple(item["rule_id"] for item in actual) != (expected_rule,):
        raise ValueError(
            f"{case.mutation} mutation must produce exactly one "
            f"{expected_rule} finding"
        )


def apply_mutation(
    graph: Mapping[str, Any], name: str, *, seed: int = 0
) -> BenchmarkCase:
    """Apply one named mutation without modifying ``graph``."""

    if name not in MUTATION_NAMES:
        raise ValueError(f"unknown mutation {name!r}; choose from {', '.join(MUTATION_NAMES)}")
    seed = require_seed(seed, label="mutation seed")
    validated_graph = require_graph(graph, label="mutation input")
    mutated = deepcopy(dict(validated_graph))
    mutated.pop("ground_truth", None)
    rng = random.Random(seed)

    if name == "privilege_expansion":
        approved = {
            (str(item["principal"]), str(item["effect"]))
            for item in mutated.get("approved_grants", [])
        }
        candidates = sorted(
            (str(service["id"]), str(effect["id"]))
            for service in mutated.get("services", [])
            for effect in mutated.get("effects", [])
            if (str(service["id"]), str(effect["id"])) not in approved
        )
        if not candidates:
            raise ValueError("privilege_expansion requires an unapproved principal/effect pair")
        principal, effect = candidates[rng.randrange(len(candidates))]
        grants = list(mutated.get("grants", []))
        grants.append({"principal": principal, "effect": effect})
        mutated["grants"] = sorted(
            grants, key=lambda item: (str(item["principal"]), str(item["effect"]))
        )
    elif name == "confused_deputy":
        current = {
            (str(item["principal"]), str(item["effect"]))
            for item in mutated.get("grants", [])
        }
        services_by_id = {
            str(item["id"]): item for item in mutated.get("services", [])
        }
        candidates = sorted(
            (str(service["id"]), str(effect["id"]), str(effect["owner"]))
            for service in mutated.get("services", [])
            for effect in mutated.get("effects", [])
            if (str(service["id"]), str(effect["id"])) not in current
        )
        if not candidates:
            raise ValueError("confused_deputy requires an ungranted principal/effect pair")
        caller, effect, owner = candidates[rng.randrange(len(candidates))]
        requests = list(mutated.get("requests", []))
        request_id = _allocate_identifier(
            f"request-confused-{len(requests):03d}",
            {str(request["id"]) for request in requests},
        )
        requests.append(
            {
                "id": request_id,
                "caller": caller,
                "service": owner,
                "effect": effect,
                "service_version": services_by_id[owner]["version"],
            }
        )
        mutated["requests"] = requests
    elif name == "stale_version":
        requests = list(mutated.get("requests", []))
        if not requests:
            raise ValueError("stale_version requires at least one request")
        index = rng.randrange(len(requests))
        requests[index] = dict(requests[index])
        service_version = requests[index]["service_version"]
        requests[index]["service_version"] = (
            service_version - 1
            if service_version == MAX_VERSION
            else service_version + 1
        )
        mutated["requests"] = requests
    elif name == "orphan_effect":
        services = list(mutated.get("services", []))
        if not services:
            raise ValueError("orphan_effect requires at least one service")
        service = services[rng.randrange(len(services))]
        orphan_id = _allocate_identifier(
            f"effect-orphan-{seed:08x}",
            {str(effect["id"]) for effect in mutated.get("effects", [])},
        )
        requests = list(mutated.get("requests", []))
        request_id = _allocate_identifier(
            f"request-orphan-{len(requests):03d}",
            {str(request["id"]) for request in requests},
        )
        requests.append(
            {
                "id": request_id,
                "caller": str(service["id"]),
                "service": str(service["id"]),
                "effect": orphan_id,
                "service_version": service["version"],
            }
        )
        mutated["requests"] = requests

    payload = _canonical_payload(mutated)
    if name == "parser_corruption":
        removed = 2 + rng.randrange(min(16, max(1, len(payload) - 1)))
        payload = payload[:-removed]
    findings = tuple(evaluate_oracle(payload))
    case = BenchmarkCase(
        case_id=_canonical_case_id(name, payload),
        mutation=name,
        seed=seed,
        payload=payload,
        expected_findings=findings,
    )
    _require_mutation_postcondition(case)
    return case


def validate_mutation(case: BenchmarkCase) -> bool:
    """Return whether a case has the exact oracle result promised by its mutation."""

    try:
        _require_mutation_postcondition(case)
    except (AttributeError, TypeError, ValueError):
        return False
    return True
