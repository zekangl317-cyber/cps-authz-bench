"""Reference invariant oracle for benchmark ground truth."""

from __future__ import annotations

import re
from typing import Any, Mapping

from .json_boundary import (
    _contains_c0_or_c1_control,
    require_unicode_scalars,
    strict_json_loads,
)
from .seeds import MAX_SEED, MIN_SEED, is_seed


_GRAPH_REQUIRED_FIELDS = frozenset(
    {
        "schema_version",
        "seed",
        "services",
        "effects",
        "approved_grants",
        "grants",
        "requests",
    }
)
_GRAPH_OPTIONAL_FIELDS = frozenset({"ground_truth"})
_SERVICE_FIELDS = frozenset({"id", "version", "zone"})
_EFFECT_FIELDS = frozenset(
    {"id", "owner", "resource", "operation", "safety_class"}
)
_GRANT_FIELDS = frozenset({"principal", "effect"})
_REQUEST_FIELDS = frozenset(
    {"id", "caller", "service", "effect", "service_version"}
)
_GROUND_TRUTH_FIELDS = frozenset({"schema_version", "findings"})
_IDENTIFIER = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:-]{0,127}\Z", re.ASCII)
MAX_GRAPH_BYTES = 32 * 1024 * 1024
MAX_SERVICES = 4096
MAX_EFFECTS = 16_384
MAX_GRANTS = 65_536
MAX_REQUESTS = 65_536
MAX_TEXT_CHARACTERS = 256
MAX_VERSION = 2**31 - 1


def _finding(rule_id: str, subject: str, message: str, **details: Any) -> dict[str, Any]:
    return {
        "rule_id": rule_id,
        "subject": subject,
        "message": message,
        "details": details,
    }


def _closed_record(value: Any, fields: frozenset[str]) -> Mapping[str, Any] | None:
    if not isinstance(value, Mapping) or frozenset(value) != fields:
        return None
    return value


def _positive_integer(value: Any) -> bool:
    return (
        isinstance(value, int)
        and not isinstance(value, bool)
        and 1 <= value <= MAX_VERSION
    )


def _string_fields(record: Mapping[str, Any], fields: tuple[str, ...]) -> bool:
    return all(isinstance(record[field], str) for field in fields)


def _valid_identifier(value: Any) -> bool:
    return isinstance(value, str) and _IDENTIFIER.fullmatch(value) is not None


def _valid_text(value: Any) -> bool:
    return (
        isinstance(value, str)
        and 1 <= len(value) <= MAX_TEXT_CHARACTERS
        and value.strip() == value
        and not _contains_c0_or_c1_control(value)
    )


def _valid_graph_shape(graph: Mapping[str, Any]) -> bool:
    if not is_seed(graph["seed"]):
        return False
    collections = (
        "services",
        "effects",
        "approved_grants",
        "grants",
        "requests",
    )
    if any(not isinstance(graph[field], list) for field in collections):
        return False
    collection_bounds = {
        "services": (1, MAX_SERVICES),
        "effects": (1, MAX_EFFECTS),
        "approved_grants": (0, MAX_GRANTS),
        "grants": (0, MAX_GRANTS),
        "requests": (0, MAX_REQUESTS),
    }
    if any(
        not minimum <= len(graph[field]) <= maximum
        for field, (minimum, maximum) in collection_bounds.items()
    ):
        return False

    for value in graph["services"]:
        record = _closed_record(value, _SERVICE_FIELDS)
        if (
            record is None
            or not _string_fields(record, ("id", "zone"))
            or not _positive_integer(record["version"])
            or not _valid_text(record["zone"])
        ):
            return False
    for value in graph["effects"]:
        record = _closed_record(value, _EFFECT_FIELDS)
        if record is None or not _string_fields(
            record, ("id", "owner", "resource", "operation", "safety_class")
        ):
            return False
        if not all(
            _valid_text(record[field])
            for field in ("resource", "operation", "safety_class")
        ):
            return False
    for field in ("approved_grants", "grants"):
        for value in graph[field]:
            record = _closed_record(value, _GRANT_FIELDS)
            if record is None or not _string_fields(record, ("principal", "effect")):
                return False
    for value in graph["requests"]:
        record = _closed_record(value, _REQUEST_FIELDS)
        if (
            record is None
            or not _string_fields(record, ("id", "caller", "service", "effect"))
            or not _positive_integer(record["service_version"])
        ):
            return False

    if "ground_truth" in graph:
        ground_truth = _closed_record(graph["ground_truth"], _GROUND_TRUTH_FIELDS)
        if (
            ground_truth is None
            or ground_truth["schema_version"] != "cps-authz-oracle/v1"
            or ground_truth["findings"] != []
        ):
            return False

    service_ids = [record["id"] for record in graph["services"]]
    effect_ids = [record["id"] for record in graph["effects"]]
    request_ids = [record["id"] for record in graph["requests"]]
    if any(not _valid_identifier(value) for value in service_ids + effect_ids + request_ids):
        return False
    if (
        len(service_ids) != len(set(service_ids))
        or len(effect_ids) != len(set(effect_ids))
        or len(request_ids) != len(set(request_ids))
    ):
        return False

    services = set(service_ids)
    effects_by_id = {record["id"]: record for record in graph["effects"]}
    effects = set(effects_by_id)
    for effect in graph["effects"]:
        if not _valid_identifier(effect["owner"]) or effect["owner"] not in services:
            return False

    for field in ("approved_grants", "grants"):
        identities: list[tuple[str, str]] = []
        for grant in graph[field]:
            principal = grant["principal"]
            effect = grant["effect"]
            if (
                not _valid_identifier(principal)
                or not _valid_identifier(effect)
                or principal not in services
                or effect not in effects
            ):
                return False
            identities.append((principal, effect))
        if len(identities) != len(set(identities)):
            return False

    for request in graph["requests"]:
        caller = request["caller"]
        service = request["service"]
        effect = request["effect"]
        if (
            not _valid_identifier(caller)
            or not _valid_identifier(service)
            or not _valid_identifier(effect)
            or caller not in services
            or service not in services
        ):
            return False
        if effect in effects_by_id and effects_by_id[effect]["owner"] != service:
            return False
    return True


def _parse(value: bytes | str | Mapping[str, Any]) -> Mapping[str, Any] | None:
    if isinstance(value, Mapping):
        try:
            require_unicode_scalars(value)
        except (RecursionError, TypeError, ValueError):
            return None
        parsed: Any = value
    else:
        try:
            if isinstance(value, bytes):
                if len(value) > MAX_GRAPH_BYTES:
                    return None
                decoded = value.decode("utf-8")
            elif isinstance(value, str):
                if len(value.encode("utf-8")) > MAX_GRAPH_BYTES:
                    return None
                decoded = value
            else:
                return None
            parsed = strict_json_loads(decoded)
        except (
            UnicodeDecodeError,
            UnicodeEncodeError,
            RecursionError,
            TypeError,
            ValueError,
        ):
            return None
    if not isinstance(parsed, Mapping):
        return None
    fields = frozenset(parsed)
    if not _GRAPH_REQUIRED_FIELDS.issubset(fields):
        return None
    if not fields.issubset(_GRAPH_REQUIRED_FIELDS | _GRAPH_OPTIONAL_FIELDS):
        return None
    if parsed.get("schema_version") != "cps-authz-graph/v1":
        return None
    if not _valid_graph_shape(parsed):
        return None
    return parsed


def require_graph(
    value: bytes | str | Mapping[str, Any], *, label: str = "graph"
) -> Mapping[str, Any]:
    """Return one schema-valid graph or raise a boundary-friendly error."""

    graph = _parse(value)
    if graph is None:
        raise ValueError(
            f"{label} must be a well-formed, schema-valid cps-authz-graph/v1 document"
        )
    return graph


def _grant_set(items: list[Mapping[str, Any]]) -> set[tuple[str, str]]:
    return {(item["principal"], item["effect"]) for item in items}


def evaluate_oracle(value: bytes | str | Mapping[str, Any]) -> list[dict[str, Any]]:
    """Return deterministic invariant findings for a graph payload."""

    graph = _parse(value)
    if graph is None:
        return [
            _finding(
                "PARSER_CORRUPTION",
                "document",
                "Input is not a well-formed, schema-valid cps-authz-graph/v1 document.",
            )
        ]

    approved = _grant_set(graph.get("approved_grants"))
    current = _grant_set(graph.get("grants"))
    findings = [
        _finding(
            "PRIVILEGE_EXPANSION",
            f"{principal}|{effect}",
            "A current principal/effect grant is absent from approved_grants.",
            principal=principal,
            effect=effect,
        )
        for principal, effect in sorted(current - approved)
    ]
    services = {item["id"]: item for item in graph["services"]}
    effects = {item["id"]: item for item in graph["effects"]}
    for request in graph["requests"]:
        request_id = request["id"]
        caller = request["caller"]
        effect_id = request["effect"]
        service_id = request["service"]
        if effect_id not in effects:
            findings.append(
                _finding(
                    "ORPHAN_EFFECT",
                    request_id,
                    "A request references an effect absent from the graph.",
                    effect=effect_id,
                )
            )
        if request["service_version"] != services[service_id]["version"]:
            findings.append(
                _finding(
                    "STALE_VERSION",
                    request_id,
                    "A request targets a service version different from the current graph.",
                    requested_version=request["service_version"],
                    current_version=services[service_id]["version"],
                    service=service_id,
                )
            )
        if effect_id in effects and (caller, effect_id) not in current:
            findings.append(
                _finding(
                    "CONFUSED_DEPUTY",
                    request_id,
                    "A service request asks for an effect not granted to its caller.",
                    caller=caller,
                    service=service_id,
                    effect=effect_id,
                )
            )
    findings.sort(key=lambda item: (item["rule_id"], item["subject"]))
    return findings
