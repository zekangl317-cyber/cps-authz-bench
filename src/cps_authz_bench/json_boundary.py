"""Strict JSON and analyzer-finding validation at public trust boundaries."""

from __future__ import annotations

import json
import math
import re
from numbers import Real
from typing import Any, Mapping


MAX_FINDINGS = 65_536
MAX_RULE_ID_CHARACTERS = 128
MAX_SUBJECT_CHARACTERS = 256
MAX_MESSAGE_CHARACTERS = 1_024
MAX_DETAIL_FIELDS = 32
MAX_DETAIL_KEY_CHARACTERS = 64
MAX_DETAIL_STRING_CHARACTERS = 1_024
MIN_DETAIL_INTEGER = -(2**63)
MAX_DETAIL_INTEGER = 2**63 - 1

_RULE_ID = re.compile(r"[A-Za-z][A-Za-z0-9._:-]{0,127}\Z", re.ASCII)
_FINDING_FIELDS = frozenset({"rule_id", "subject", "message", "details", "confidence"})
_REQUIRED_FINDING_FIELDS = frozenset({"rule_id", "subject"})


class StrictJSONError(ValueError):
    """A JSON document is ambiguous, non-standard, or malformed."""


def _object_without_duplicate_keys(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise StrictJSONError(f"duplicate JSON object member {key!r}")
        result[key] = value
    return result


def _reject_nonstandard_number(token: str) -> None:
    raise StrictJSONError(f"non-standard JSON number {token!r}")


def _require_unicode_scalars(value: str) -> None:
    try:
        value.encode("utf-8")
    except UnicodeEncodeError as error:
        raise StrictJSONError(
            "decoded JSON strings and object keys must contain valid Unicode scalar values"
        ) from error


def require_unicode_scalars(value: Any) -> None:
    """Reject strings or object keys that cannot be encoded as strict UTF-8."""

    pending = [value]
    seen_containers: set[int] = set()
    while pending:
        item = pending.pop()
        if isinstance(item, str):
            _require_unicode_scalars(item)
        elif isinstance(item, Mapping):
            identity = id(item)
            if identity in seen_containers:
                continue
            seen_containers.add(identity)
            nested_values = []
            for key, nested_value in item.items():
                if isinstance(key, str):
                    _require_unicode_scalars(key)
                nested_values.append(nested_value)
            pending.extend(nested_values)
        elif isinstance(item, list):
            identity = id(item)
            if identity in seen_containers:
                continue
            seen_containers.add(identity)
            pending.extend(item)


def strict_json_loads(value: bytes | bytearray | str) -> Any:
    """Decode one standards-compliant JSON value without parser differentials."""

    try:
        text = bytes(value).decode("utf-8") if isinstance(value, (bytes, bytearray)) else value
        if not isinstance(text, str):
            raise TypeError("JSON input must be UTF-8 bytes or text")
        parsed = json.loads(
            text,
            object_pairs_hook=_object_without_duplicate_keys,
            parse_constant=_reject_nonstandard_number,
        )
        require_unicode_scalars(parsed)
        pending = [parsed]
        while pending:
            item = pending.pop()
            if isinstance(item, float) and not math.isfinite(item):
                raise StrictJSONError("JSON number is outside the finite numeric range")
            elif isinstance(item, Mapping):
                pending.extend(item.values())
            elif isinstance(item, list):
                pending.extend(item)
        return parsed
    except StrictJSONError:
        raise
    except (UnicodeDecodeError, json.JSONDecodeError, RecursionError, TypeError) as error:
        raise StrictJSONError(str(error)) from error


def _contains_c0_or_c1_control(value: str) -> bool:
    """Recognize C0/C1 controls while deliberately preserving Unicode Cf."""

    return any(
        ord(character) < 0x20 or 0x7F <= ord(character) <= 0x9F
        for character in value
    )


def _bounded_text(value: Any, *, label: str, limit: int) -> str:
    if not isinstance(value, str):
        raise ValueError(f"{label} must be a string")
    if _contains_c0_or_c1_control(value):
        raise ValueError(f"{label} must not contain control characters")
    if not value or value != value.strip() or len(value) > limit:
        raise ValueError(f"{label} must be a non-empty trimmed string of at most {limit} characters")
    try:
        value.encode("utf-8")
    except UnicodeEncodeError as error:
        raise ValueError(f"{label} must contain valid Unicode scalar values") from error
    return value


def _validated_details(value: Any, *, index: int) -> dict[str, Any]:
    if not isinstance(value, Mapping):
        raise ValueError(f"tool finding {index} details must be an object")
    if len(value) > MAX_DETAIL_FIELDS:
        raise ValueError(f"tool finding {index} details has too many fields")
    normalized: dict[str, Any] = {}
    for key, item in value.items():
        normalized_key = _bounded_text(
            key,
            label=f"tool finding {index} detail key",
            limit=MAX_DETAIL_KEY_CHARACTERS,
        )
        if item is None or isinstance(item, bool):
            normalized[normalized_key] = item
        elif isinstance(item, int):
            if not MIN_DETAIL_INTEGER <= item <= MAX_DETAIL_INTEGER:
                raise ValueError(f"tool finding {index} detail integer is out of range")
            normalized[normalized_key] = item
        elif isinstance(item, float):
            if not math.isfinite(item):
                raise ValueError(f"tool finding {index} detail number must be finite")
            normalized[normalized_key] = item
        elif isinstance(item, str):
            normalized[normalized_key] = _bounded_text(
                item,
                label=f"tool finding {index} detail value",
                limit=MAX_DETAIL_STRING_CHARACTERS,
            )
        else:
            raise ValueError(f"tool finding {index} detail values must be JSON scalars")
    return normalized


def normalize_findings(value: Any) -> tuple[dict[str, Any], ...]:
    """Validate the closed, bounded analyzer finding schema and sort records."""

    if not isinstance(value, list):
        raise ValueError("tool output field 'findings' must be an array")
    if len(value) > MAX_FINDINGS:
        raise ValueError(f"tool output may contain at most {MAX_FINDINGS} findings")
    normalized: list[dict[str, Any]] = []
    for index, finding in enumerate(value):
        if not isinstance(finding, Mapping):
            raise ValueError(f"tool finding {index} must be an object")
        fields = frozenset(finding)
        if not _REQUIRED_FINDING_FIELDS.issubset(fields) or not fields.issubset(
            _FINDING_FIELDS
        ):
            raise ValueError(
                f"tool finding {index} must contain rule_id and subject and only "
                "message, details, or confidence as optional fields"
            )
        rule_id = _bounded_text(
            finding["rule_id"],
            label=f"tool finding {index} rule_id",
            limit=MAX_RULE_ID_CHARACTERS,
        )
        if _RULE_ID.fullmatch(rule_id) is None:
            raise ValueError(f"tool finding {index} rule_id has invalid syntax")
        subject = _bounded_text(
            finding["subject"],
            label=f"tool finding {index} subject",
            limit=MAX_SUBJECT_CHARACTERS,
        )
        record: dict[str, Any] = {"rule_id": rule_id, "subject": subject}
        if "message" in finding:
            record["message"] = _bounded_text(
                finding["message"],
                label=f"tool finding {index} message",
                limit=MAX_MESSAGE_CHARACTERS,
            )
        if "details" in finding:
            record["details"] = _validated_details(finding["details"], index=index)
        if "confidence" in finding:
            confidence = finding["confidence"]
            if (
                isinstance(confidence, bool)
                or not isinstance(confidence, Real)
                or not math.isfinite(confidence)
                or not 0.0 <= confidence <= 1.0
            ):
                raise ValueError(f"tool finding {index} confidence must be finite in [0, 1]")
            record["confidence"] = float(confidence)
        normalized.append(record)
    normalized.sort(
        key=lambda item: (
            item["rule_id"],
            item["subject"],
            json.dumps(item, allow_nan=False, ensure_ascii=False, sort_keys=True),
        )
    )
    return tuple(normalized)


def parse_analyzer_output(value: bytes | bytearray | str) -> tuple[dict[str, Any], ...]:
    """Strictly parse one closed analyzer-output document."""

    parsed = strict_json_loads(value)
    if not isinstance(parsed, Mapping) or frozenset(parsed) != {"findings"}:
        raise ValueError("tool output must be an object containing only 'findings'")
    return normalize_findings(parsed["findings"])
