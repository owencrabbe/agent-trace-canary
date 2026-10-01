from __future__ import annotations

import base64
import json
from collections.abc import Iterator, Mapping, Sequence
from typing import Any

from .models import CanaryReport, Finding, Status

SUPPORTED_ENCODINGS = {"raw", "base64", "base64url", "hex", "url"}


class DocumentError(ValueError):
    """Raised for an invalid canary document without including capture content."""


def _escape(token: object) -> str:
    return str(token).replace("~", "~0").replace("/", "~1")


def _walk(value: Any, pointer: str = "", json_depth: int = 0) -> Iterator[tuple[str, str]]:
    if isinstance(value, Mapping):
        for key, child in value.items():
            yield from _walk(child, f"{pointer}/{_escape(key)}", json_depth)
    elif isinstance(value, Sequence) and not isinstance(value, (str, bytes, bytearray)):
        for index, child in enumerate(value):
            yield from _walk(child, f"{pointer}/{index}", json_depth)
    elif isinstance(value, bytes):
        yield pointer or "/", value.decode("utf-8", errors="replace")
    elif isinstance(value, str):
        yield pointer or "/", value
        if json_depth < 3:
            stripped = value.strip()
            if stripped.startswith(("{", "[", '"')):
                try:
                    decoded = json.loads(stripped)
                except (json.JSONDecodeError, RecursionError):
                    return
                if decoded != value:
                    yield from _walk(decoded, f"{pointer}/~json", json_depth + 1)


def _resolve(document: Any, pointer: str) -> tuple[bool, Any]:
    if not isinstance(pointer, str) or not pointer.startswith("/"):
        return False, None
    current = document
    if pointer == "/":
        return True, current
    for raw in pointer[1:].split("/"):
        token = raw.replace("~1", "/").replace("~0", "~")
        try:
            if isinstance(current, list):
                current = current[int(token)]
            elif isinstance(current, dict):
                current = current[token]
            else:
                return False, None
        except (KeyError, IndexError, ValueError):
            return False, None
    return True, current


def _variants(value: str, declared: list[str]) -> list[tuple[str, str]]:
    raw = value.encode("utf-8")
    variants = {
        "raw": value,
        "base64": base64.b64encode(raw).decode("ascii"),
        "base64url": base64.urlsafe_b64encode(raw).decode("ascii").rstrip("="),
        "hex": raw.hex(),
        # Percent-encode every byte. RFC 3986 leaves unreserved characters alone,
        # so urllib.parse.quote(..., safe="") would not actually transform this
        # project's underscore-heavy sentinels.
        "url": "".join(f"%{byte:02X}" for byte in raw),
    }
    unique: list[tuple[str, str]] = []
    seen: set[str] = set()
    for name in declared:
        encoded = variants[name]
        if encoded not in seen:
            seen.add(encoded)
            unique.append((name, encoded))
    return unique


def _contains(value: Any, variants: list[tuple[str, str]]) -> bool:
    return any(needle in text for _, text in _walk(value) for _, needle in variants if needle)


def check_document(document: Any) -> CanaryReport:
    """Check one parsed canary document. Reports never include matched capture text."""
    if not isinstance(document, dict):
        return CanaryReport(Status.INCONCLUSIVE, reasons=["document must be a JSON object"])

    metadata = document.get("metadata")
    scenarios = document.get("scenarios")
    capture_present = "capture" in document
    capture = document.get("capture")
    dependencies = metadata.get("dependencies", {}) if isinstance(metadata, dict) else {}
    safe_dependencies = {
        str(k): str(v) for k, v in dependencies.items()
    } if isinstance(dependencies, dict) else {}
    report = CanaryReport(Status.INCONCLUSIVE, dependency_versions=safe_dependencies)

    if document.get("schema_version") != 1:
        report.reasons.append("unsupported or missing schema_version")
    if not isinstance(metadata, dict):
        report.reasons.append("missing metadata object")
    else:
        if metadata.get("flush_ok") is not True:
            report.reasons.append("capture flush was not confirmed")
        if metadata.get("script_complete") is not True:
            report.reasons.append("scripted steps were not confirmed complete")
    if not capture_present or capture in (None, {}, [], ""):
        report.reasons.append("capture is missing or empty")
    if not isinstance(scenarios, list) or not scenarios:
        report.reasons.append("scenario manifest is missing or empty")
        return report

    parsed: list[tuple[str, str, str, list[tuple[str, str]], dict[str, Any]]] = []
    seen_ids: set[str] = set()
    for index, scenario in enumerate(scenarios):
        if not isinstance(scenario, dict):
            report.reasons.append(f"scenario at index {index} is not an object")
            continue
        scenario_id = scenario.get("scenario_id")
        canary_id = scenario.get("canary_id")
        canary = scenario.get("canary")
        if not all(isinstance(item, str) and item for item in (scenario_id, canary_id, canary)):
            report.reasons.append(f"scenario at index {index} has invalid identifiers")
            continue
        if scenario_id in seen_ids:
            report.reasons.append(f"duplicate scenario_id: {scenario_id}")
        seen_ids.add(scenario_id)
        report.checked_scenarios.append(scenario_id)
        if scenario.get("exercised") is not True:
            report.reasons.append(f"scenario not exercised: {scenario_id}")
        else:
            report.exercised_scenarios.append(scenario_id)
        declared = scenario.get("encodings", ["raw"])
        if not isinstance(declared, list) or not declared or any(x not in SUPPORTED_ENCODINGS for x in declared):
            report.reasons.append(f"unsupported encoding declaration: {scenario_id}")
            continue
        controls = scenario.get("controls")
        if not isinstance(controls, dict):
            report.reasons.append(f"missing controls: {scenario_id}")
            continue
        parsed.append((scenario_id, canary_id, canary, _variants(canary, declared), controls))

    if capture_present:
        locations = list(_walk(capture))
        report.locations_checked = len(locations)
        for scenario_id, canary_id, _canary, variants, _controls in parsed:
            for location, text in locations:
                for encoding, needle in variants:
                    if needle and needle in text:
                        report.findings.append(Finding(canary_id, scenario_id, f"/capture{location if location != '/' else ''}", encoding))

    if report.findings:
        report.status = Status.LEAK
        report.reasons = []
        return report

    for scenario_id, _canary_id, _canary, variants, controls in parsed:
        positive_pointer = controls.get("content_enabled_pointer")
        privacy_pointer = controls.get("privacy_enabled_pointer")
        positive_found, positive_value = _resolve(document, positive_pointer)
        privacy_found, privacy_value = _resolve(document, privacy_pointer)
        if not positive_found:
            report.reasons.append(f"positive-control boundary missing: {scenario_id}")
        elif not _contains(positive_value, variants):
            report.reasons.append(f"positive-control canary not observed: {scenario_id}")
        if not privacy_found:
            report.reasons.append(f"privacy-control boundary missing: {scenario_id}")
        elif _contains(privacy_value, variants):
            report.reasons.append(f"privacy-control canary remained observable: {scenario_id}")

    if report.reasons:
        report.status = Status.INCONCLUSIVE
    else:
        report.status = Status.PASS
    return report
