from __future__ import annotations

import base64
import json
import re
import urllib.parse
from collections.abc import Iterator, Mapping, Sequence
from typing import Any

from .models import CanaryReport, Finding, Status

SUPPORTED_ENCODINGS = {"raw", "base64", "base64url", "hex", "url"}
DEFAULT_REQUIRED_SCENARIOS = (
    "prompt",
    "output",
    "tool_args",
    "tool_result",
    "tool_exception",
    "output_validation_retry",
)
SAFE_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$")
MAX_URL_DECODE_CHARS = 1_000_000


class DocumentError(ValueError):
    """Raised for an invalid canary document without including capture content."""


def _escape(token: object) -> str:
    return str(token).replace("~", "~0").replace("/", "~1")


def _walk(value: Any, pointer: str = "", json_depth: int = 0) -> Iterator[tuple[str, str]]:
    if isinstance(value, Mapping):
        for index, (key, child) in enumerate(value.items()):
            if isinstance(key, (str, bytes)):
                key_text = key.decode("utf-8", errors="replace") if isinstance(key, bytes) else key
                # A key can itself be the leaked value. Use an ordinal location so
                # the report never repeats that key.
                yield f"{pointer}/~keys/{index}", key_text
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


def _direct_variants(value: str, declared: list[str]) -> list[tuple[str, str]]:
    raw = value.encode("utf-8")
    variants: list[tuple[str, str]] = []
    if "raw" in declared:
        variants.append(("raw", value))
    if "base64" in declared:
        encoded = base64.b64encode(raw).decode("ascii")
        variants.extend(("base64", item) for item in {encoded, encoded.rstrip("=")})
    if "base64url" in declared:
        encoded = base64.urlsafe_b64encode(raw).decode("ascii")
        variants.extend(("base64url", item) for item in {encoded, encoded.rstrip("=")})
    unique: list[tuple[str, str]] = []
    seen: set[str] = set()
    for name, encoded in variants:
        if encoded not in seen:
            seen.add(encoded)
            unique.append((name, encoded))
    return unique


def _match_text(text: str, canary: str, declared: list[str]) -> tuple[list[str], bool]:
    matches: list[str] = []
    for encoding, needle in _direct_variants(canary, declared):
        if needle and needle in text and encoding not in matches:
            matches.append(encoding)
    if "hex" in declared and canary.encode("utf-8").hex() in text.lower():
        matches.append("hex")
    skipped_url = False
    if "url" in declared:
        if len(text) > MAX_URL_DECODE_CHARS:
            skipped_url = True
        else:
            try:
                decoded = urllib.parse.unquote_to_bytes(text).decode("utf-8", errors="replace")
            except (ValueError, UnicodeError):
                decoded = ""
            # Require at least one valid escape so a raw match is not reported a
            # second time as URL encoding. Partial and mixed-case escapes remain
            # valid and are decoded by unquote_to_bytes.
            has_escape = re.search(r"%[0-9A-Fa-f]{2}", text) is not None
            if canary in decoded and (has_escape or "raw" not in declared):
                matches.append("url")
    return matches, skipped_url


def _contains(value: Any, canary: str, declared: list[str]) -> tuple[bool, bool]:
    skipped = False
    for _, text in _walk(value):
        matches, text_skipped = _match_text(text, canary, declared)
        skipped = skipped or text_skipped
        if matches:
            return True, skipped
    return False, skipped


def _safe_id(value: Any) -> bool:
    return (
        isinstance(value, str)
        and SAFE_ID.fullmatch(value) is not None
        and not value.upper().startswith("TEST_ONLY_")
    )


def _safe_dependencies(
    metadata: Any,
    parsed: list[tuple[str, str, str, list[str], dict[str, Any]]],
) -> dict[str, str]:
    dependencies = metadata.get("dependencies", {}) if isinstance(metadata, dict) else {}
    if not isinstance(dependencies, dict):
        return {}
    result: dict[str, str] = {}
    for index, (key, value) in enumerate(dependencies.items()):
        key_text, value_text = str(key), str(value)
        sensitive = "TEST_ONLY_" in key_text.upper() or "TEST_ONLY_" in value_text.upper()
        for _scenario_id, _canary_id, canary, declared, _controls in parsed:
            key_matches, _ = _match_text(key_text, canary, declared)
            value_matches, _ = _match_text(value_text, canary, declared)
            sensitive = sensitive or bool(key_matches or value_matches)
        if sensitive:
            result[f"redacted-{index}"] = "[redacted]"
        elif _safe_id(key_text) and len(value_text) <= 64 and "\n" not in value_text:
            result[key_text] = value_text
    return result


def _safe_location(
    location: str,
    parsed: list[tuple[str, str, str, list[str], dict[str, Any]]],
) -> str:
    for _scenario_id, _canary_id, canary, declared, _controls in parsed:
        matches, _ = _match_text(location, canary, declared)
        if matches:
            return "/capture/~redacted-key-path"
    return f"/capture{location if location != '/' else ''}"


def check_document(document: Any) -> CanaryReport:
    """Check one parsed canary document. Reports never include matched capture text."""
    if not isinstance(document, dict):
        return CanaryReport(Status.INCONCLUSIVE, reasons=["document must be a JSON object"])

    metadata = document.get("metadata")
    scenarios = document.get("scenarios")
    capture_present = "capture" in document
    capture = document.get("capture")
    report = CanaryReport(Status.INCONCLUSIVE)

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

    parsed: list[tuple[str, str, str, list[str], dict[str, Any]]] = []
    seen_ids: set[str] = set()
    for index, scenario in enumerate(scenarios):
        if not isinstance(scenario, dict):
            report.reasons.append(f"scenario at index {index} is not an object")
            continue
        scenario_id = scenario.get("scenario_id")
        canary_id = scenario.get("canary_id")
        canary = scenario.get("canary")
        if not _safe_id(scenario_id) or not _safe_id(canary_id):
            report.reasons.append(f"scenario at index {index} has invalid identifiers")
            continue
        if not isinstance(canary, str) or not canary.startswith("TEST_ONLY_") or len(canary) > 256:
            report.reasons.append(f"scenario at index {index} has invalid synthetic canary")
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
        if (
            not isinstance(declared, list)
            or not declared
            or any(not isinstance(x, str) or x not in SUPPORTED_ENCODINGS for x in declared)
        ):
            report.reasons.append(f"unsupported encoding declaration: {scenario_id}")
            continue
        controls = scenario.get("controls")
        if not isinstance(controls, dict):
            report.reasons.append(f"missing controls: {scenario_id}")
            continue
        parsed.append((scenario_id, canary_id, canary, declared, controls))

    report.dependency_versions = _safe_dependencies(metadata, parsed)
    required = metadata.get("required_scenarios", list(DEFAULT_REQUIRED_SCENARIOS)) if isinstance(metadata, dict) else None
    if (
        not isinstance(required, list)
        or not required
        or any(not _safe_id(item) for item in required)
    ):
        report.reasons.append("required_scenarios is missing or invalid")
    else:
        parsed_ids = {item[0] for item in parsed}
        for scenario_id in required:
            if scenario_id not in parsed_ids:
                report.reasons.append(f"required scenario missing: {scenario_id}")

    if capture_present:
        locations = list(_walk(capture))
        observable_values = [item for item in locations if "/~keys/" not in item[0]]
        report.locations_checked = len(observable_values)
        if not observable_values:
            report.reasons.append("capture contains no observable fields")
        url_scan_skipped = False
        for scenario_id, canary_id, canary, declared, _controls in parsed:
            for location, text in locations:
                encodings, skipped = _match_text(text, canary, declared)
                url_scan_skipped = url_scan_skipped or skipped
                for encoding in encodings:
                    report.findings.append(
                        Finding(canary_id, scenario_id, _safe_location(location, parsed), encoding)
                    )
        if url_scan_skipped:
            report.reasons.append("URL-decoding scan limit exceeded")

    if report.findings:
        report.status = Status.LEAK
        report.reasons = []
        return report

    for scenario_id, _canary_id, canary, declared, controls in parsed:
        positive_pointer = controls.get("content_enabled_pointer")
        privacy_pointer = controls.get("privacy_enabled_pointer")
        positive_prefix = "/controls/content_enabled"
        privacy_prefix = "/capture"
        valid_pointers = (
            isinstance(positive_pointer, str)
            and isinstance(privacy_pointer, str)
            and positive_pointer.startswith(positive_prefix + "/")
            and privacy_pointer.startswith(privacy_prefix + "/")
            and positive_pointer[len(positive_prefix):] == privacy_pointer[len(privacy_prefix):]
        )
        if not valid_pointers:
            report.reasons.append(f"invalid control boundary pointers: {scenario_id}")
            continue
        positive_found, positive_value = _resolve(document, positive_pointer)
        privacy_found, privacy_value = _resolve(document, privacy_pointer)
        if not positive_found:
            report.reasons.append(f"positive-control boundary missing: {scenario_id}")
        else:
            positive_contains, positive_skipped = _contains(positive_value, canary, declared)
            if positive_skipped:
                report.reasons.append(f"positive-control scan limit exceeded: {scenario_id}")
            elif not positive_contains:
                report.reasons.append(f"positive-control canary not observed: {scenario_id}")
        if not privacy_found:
            report.reasons.append(f"privacy-control boundary missing: {scenario_id}")
        else:
            privacy_contains, privacy_skipped = _contains(privacy_value, canary, declared)
            if privacy_skipped:
                report.reasons.append(f"privacy-control scan limit exceeded: {scenario_id}")
            elif privacy_contains:
                report.reasons.append(f"privacy-control canary remained observable: {scenario_id}")

    if report.reasons:
        report.status = Status.INCONCLUSIVE
    else:
        report.status = Status.PASS
    return report
