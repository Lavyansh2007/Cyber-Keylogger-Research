
from .findings import DetectionFinding


def calculate_risk_score(
    findings: list[DetectionFinding],
    signature_status: str | None = None
) -> tuple[int, str, list[str]]:

    score = 0
    reasons = []
    seen_rules = set()

    # Keyboard API imports alone are weak evidence.
    for finding in findings:
        if (
            finding.rule_name == "KEYBOARD_INPUT_API"
            and "KEYBOARD_INPUT_API" not in seen_rules
        ):
            score += 5
            reasons.append(
                "+5: Keyboard/input API imports detected "
                "(weak indicator)"
            )
            seen_rules.add("KEYBOARD_INPUT_API")

        if (
            finding.rule_name == "MISSING_EXECUTABLE"
            and "MISSING_EXECUTABLE" not in seen_rules
        ):
            score += 5
            reasons.append(
                "+5: Executable path could not be accessed"
            )
            seen_rules.add("MISSING_EXECUTABLE")

        if (
            finding.rule_name == "SUSPICIOUS_FILE_LOCATION"
            and "SUSPICIOUS_FILE_LOCATION" not in seen_rules
        ):
            score += 5
            reasons.append(
                "+5: Executable runs from a temporary "
                "or Downloads location"
            )
            seen_rules.add("SUSPICIOUS_FILE_LOCATION")

    # Resolve signature status.
    status = (signature_status or "").strip().lower()

    if not status:
        for finding in findings:
            evidence_status = finding.evidence.get(
                "signature_status"
            )
            if evidence_status:
                status = str(evidence_status).strip().lower()
                break

    # A missing signature is weaker evidence than an invalid one.
    if status in {"hashmismatch", "nottrusted", "invalid"}:
        score += 20
        reasons.append(
            "+20: Executable signature is invalid or untrusted"
        )
    elif status in {"notsigned", "not signed"}:
        score += 5
        reasons.append(
            "+5: Executable has no digital signature "
            "(not proof of malware)"
        )

    score = min(score, 100)

    if score >= 30:
        level = "HIGH"
    elif score >= 15:
        level = "MEDIUM"
    else:
        level = "LOW"

    if not reasons:
        reasons.append("No configured risk indicators detected")

    return score, level, reasons
