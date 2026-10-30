import unittest
from src.detection.findings import DetectionFinding,Severity
from src.detection.risk_scoring import calculate_risk_score

def make_finding(rule_name, evidence=None):
    return DetectionFinding(
        rule_name=rule_name,
        severity=Severity.LOW,
        description="Test finding",
        pid=123,
        process_name="test.exe",
        evidence=evidence or {}
    )

class TestRiskScoring(unittest.TestCase):

    def test_no_findings(self):
        score, level, reasons = calculate_risk_score([])

        self.assertEqual(score, 0)
        self.assertEqual(level, "LOW")
        self.assertTrue(reasons)

    def test_keyboard_api_with_valid_signature(self):
        finding = make_finding(
            "KEYBOARD_INPUT_API",
            {"signature_status": "Valid"}
        )
        score, level, reasons = calculate_risk_score([finding])

        self.assertEqual(score, 5)
        self.assertEqual(level, "LOW")

    def test_keyboard_api_with_invalid_signature(self):
        finding = make_finding(
            "KEYBOARD_INPUT_API",
            {"signature_status": "HashMismatch"}
        )

        score, level, reasons = calculate_risk_score([finding])

        self.assertEqual(score, 25)
        self.assertEqual(level, "MEDIUM")

    def test_missing_executable(self):
        finding = make_finding("MISSING_EXECUTABLE")

        score, level, reasons = calculate_risk_score([finding])

        self.assertEqual(score,5)
        self.assertEqual(level, "LOW")

    def test_keyboard_api_and_suspicious_location(self):
        findings = [
            make_finding("KEYBOARD_INPUT_API"),
            make_finding("SUSPICIOUS_FILE_LOCATION")
        ]
        score, level, reasons = calculate_risk_score(
            findings,
            signature_status="Valid"
        )
        self.assertEqual(score, 10)
        self.assertEqual(level, "LOW")

    def test_keyboard_api_location_and_invalid_signature(self):
        findings = [
            make_finding("KEYBOARD_INPUT_API"),
            make_finding("SUSPICIOUS_FILE_LOCATION")
        ]
        score, level, reasons = calculate_risk_score(
            findings,
            signature_status="HashMismatch"
        )
        self.assertEqual(score, 30)
        self.assertEqual(level, "HIGH")

    def test_duplicate_finding_does_not_double_score(self):
        finding = make_finding("KEYBOARD_INPUT_API")

        score, level, reasons = calculate_risk_score(
            [finding, finding],
            signature_status="Valid"
        )
        self.assertEqual(score,5)
        self.assertEqual(level, "LOW")

if __name__ == "__main__":
    unittest.main()
        