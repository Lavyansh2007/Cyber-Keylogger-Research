import unittest

from src.detection.rules import (
    check_missing_executable,
    check_suspicious_file_location,
    check_keyboard_input_apis,
)

from src.detection.models import (
    ProcessInfo,
    ImportedFunction,
    SignatureInfo,
)

from src.detection.findings import Severity


class TestDetectionRules(unittest.TestCase):

    def make_process(self, name="test.exe", executable="C:\\test.exe"):
        return ProcessInfo(
            pid=1234,
            name=name,
            executable=executable,
            username="testuser"
    )

    # Missing executable rule

    def test_missing_executable_detected(self):
        process = self.make_process(
            name="unknown.exe",
            executable=None
        )

        finding = check_missing_executable(process)

        self.assertIsNotNone(finding)
        self.assertEqual(finding.rule_name, "MISSING_EXECUTABLE")
        self.assertEqual(finding.severity, Severity.LOW)

    def test_system_idle_process_not_flagged(self):
        process = self.make_process(
            name="System Idle Process",
            executable=None
        )

        finding = check_missing_executable(process)

        self.assertIsNone(finding)

    # Suspicious file location rule

    def test_temp_location_detected(self):
        process = self.make_process(
            executable="C:\\Users\\test\\AppData\\Local\\Temp\\test.exe"
        )

        finding = check_suspicious_file_location(process)

        self.assertIsNotNone(finding)
        self.assertEqual(
            finding.rule_name,
            "SUSPICIOUS_FILE_LOCATION"
        )

    def test_normal_location_not_flagged(self):
        process = self.make_process(
            executable="C:\\Program Files\\test.exe"
        )

        finding = check_suspicious_file_location(process)

        self.assertIsNone(finding)

    # Keyboard API rule

    def test_keyboard_api_detected(self):
        process = self.make_process()

        imports = [
            ImportedFunction(
                dll="USER32.dll",
                function="GetAsyncKeyState"
            )
        ]

        signature = SignatureInfo(
            status="Valid",
            signer="Test Signer"
        )

        findings = check_keyboard_input_apis(
            process,
            imports,
            signature
        )

        self.assertEqual(len(findings), 1)
        self.assertEqual(
            findings[0].rule_name,
            "KEYBOARD_INPUT_API"
        )

    def test_no_keyboard_api_not_flagged(self):
        process = self.make_process()

        imports = [
            ImportedFunction(
                dll="KERNEL32.dll",
                function="CreateFileW"
            )
        ]

        signature = SignatureInfo(
            status="Valid",
            signer="Test Signer"
        )

        findings = check_keyboard_input_apis(
            process,
            imports,
            signature
        )

        self.assertEqual(len(findings), 0)


if __name__ == "__main__":
    unittest.main()