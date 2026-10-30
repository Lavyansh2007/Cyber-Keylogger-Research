
import unittest

from src.detection.models import ProcessInfo
from src.detection.rules import check_suspicious_file_location


class TestFileLocationRule(unittest.TestCase):

    def make_process(self, path):
        return ProcessInfo(
            pid=123,
            name="test.exe",
            executable=path,
            username="testuser",
        )

    def test_temp_path_is_flagged(self):
        process = self.make_process(
            r"C:\Users\Tester\AppData\Local\Temp\test.exe"
        )
        finding = check_suspicious_file_location(process)
        self.assertIsNotNone(finding)
        self.assertEqual(
            finding.rule_name, "SUSPICIOUS_FILE_LOCATION"
        )

    def test_downloads_path_is_flagged(self):
        process = self.make_process(
            r"C:\Users\Tester\Downloads\test.exe"
        )
        finding = check_suspicious_file_location(process)
        self.assertIsNotNone(finding)

    def test_program_files_is_not_flagged(self):
        process = self.make_process(
            r"C:\Program Files\Example\test.exe"
        )
        finding = check_suspicious_file_location(process)
        self.assertIsNone(finding)

    def test_missing_path_is_not_flagged(self):
        process = self.make_process(None)
        finding = check_suspicious_file_location(process)
        self.assertIsNone(finding)


if __name__ == "__main__":
    unittest.main()
