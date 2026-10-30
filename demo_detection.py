from types import SimpleNamespace

from src.detection.rules import check_keyboard_input_apis


def run_detection_demo():

    # Simulated process information
    process = SimpleNamespace(
        pid=9999,
        name="Simulated-Keylogger.exe"
    )

    # Simulated imported API
    imports = [
        SimpleNamespace(
            dll="USER32.dll",
            function="GetAsyncKeyState"
        )
    ]

    # Simulated signature information
    signature = SimpleNamespace(
        status="NotSigned",
        signer=None
    )

    print("\n=== Detection Demonstration ===")
    print("Running keyboard API detection rule...\n")

    findings = check_keyboard_input_apis(
        process,
        imports,
        signature
    )

    if not findings:
        print("No findings detected.")
        return

    for finding in findings:
        print("DETECTION FOUND")
        print("------------------------------")
        print("Process:", finding.process_name)
        print("PID:", finding.pid)
        print("Rule:", finding.rule_name)
        print("Severity:", finding.severity.value)
        print("Description:", finding.description)
        print("Evidence:", finding.evidence)

    print("\nDemo completed.")


if __name__ == "__main__":
    run_detection_demo()