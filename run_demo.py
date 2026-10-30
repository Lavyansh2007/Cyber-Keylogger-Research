
import sys
import subprocess
import tkinter as tk
from tkinter.scrolledtext import ScrolledText
from types import SimpleNamespace

from src.detection.rules import check_keyboard_input_apis
from src.detection.process_scanner import scan_processes
from src.detection.rule_engine import analyze_process_with_signature
from src.detection.risk_scoring import calculate_risk_score


# --------------------------------------------------
# 1. RUN UNIT TESTS
# --------------------------------------------------

def run_tests():
    print("\n========== RUNNING UNIT TESTS ==========\n")

    result = subprocess.run(
        [
            sys.executable,
            "-m",
            "unittest",
            "discover",
            "-s",
            "tests",
        ],
        capture_output=True,
        text=True,
    )

    print(result.stdout)
    print(result.stderr)

    if result.returncode == 0:
        print("All tests passed.")
    else:
        print("Some tests failed.")

    return result


# --------------------------------------------------
# 2. SCAN REAL RUNNING PROCESSES
# --------------------------------------------------

def scan_system():
    print("\n========== SCANNING PROCESSES ==========\n")

    processes = scan_processes()
    report = []

    for process in processes:

        findings, signature_status = (
            analyze_process_with_signature(process)
        )

        score, level, reasons = calculate_risk_score(
            findings,
            signature_status,
        )

        report.append({
            "pid": process.pid,
            "name": process.name,
            "path": process.executable or "Unknown",
            "signature": signature_status or "Not available",
            "score": score,
            "level": level,
            "reasons": reasons,
        })

    report.sort(
        key=lambda item: item["score"],
        reverse=True,
    )

    return report


# --------------------------------------------------
# 3. SAFE SIMULATED DETECTION
# --------------------------------------------------

def run_simulated_detection():
    print("\n========== SIMULATED DETECTION ==========\n")

    # Synthetic process information.
    # This is NOT a real running keylogger.
    process = SimpleNamespace(
        pid=9999,
        name="Simulated-Keylogger.exe",
    )

    # Synthetic keyboard API import
    imports = [
        SimpleNamespace(
            dll="USER32.dll",
            function="GetAsyncKeyState",
        )
    ]

    # Synthetic signature information
    signature = SimpleNamespace(
        status="NotSigned",
        signer=None,
    )

    # Run the existing keyboard API detection rule
    findings = check_keyboard_input_apis(
        process,
        imports,
        signature,
    )

    # Use the existing risk-scoring function
    score, level, reasons = calculate_risk_score(
        findings,
        signature.status,
    )

    print("Process:", process.name)
    print("Findings:", len(findings))
    print("Risk Score:", score)
    print("Risk Level:", level)

    return {
        "name": process.name,
        "pid": process.pid,
        "score": score,
        "level": level,
        "findings": findings,
        "reasons": reasons,
    }


# --------------------------------------------------
# 4. CREATE THE REPORT
# --------------------------------------------------

def create_report(test_result, report):

    lines = []

    lines.append("CYBER-KEYLOGGER RESEARCH")
    lines.append("PROCESS RISK REPORT")
    lines.append("=" * 60)

    # Unit test results
    lines.append("\nUNIT TESTS")
    lines.append("-" * 60)

    if test_result.returncode == 0:
        lines.append("Result: PASSED")
    else:
        lines.append("Result: FAILED")

    # Categorize processes
    high_processes = [
        item for item in report
        if item["level"] == "HIGH"
    ]

    medium_processes = [
        item for item in report
        if item["level"] == "MEDIUM"
    ]

    low_processes = [
        item for item in report
        if item["level"] == "LOW"
    ]

    # LOW processes with findings
    low_with_findings = [
        item for item in low_processes
        if item["score"] > 0
    ]

    # Processes with zero score
    zero_risk_processes = [
        item for item in report
        if item["score"] == 0
    ]

    # Function to add process details
    def add_process(item):

        lines.append("")
        lines.append(f"Process: {item['name']}")
        lines.append(f"PID: {item['pid']}")
        lines.append(f"Risk Score: {item['score']}/100")
        lines.append(f"Risk Level: {item['level']}")
        lines.append(f"Signature: {item['signature']}")
        lines.append(f"Path: {item['path']}")

        for reason in item["reasons"]:
            lines.append(f"  - {reason}")

    # HIGH RISK
    if high_processes:

        lines.append("\n========== HIGH RISK ==========")

        for item in high_processes:
            add_process(item)

    # MEDIUM RISK
    if medium_processes:

        lines.append("\n========== MEDIUM RISK ==========")

        for item in medium_processes:
            add_process(item)

    # LOW RISK
    if low_processes:

        lines.append("\n========== LOW RISK ==========")

        # Processes with findings first
        if low_with_findings:

            lines.append(
                "\n--- Processes with findings "
                "(score > 0) ---"
            )

            for item in low_with_findings:
                add_process(item)

        # Partition between findings and zero-score processes
        if zero_risk_processes:

            lines.append("\n" + "-" * 60)

            lines.append(
                "\n--- Processes with zero risk "
                "(score = 0) ---"
            )

            for item in zero_risk_processes:
                add_process(item)

    # Risk summary
    risk_counts = {
        "HIGH": len(high_processes),
        "MEDIUM": len(medium_processes),
        "LOW": len(low_processes),
    }

    processes_with_findings = sum(
        1 for item in report
        if item["score"] > 0
    )

    lines.append("\n========== RISK SUMMARY ==========")

    lines.append(f"HIGH: {risk_counts['HIGH']}")
    lines.append(f"MEDIUM: {risk_counts['MEDIUM']}")
    lines.append(f"LOW: {risk_counts['LOW']}")

    lines.append(
        f"Processes analyzed: {len(report)}"
    )

    lines.append(
        f"Processes with findings: "
        f"{processes_with_findings}"
    )

    lines.append(
        f"Processes with zero risk: "
        f"{len(report) - processes_with_findings}"
    )

    lines.append("\nNOTE")
    lines.append("-" * 60)

    lines.append(
        "A risk score is not proof of malicious activity."
    )

    lines.append(
        "The simulated test process uses synthetic data."
    )

    lines.append(
        "No real keystrokes were captured."
    )

    return "\n".join(lines)


# --------------------------------------------------
# 5. DISPLAY REPORT POPUP
# --------------------------------------------------

def show_popup(report_text):

    root = tk.Tk()

    root.title(
        "Cyber-Keylogger Research - Detection Report"
    )

    root.geometry("900x650")

    text_area = ScrolledText(
        root,
        wrap=tk.WORD,
        font=("Consolas", 10),
    )

    text_area.pack(
        fill=tk.BOTH,
        expand=True,
        padx=10,
        pady=10,
    )

    text_area.insert(
        tk.END,
        report_text,
    )

    text_area.configure(
        state=tk.DISABLED
    )

    root.mainloop()


# --------------------------------------------------
# 6. MAIN PROGRAM
# --------------------------------------------------

def main():

    # Run tests
    test_result = run_tests()

    # Scan actual running processes
    report = scan_system()

    # Run safe simulated detection
    demo_result = run_simulated_detection()

    # Add simulated detection to main report
    report.append({
        "pid": demo_result["pid"],
        "name": demo_result["name"],
        "path": "SIMULATED TEST PROCESS",
        "signature": "NotSigned",
        "score": demo_result["score"],
        "level": demo_result["level"],
        "reasons": demo_result["reasons"],
    })

    # Sort by risk score
    report.sort(
        key=lambda item: item["score"],
        reverse=True,
    )

    # Create report
    report_text = create_report(
        test_result,
        report,
    )

    # Print report in terminal
    print("\n")
    print(report_text)

    # Display popup
    print("\nOpening report popup...")

    show_popup(report_text)


if __name__ == "__main__":
    main()
