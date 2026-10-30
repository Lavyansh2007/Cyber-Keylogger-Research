
import time
import os

from .models import ProcessInfo
from .findings import DetectionFinding
from .process_scanner import scan_processes
from .executable_analyzer import get_imported_functions
from .indicators import KEYBOARD_INPUT_APIS
from .rules import (
    check_missing_executable,
    check_keyboard_input_apis,
    check_suspicious_file_location,
)
from .file_metadata import get_executable_metadata
from .signature_analyzer import get_signature_info
from .risk_scoring import calculate_risk_score


def analyze_process_with_signature(
    process: ProcessInfo,
) -> tuple[list[DetectionFinding], str | None]:

    findings = []

    # 1. Check whether the executable path is available.
    missing_finding = check_missing_executable(process)

    if missing_finding is not None:
        findings.append(missing_finding)

    if not process.executable:
        return findings, None

    # 2. Check that the executable is an accessible file.
    metadata = get_executable_metadata(process.executable)

    print(
        f"[ANALYZE] {process.name} | "
        f"size={metadata.size}"
    )

    if not metadata.exists:
        print(
            f"[SKIP] {process.name} | "
            "executable is not an accessible file"
        )
        return findings, None

    location_finding = check_suspicious_file_location(process)

    if location_finding is not None:
        findings.append(location_finding)

    executable_path = os.path.normcase(
        os.path.abspath(process.executable)
    )

    # 3. Check the digital signature.
    start_time = time.perf_counter()
    signature = get_signature_info(executable_path)

    print(
        f"[SIGNATURE] {process.name} | "
        f"status={signature.status} | "
        f"signer={signature.signer}"
    )

    print(
        f"[TIMING] Signature check took "
        f"{time.perf_counter() - start_time:.2f} seconds"
    )

    # 4. Inspect imported PE functions.
    
    # 4. Inspect imported PE functions.
    imports = get_imported_functions(process.executable)

    print(
        f"[DEBUG] {process.name} | "
        f"import_count={len(imports)}"
    )

    # 5. Check keyboard/input API indicators.
    keyboard_findings = check_keyboard_input_apis(
        process,
        imports,
        signature,
    )

    print(
        f"[DEBUG] {process.name} | "
        f"keyboard_findings={len(keyboard_findings)}"
    )

    for finding in keyboard_findings:
        print(
            f"[FINDING] {finding.rule_name} | "
            f"severity={finding.severity}"
        )

    findings.extend(keyboard_findings)

    print(
        f"[DEBUG] {process.name} | "
        f"total_findings={len(findings)}"
    )

    return findings, signature.status



def analyze_process(
    process: ProcessInfo,
) -> list[DetectionFinding]:
    """Compatibility wrapper returning findings only."""
    findings, _ = analyze_process_with_signature(process)
    return findings



def analyze_system() -> list[DetectionFinding]:
    """Analyze scanned processes and deduplicate findings."""
    processes = scan_processes()
    unique_findings = {}

    for process in processes:
        findings, _ = analyze_process_with_signature(process)

        executable_path = None

        if process.executable:
            executable_path = os.path.normcase(
                os.path.abspath(process.executable)
            )

        for finding in findings:
            key = (
                executable_path,
                finding.rule_name,
                finding.pid,
            )

            if key not in unique_findings:
                unique_findings[key] = finding

    all_findings = list(unique_findings.values())
    print(f"[DEBUG] Final findings count: {len(all_findings)}")

    return all_findings



if __name__ == "__main__":
    processes = scan_processes()

    findings_by_pid = {}
    signature_status_by_pid = {}
    process_name_by_pid = {}
    executable_by_pid = {}

    # Analyze each process only once.
    for process in processes:
        process_findings, signature_status = (
            analyze_process_with_signature(process)
        )

        findings_by_pid[process.pid] = process_findings
        signature_status_by_pid[process.pid] = signature_status
        process_name_by_pid[process.pid] = process.name
        executable_by_pid[process.pid] = process.executable

        for finding in process_findings:
            print(finding)

    # Calculate risk scores and prepare the report.
    report = []

    for pid, process_findings in findings_by_pid.items():
        signature_status = signature_status_by_pid.get(pid)

        score, level, reasons = calculate_risk_score(
            process_findings,
            signature_status,
        )

        report.append({
            "pid": pid,
            "name": process_name_by_pid.get(pid, "Unknown"),
            "signature": signature_status or "Not available",
            "score": score,
            "level": level,
            "reasons": reasons,
            "path": executable_by_pid.get(pid) or "Unknown",
        })

    # Sort once, after collecting all processes.
    report.sort(key=lambda item: item["score"], reverse=True)

    # Count processes in each risk category.
    risk_counts = {"HIGH": 0, "MEDIUM": 0, "LOW": 0}
    scored_processes = 0

    for item in report:
        if item["score"] == 0:
            continue

        risk_counts[item["level"]] += 1
        scored_processes += 1

    # Print the report only once.
        # Print the report only once.
    print("\n========== PROCESS RISK REPORT ==========")

    for item in report:
        print(f"\nProcess: {item['name']}")
        print(f"PID: {item['pid']}")
        print(f"Signature Status: {item['signature']}")
        print(f"Risk Score: {item['score']}/100")
        print(f"Risk Level: {item['level']}")

        if item["reasons"]:
            for reason in item["reasons"]:
                print(f"- {reason}")
        else:
            print("- No suspicious indicators detected.")

        print(f"Executable Path: {item['path']}")

    print("\nRisk Summary:")
    print(f"HIGH: {risk_counts['HIGH']}")
    print(f"MEDIUM: {risk_counts['MEDIUM']}")
    print(f"LOW: {risk_counts['LOW']}")
    print(f"Processes analyzed: {len(report)}")
    print(f"Processes with findings: {scored_processes}")
    print(f"Processes with zero risk: {len(report) - scored_processes}")
    print("=========================================")