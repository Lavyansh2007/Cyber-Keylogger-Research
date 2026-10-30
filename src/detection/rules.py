import os
from .models import ProcessInfo,ImportedFunction,SignatureInfo
from .findings import DetectionFinding, Severity
from .indicators import KEYBOARD_INPUT_APIS

from pathlib import Path


def check_suspicious_file_location(
    process: ProcessInfo,
) -> DetectionFinding | None:

    if not process.executable:
        return None

    # Expand environment variables and normalize path separators.
    path = os.path.expandvars(process.executable)
    path = path.replace("\\", "/")

    # Extract folder names from the path.
    parts = {
        part.casefold()
        for part in path.split("/")
        if part
    }

    matched_locations = []

    # Check temporary directories.
    if "temp" in parts or "tmp" in parts:
        matched_locations.append("temporary_directory")

    # Check Downloads directories.
    if "downloads" in parts:
        matched_locations.append("downloads_directory")

    if not matched_locations:
        return None

    return DetectionFinding(
        rule_name="SUSPICIOUS_FILE_LOCATION",
        severity=Severity.LOW,
        description=(
            "Executable runs from a temporary or Downloads location; "
            "this alone does not prove malicious activity."
        ),
        pid=process.pid,
        process_name=process.name,
        evidence={
            "path": path,
            "matched_locations": matched_locations,
        },
    )

    if not process.executable:
        return None

    path = Path(
        os.path.expandvars(process.executable)
    ).resolve()

    # Get folder names from the executable path.
    parts = {
        part.casefold()
        for part in path.parts
    }

    matched_locations = []

    # Check temporary folders.
    if "temp" in parts or "tmp" in parts:
        matched_locations.append("temporary_directory")

    # Check Downloads folder.
    if "downloads" in parts:
        matched_locations.append("downloads_directory")

    if not matched_locations:
        return None

    return DetectionFinding(
        rule_name="SUSPICIOUS_FILE_LOCATION",
        severity=Severity.LOW,
        description=(
            "Executable runs from a temporary or Downloads location; "
            "this alone does not prove malicious activity."
        ),
        pid=process.pid,
        process_name=process.name,
        evidence={
            "path": str(path),
            "matched_locations": matched_locations,
        },
    )

import platform


def check_missing_executable(
    process: ProcessInfo
) -> DetectionFinding | None:

    if process.executable is not None:
        return None

    # Linux kernel threads normally do not have executable paths.
    if platform.system() == "Linux":
        if process.name.startswith(("kworker", "kthread", "kernel")):
            return None

    # Preserve the existing Windows behavior.
    if process.name == "System Idle Process":
        return None

    return DetectionFinding(
        rule_name="MISSING_EXECUTABLE",
        severity=Severity.LOW,
        description="Executable path could not be accessed.",
        pid=process.pid,
        process_name=process.name,
        evidence={
            "executable": None
        }
    )

def check_keyboard_input_apis(process, imports, signature):
    findings = []

    keyboard_apis = {
        api.lower() for api in KEYBOARD_INPUT_APIS
    }

    matched_apis = []

    for imported in imports:

        # Support both ImportedFunction objects and dictionaries
        if isinstance(imported, dict):
            api_name = imported.get("api", imported.get("function", ""))
            dll_name = imported.get("dll", "")
        else:
            api_name = imported.function
            dll_name = imported.dll

        if api_name.lower() in keyboard_apis:
            matched_apis.append({
                "dll": dll_name,
                "api": api_name
            })

    if matched_apis:
        findings.append(
            DetectionFinding(
                rule_name="KEYBOARD_INPUT_API",
                severity=Severity.LOW,
                description=(
                    "Executable imports keyboard/input APIs. "
                    "Imports alone do not establish malicious behaviour."
                ),
                pid=process.pid,
                process_name=process.name,
                evidence={
                    "matched_apis": matched_apis,
                    "api_count": len(matched_apis),
                    "signature_status": signature.status,
                    "signer": signature.signer
                }
            )
        )

    return findings