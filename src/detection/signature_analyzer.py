
import json
import os
import platform
import subprocess
from functools import lru_cache

from .models import SignatureInfo


@lru_cache(maxsize=256)
def get_signature_info(
    executable_path: str
) -> SignatureInfo:

    if not executable_path:
        return SignatureInfo(
            status="NOT_APPLICABLE",
            signer=None
        )

    system = platform.system()

    if system == "Windows":
        return get_windows_signature(executable_path)

    elif system == "Linux":
        return get_linux_signature(executable_path)

    else:
        return SignatureInfo(
            status="NOT_APPLICABLE",
            signer=None
        )


def get_windows_signature(
    executable_path: str
) -> SignatureInfo:

    powershell_command = """
    $path = $env:TARGET_EXE
    $sig = Get-AuthenticodeSignature -LiteralPath $path

    $result = [PSCustomObject]@{
        Status = [int]$sig.Status
        Signer = if ($sig.SignerCertificate) {
            $sig.SignerCertificate.Subject
        } else {
            $null
        }
    }

    $result | ConvertTo-Json -Compress
    """

    try:
        env = os.environ.copy()
        env["TARGET_EXE"] = executable_path

        result = subprocess.run(
            [
                "powershell.exe",
                "-NoProfile",
                "-Command",
                powershell_command
            ],
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=3,
            env=env
        )

        if result.returncode != 0:
            return SignatureInfo(
                status="ERROR",
                signer=None
            )

        if not result.stdout.strip():
            return SignatureInfo(
                status="ERROR",
                signer=None
            )

        data = json.loads(result.stdout)

        status_value = data.get("Status")

        if status_value == 0:
            status = "Valid"
        elif status_value == 1:
            status = "NotTrusted"
        elif status_value == 2:
            status = "NotSigned"
        elif status_value == 3:
            status = "UnknownError"
        elif status_value == 4:
            status = "HashMismatch"
        else:
            status = f"Unknown({status_value})"

        return SignatureInfo(
            status=status,
            signer=data.get("Signer")
        )

    except subprocess.TimeoutExpired:
        return SignatureInfo(
            status="TIMEOUT",
            signer=None
        )

    except KeyboardInterrupt:
        raise

    except (
        json.JSONDecodeError,
        OSError,
        ValueError
    ):
        return SignatureInfo(
            status="ERROR",
            signer=None
        )


def get_linux_signature(
    executable_path: str
) -> SignatureInfo:

    # Linux executables do not use Windows Authenticode.
    # Signature verification for Linux will be implemented
    # separately using a suitable Linux signing mechanism.

    return SignatureInfo(
        status="NOT_APPLICABLE",
        signer=None
    )
