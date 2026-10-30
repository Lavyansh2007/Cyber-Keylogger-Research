from types import SimpleNamespace

from src.detection.rules import check_keyboard_input_apis
from src.detection.models import ImportedFunction
from src.detection.models import SignatureInfo


process = SimpleNamespace(
    pid=1234,
    name="TestApplication",
    executable=None,
)

imports = [
    ImportedFunction(
        dll="USER32.dll",
        function="GetAsyncKeyState"
    )
]

signature = SignatureInfo(
    status="NotSigned",
    signer=None
)

findings = check_keyboard_input_apis(
    process,
    imports,
    signature
)

for finding in findings:
    print(f"Rule: {finding.rule_name}")
    print(f"Severity: {finding.severity}")
    print(f"Description: {finding.description}")
    print(f"Evidence: {finding.evidence}")