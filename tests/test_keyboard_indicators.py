from src.detection.models import ProcessInfo, ImportedFunction
from src.detection.rules import check_keyboard_input_apis
from src.detection.models import SignatureInfo

process = ProcessInfo(pid=1234, name="test.exe",executable=r"C:\Test\test.exe", username="TestUser")

imports = [ImportedFunction(dll="USER32.dll", function="GetAsyncKeyState"),
           ImportedFunction(dll="KERNEL32.dll", function="VirtualAlloc")]
signature = SignatureInfo(
    status="Valid",
    signer="Test Signer"
)
findings = check_keyboard_input_apis(process, imports,signature)

for finding in findings:
    print(finding)
    