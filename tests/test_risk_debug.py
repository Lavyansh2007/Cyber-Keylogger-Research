
from src.detection.risk_scoring import calculate_risk_score
from src.detection.findings import DetectionFinding, Severity

finding = DetectionFinding(
    rule_name="KEYBOARD_INPUT_API",
    severity=Severity.LOW,
    description="Synthetic test finding",
    pid=1234,
    process_name="TestProcess.exe",
    evidence={}
)

score, level, reasons = calculate_risk_score(
    [finding],
    "Valid"
)

print("Score:", score)
print("Level:", level)
print("Reasons:", reasons)

assert score == 5
assert level == "LOW"
