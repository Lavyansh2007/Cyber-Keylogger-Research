from dataclasses import dataclass
from enum import Enum

class Severity(Enum):
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"

@dataclass
class DetectionFinding:
    rule_name: str
    severity: Severity
    description: str
    pid: int
    process_name: str
    evidence: dict