from dataclasses import dataclass


@dataclass
class ProcessInfo:
    pid: int
    name: str
    executable: str | None
    username: str | None

@dataclass
class ImportedFunction:
    dll : str
    function: str

@dataclass
class ExecutableMetadata:
    path: str | None
    exists: bool
    size: int | None

@dataclass
class SignatureInfo:
    status: str
    signer: str | None

@dataclass
class ExecutableMetadata:
    path: str | None
    exists: bool
    size: int | None

@dataclass
class SignatureInfo:
    status: str
    signer: str | None