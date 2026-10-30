from pathlib import Path
from .models import ExecutableMetadata

def get_executable_metadata(executable_path: str) -> ExecutableMetadata:
    path = Path(executable_path)

    try:
        if not path.exists():
            return ExecutableMetadata(path=str(path), exists=False, size=None)

        return ExecutableMetadata(path=str(path),exists=True,size=path.stat().st_size)
    except (OSError, PermissionError):
        return ExecutableMetadata(path=str(path), exists=False, size=None)