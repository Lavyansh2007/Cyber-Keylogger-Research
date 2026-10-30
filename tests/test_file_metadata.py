from src.detection.file_metadata import get_executable_metadata

path = r"C:\Windows\explorer.exe"

metadata = get_executable_metadata(path)

print(metadata)