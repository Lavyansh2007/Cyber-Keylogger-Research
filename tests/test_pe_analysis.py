from src.detection.executable_analyzer import get_imported_functions

path = r"C:\Windows\System32\user32.dll"

imports = get_imported_functions(path)

print("Imported functions found:", len(imports))

for imported in imports:
    print(f"{imported['dll']} -> {imported['api']}")