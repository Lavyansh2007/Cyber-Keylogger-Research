from src.detection.signature_analyzer import get_signature_info

path = r"C:\Windows\explorer.exe"

signature = get_signature_info(path)
print(signature)