import ctypes

# Load Windows keyboard-related API library.
user32 = ctypes.WinDLL("user32")

# Access the API without capturing or storing any keystrokes.
api = user32.GetAsyncKeyState

print("Test program running.")
print("Loaded API:", api.__name__)
print("No keyboard input captured.")