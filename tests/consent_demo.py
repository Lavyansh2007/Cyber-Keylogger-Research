"""
Consent-based activity simulator for defensive cybersecurity testing.

This program does NOT:
- Capture real keyboard input
- Install keyboard hooks
- Store keystrokes
- Run in the background

It only prints simulated activity.
"""

def run_demo():
    print("===================================")
    print(" Consent-Based Detection Demo")
    print("===================================")

    consent = input(
        "This demo will display simulated activity only.\n"
        "Do you consent to run it? (yes/no): "
    ).strip().lower()

    if consent != "yes":
        print("Demo cancelled.")
        return

    print("\nStarting simulated activity...\n")

    simulated_events = [
        "Simulated keyboard API accessed",
        "Simulated keyboard hook requested",
        "Simulated activity ended"
    ]

    for event in simulated_events:
        print("[SIMULATED]", event)

    print("\nDemo completed.")
    print("No real keyboard input was captured or stored.")


if __name__ == "__main__":
    run_demo()