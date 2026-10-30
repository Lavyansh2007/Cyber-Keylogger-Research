import time
from datetime import datetime

LOG_FILE = "demo_log.txt"
DURATION = 30  # seconds


def simulate_activity():
    events = [
        "Keyboard input API requested",
        "Keyboard activity detected",
        "Input monitoring simulation started",
        "Input monitoring simulation stopped",
    ]

    print("\n=== Cyber-Keylogger Research Demo ===")
    print("Simulated activity only.")
    print("No real keystrokes are recorded.\n")

    start_time = time.time()

    with open(LOG_FILE, "w", encoding="utf-8") as log:

        log.write("=== Simulated Activity Log ===\n")

        while time.time() - start_time < DURATION:

            for event in events:

                if time.time() - start_time >= DURATION:
                    break

                timestamp = datetime.now().strftime(
                    "%Y-%m-%d %H:%M:%S"
                )

                message = f"[{timestamp}] {event}"

                print(message)
                log.write(message + "\n")
                log.flush()

                time.sleep(1)

    print("\nDemo completed.")
    print(f"Duration: {DURATION} seconds")
    print(f"Log saved to: {LOG_FILE}")


if __name__ == "__main__":
    simulate_activity()