import psutil 

from .models import ProcessInfo

def scan_processes() -> list[ProcessInfo]:
    processes = []
    for process in psutil.process_iter(
        ["pid","name","exe","username"]
    ):
        try:
            info = process.info
            process_info = ProcessInfo(
                pid=info["pid"],
                name=info["name"] or "Unknown",
                executable=info["exe"],
                username=info["username"]
            )
            processes.append(process_info)
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            continue
    return processes
if __name__ == "__main__":
    processes = scan_processes()

    for process in processes:
        print(process)
