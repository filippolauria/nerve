import threading
from bin.scanner import scanner
from bin.attacker import attacker
from bin.scheduler import scheduler


def start_workers():
    workers = [
        ("scanner", scanner),
        ("attacker", attacker),
        ("scheduler", scheduler)
    ]

    for name, target in workers:
        thread = threading.Thread(target=target, name=name, daemon=True)
        thread.start()
