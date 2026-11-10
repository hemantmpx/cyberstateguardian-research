"""Sample a process tree without storing command lines, environment variables, or secrets."""

from __future__ import annotations

import argparse
import json
import os
import threading
import time
from pathlib import Path

import psutil


class ResourceMonitor:
    def __init__(self, pid: int | None = None, interval: float = 0.05):
        if interval <= 0:
            raise ValueError("sampling interval must be positive")
        self.root = psutil.Process(pid or os.getpid())
        self.interval = interval
        self.stop = threading.Event()
        self.cpu = {}
        self.peak_rss = 0
        self.samples = 0
        self.errors = 0

    def sample(self):
        try:
            processes = [self.root, *self.root.children(recursive=True)]
        except psutil.Error:
            self.errors += 1
            return
        rss = 0
        for process in processes:
            try:
                key = (process.pid, process.create_time())
                times = process.cpu_times()
                value = times.user + times.system
                initial, previous = self.cpu.get(key, (value, value))
                # Children born after monitoring started have zero initial CPU usage.
                if key not in self.cpu and key[1] >= self.started_epoch:
                    initial = 0.0
                self.cpu[key] = (initial, max(value, previous))
                rss += process.memory_info().rss
            except psutil.Error:
                self.errors += 1
        self.peak_rss = max(self.peak_rss, rss)
        self.samples += 1

    def __enter__(self):
        self.started_epoch = time.time()
        self.started = time.perf_counter()
        self.sample()
        self.thread = threading.Thread(target=self._loop, daemon=True)
        self.thread.start()
        return self

    def _loop(self):
        while not self.stop.wait(self.interval):
            self.sample()

    def __exit__(self, *_):
        self.stop.set()
        self.thread.join()
        self.sample()
        self.elapsed = time.perf_counter() - self.started

    def result(self):
        return {
            "wall_seconds": self.elapsed,
            "sampled_process_tree_cpu_seconds": sum(
                end - start for start, end in self.cpu.values()
            ),
            "sampled_peak_process_tree_rss_bytes": self.peak_rss,
            "observed_processes": len(self.cpu),
            "samples": self.samples,
            "sampling_errors": self.errors,
            "interval_seconds": self.interval,
            "limitation": "Sampled lower bound: short-lived children may be missed; RSS sums "
            "can double-count shared pages. Includes monitor overhead.",
        }


def main():
    parser = argparse.ArgumentParser(
        description="Measure an existing process and its child processes"
    )
    parser.add_argument("--pid", type=int, required=True)
    parser.add_argument("--seconds", type=float, default=60)
    parser.add_argument("--interval", type=float, default=0.05)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    if args.seconds <= 0:
        parser.error("--seconds must be positive")
    with ResourceMonitor(args.pid, args.interval) as monitor:
        time.sleep(args.seconds)
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(monitor.result(), indent=2))


if __name__ == "__main__":
    main()
