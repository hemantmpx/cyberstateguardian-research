"""Summarize a paired, single-host CSG probe operational-overhead pilot."""

from __future__ import annotations

import argparse
import hashlib
import json
import statistics
from collections import Counter, defaultdict
from pathlib import Path
from typing import Any

METRICS = (
    "host_cpu_percent",
    "available_memory_mib",
    "probe_cpu_percent_of_host_capacity",
    "probe_working_set_mib",
    "wazuh_cpu_percent_of_host_capacity",
    "wazuh_working_set_mib",
)


def load_samples(path: Path) -> list[dict[str, Any]]:
    with path.open(encoding="utf-8-sig") as handle:
        return [json.loads(line) for line in handle if line.strip()]


def summarize(samples: list[dict[str, Any]], metadata: dict[str, Any]) -> dict[str, Any]:
    if metadata.get("status") != "completed":
        raise ValueError(f"run is not complete: {metadata.get('status')}")
    cleanup = metadata.get("cleanup")
    if cleanup is not None and not all(
        cleanup.get(key) is True for key in ("task_running", "task_enabled", "wazuh_running")
    ):
        raise ValueError("post-run probe/Wazuh restoration checks failed")
    grouped: dict[str, dict[str, list[dict[str, Any]]]] = defaultdict(lambda: defaultdict(list))
    for row in samples:
        grouped[row["pair_id"]][row["condition"]].append(row)

    expected_pairs = int(metadata["pairs"])
    if len(grouped) != expected_pairs:
        raise ValueError(f"expected {expected_pairs} pairs, found {len(grouped)}")
    expected_samples = int(metadata["measurement_seconds_per_condition"]) // int(
        metadata["sample_period_seconds"]
    )

    pairs = []
    orders = {}
    for pair_id in sorted(grouped):
        conditions = grouped[pair_id]
        if set(conditions) != {"probe_on", "probe_off"}:
            raise ValueError(f"{pair_id} does not contain exactly one ON and OFF phase")
        ordered_conditions = []
        for condition in ("probe_on", "probe_off"):
            rows = conditions[condition]
            if len(rows) != expected_samples:
                raise ValueError(
                    f"{pair_id}/{condition} has {len(rows)} samples; expected {expected_samples}"
                )
            positions = {row["order_position"] for row in rows}
            if len(positions) != 1:
                raise ValueError(f"{pair_id}/{condition} has inconsistent order positions")
            ordered_conditions.append((int(next(iter(positions))), condition))
        ordered_conditions.sort()
        if [position for position, _ in ordered_conditions] != [1, 2]:
            raise ValueError(f"{pair_id} has invalid phase order positions")
        order = [condition for _, condition in ordered_conditions]
        plan_order = next(
            (item["order"] for item in metadata["randomized_plan"] if item["pair_id"] == pair_id),
            None,
        )
        if order != plan_order:
            raise ValueError(f"{pair_id} sample order does not match frozen randomized plan")
        orders[pair_id] = order
        summaries: dict[str, dict[str, float | int | None]] = {}
        for condition, rows in conditions.items():
            if not rows:
                raise ValueError(f"{pair_id}/{condition} has no samples")
            for row in rows:
                if row["wazuh_service_state"] != "Running":
                    raise ValueError(f"Wazuh was not running in {pair_id}/{condition}")
                if condition == "probe_on" and row["probe_process_count"] < 1:
                    raise ValueError(f"probe process absent in {pair_id}/{condition}")
                if condition == "probe_off" and row["probe_process_count"] != 0:
                    raise ValueError(f"probe process present in {pair_id}/{condition}")
                if row["probe_task_state"] not in (
                    {"Running"} if condition == "probe_on" else {"Disabled"}
                ):
                    raise ValueError(
                        f"unexpected task state in {pair_id}/{condition}: {row['probe_task_state']}"
                    )
            summaries[condition] = {
                "sample_count": len(rows),
                **{
                    metric: _median([r[metric] for r in rows if r.get(metric) is not None])
                    for metric in METRICS
                },
            }
        differences = {
            metric: _round_or_none(
                summaries["probe_on"][metric] - summaries["probe_off"][metric]
                if summaries["probe_on"][metric] is not None
                and summaries["probe_off"][metric] is not None
                else None
            )
            for metric in METRICS
        }
        pairs.append(
            {
                "pair_id": pair_id,
                "order": order,
                "conditions": summaries,
                "on_minus_off": differences,
            }
        )

    aggregate = {}
    for metric in METRICS:
        values = [p["on_minus_off"][metric] for p in pairs if p["on_minus_off"][metric] is not None]
        aggregate[metric] = {
            "paired_block_count": len(values),
            "median_on_minus_off": _round_or_none(statistics.median(values)) if values else None,
            "mean_on_minus_off": _round_or_none(statistics.mean(values)) if values else None,
            "min_on_minus_off": _round_or_none(min(values)) if values else None,
            "max_on_minus_off": _round_or_none(max(values)) if values else None,
            "paired_block_differences": values,
        }
    condition_aggregate = {}
    for metric in METRICS:
        condition_aggregate[metric] = {}
        for condition in ("probe_on", "probe_off"):
            values = [
                pair["conditions"][condition][metric]
                for pair in pairs
                if pair["conditions"][condition][metric] is not None
            ]
            condition_aggregate[metric][condition] = {
                "paired_block_count": len(values),
                "median": _round_or_none(statistics.median(values)) if values else None,
                "min": _round_or_none(min(values)) if values else None,
                "max": _round_or_none(max(values)) if values else None,
            }
    order_counts = Counter(" -> ".join(order) for order in orders.values())
    balanced = len(order_counts) == 2 and all(
        count == expected_pairs // 2 for count in order_counts.values()
    )
    return {
        "experiment_id": metadata.get("experiment_id"),
        "status": metadata.get("status"),
        "host": metadata.get("windows"),
        "pairs": pairs,
        "aggregate": aggregate,
        "condition_aggregate": condition_aggregate,
        "realized_order_counts": dict(order_counts),
        "realized_order_balanced": balanced,
        "interpretation_limit": (
            "Exploratory repeated-measures pilot on one VM. The paired blocks, not individual "
            "samples, are the replication units; no broad performance or detection claim "
            "is supported."
        ),
    }


def _median(values: list[float | int]) -> float | None:
    return _round_or_none(statistics.median(values)) if values else None


def _round_or_none(value: float | None) -> float | None:
    return round(value, 4) if value is not None else None


def _display_path(path: Path) -> str:
    resolved = path.resolve()
    try:
        return resolved.relative_to(Path.cwd().resolve()).as_posix()
    except ValueError:
        return path.as_posix()


def write_report(result: dict[str, Any], out_dir: Path, source_paths: list[Path]) -> None:
    out_dir.mkdir(parents=True, exist_ok=True)
    json_path = out_dir / "summary.json"
    json_path.write_text(json.dumps(result, indent=2) + "\n", encoding="utf-8")
    lines = [
        "# CSG Probe Overhead Pilot",
        "",
        f"Status: **{result['status']}**",
        "",
        "## Scope",
        "",
        (
            "This is an exploratory paired ON/OFF operational-overhead measurement on one Windows "
            "VM. Wazuh remained enabled in both conditions. The probe scheduled task was the only "
            "treatment changed. No security behavior or persistent host object was mutated. This "
            "experiment says nothing about malicious-activity detection or cross-host "
            "generalization."
        ),
        "",
        (
            f"Host: `{result['host']['caption']}`, Windows `{result['host']['version']}` "
            f"build `{result['host']['build']}`, {result['host']['architecture']}, "
            f"{result['host']['total_memory_mib']} MiB guest RAM"
        ),
        f"Paired blocks: {len(result['pairs'])}",
        "",
        "## Paired results",
        "",
        (
            "For ON and OFF columns, each value is the median across the six phase-level medians. "
            "For the difference column, ON minus OFF is calculated within each pair, then "
            "summarized across pairs. Five-second samples within each phase are repeated "
            "measurements, "
            "not independent trials."
        ),
        "",
        "| Metric | ON median (range) | OFF median (range) | "
        "ON - OFF median (range) | Paired contrasts (n) |",
        "|---|---:|---:|---:|---:|",
    ]
    labels = {
        "host_cpu_percent": "Host CPU utilization (percentage points)",
        "available_memory_mib": "Available memory (MiB)",
        "probe_cpu_percent_of_host_capacity": "Probe CPU (percent of host capacity)",
        "probe_working_set_mib": "Probe working set (MiB)",
        "wazuh_cpu_percent_of_host_capacity": "Wazuh CPU (percent of host capacity)",
        "wazuh_working_set_mib": "Wazuh working set (MiB)",
    }
    for metric, label in labels.items():
        item = result["aggregate"][metric]
        on = result["condition_aggregate"][metric]["probe_on"]
        off = result["condition_aggregate"][metric]["probe_off"]
        on_text = (
            f"{on['median']} ({on['min']} to {on['max']})"
            if on["median"] is not None
            else "not measured"
        )
        off_text = (
            f"{off['median']} ({off['min']} to {off['max']})"
            if off["median"] is not None
            else "not measured"
        )
        difference = (
            f"{item['median_on_minus_off']} "
            f"({item['min_on_minus_off']} to {item['max_on_minus_off']})"
            if item["median_on_minus_off"] is not None
            else "not applicable"
        )
        lines.append(
            f"| {label} | {on_text} | {off_text} | {difference} | "
            f"{item['paired_block_count']} paired differences |"
        )
    lines.extend(
        [
            "",
            "## Per-block data",
            "",
            "| Pair | Order | Host CPU delta (pp) | Available memory delta (MiB) | "
            "Probe CPU ON (% host) | Probe RSS ON (MiB) |",
            "|---|---|---:|---:|---:|---:|",
        ]
    )
    for pair in result["pairs"]:
        on = pair["conditions"]["probe_on"]
        diff = pair["on_minus_off"]
        lines.append(
            f"| {pair['pair_id']} | {' -> '.join(pair['order'])} | "
            f"{diff['host_cpu_percent']} | {diff['available_memory_mib']} | "
            f"{on['probe_cpu_percent_of_host_capacity']} | {on['probe_working_set_mib']} |"
        )
    lines.extend(
        [
            "",
            "## Interpretation and limitations",
            "",
            _order_note(result),
            "",
            (
                "Treat these values as a local operational baseline, not a benchmark. One host and "
                "few blocks, background activity, and measurement-tool overhead limit inference. "
                "Report the paired-block range and raw samples; within-phase measurements are not "
                "independent trials. A stronger study repeats across days and workload "
                "strata, using "
                "a pre-registered sample size and independent machines."
            ),
            "",
            "## Artifacts",
            "",
            "| File | SHA-256 |",
            "|---|---|",
        ]
    )
    for path in sorted(source_paths):
        lines.append(f"| `{_display_path(path)}` | `{_sha256(path)}` |")
    lines.append(f"| `summary.json` | `{_sha256(json_path)}` |")
    results_path = out_dir / "RESULTS.md"
    results_path.write_text("\n".join(lines) + "\n", encoding="utf-8")
    manifest_files = [
        {"file": _display_path(path), "sha256": _sha256(path), "bytes": path.stat().st_size}
        for path in sorted(source_paths)
    ]
    manifest_files.extend(
        {"file": path.name, "sha256": _sha256(path), "bytes": path.stat().st_size}
        for path in (json_path, results_path)
    )
    manifest = {
        "manifest_scope": "run artifacts and analysis sources; manifest does not hash itself",
        "files": manifest_files,
    }
    (out_dir / "artifact-manifest.json").write_text(
        json.dumps(manifest, indent=2) + "\n", encoding="utf-8"
    )


def _order_note(result: dict[str, Any]) -> str:
    observed = "; ".join(
        f"{count} {order}" for order, count in result["realized_order_counts"].items()
    )
    if result["realized_order_balanced"]:
        order_text = f"Order audit: {observed}. The predeclared order balance was achieved."
    else:
        order_text = (
            f"Order audit: {observed}. The imbalance is retained, not hidden; "
            "the next run should use constrained balanced order."
        )
    return (
        order_text
        + " Host-wide CPU and memory changes are descriptive and cannot be attributed to the probe "
        "from this run."
    )


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--samples", type=Path, required=True)
    parser.add_argument("--metadata", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--artifact", type=Path, action="append", default=[])
    args = parser.parse_args()
    samples = load_samples(args.samples)
    metadata = json.loads(args.metadata.read_text(encoding="utf-8-sig"))
    result = summarize(samples, metadata)
    sources = [args.samples, args.metadata, Path(__file__), *args.artifact]
    write_report(result, args.output, sources)
    print(f"Wrote {args.output / 'RESULTS.md'} with {len(result['pairs'])} paired blocks.")


if __name__ == "__main__":
    main()
