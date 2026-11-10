"""Migrate the current result set into a readable published/runs layout."""

from __future__ import annotations

import argparse
import json
import shutil
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
RESULTS = ROOT / "experiments/results"
PUBLISHED = RESULTS / "published"
RUNS = RESULTS / "runs"


def move_one(source: Path, destination: Path, moved: list[dict[str, str]]) -> None:
    if not source.exists():
        return
    destination.parent.mkdir(parents=True, exist_ok=True)
    if destination.exists():
        raise FileExistsError(f"refusing to overwrite {destination}")
    shutil.move(str(source), str(destination))
    moved.append({"from": str(source.relative_to(ROOT)), "to": str(destination.relative_to(ROOT))})


def replace_paths(value: Any, mapping: dict[str, str]) -> Any:
    if isinstance(value, str):
        return mapping.get(value, value)
    if isinstance(value, list):
        return [replace_paths(item, mapping) for item in value]
    if isinstance(value, dict):
        return {key: replace_paths(item, mapping) for key, item in value.items()}
    return value


def migrate() -> dict[str, Any]:
    moved: list[dict[str, str]] = []
    mapping: dict[str, str] = {}

    published_names = (
        "RESEARCH_RESULTS_DETAILED-20260923.md",
        "research-freeze-20260923.json",
        "live-telemetry-campaign-summary-20260923.json",
        "windows-apt-2025-import-summary-20260923.json",
        "windows-apt-2025-evaluation-20260923.json",
        "incident-correlation-expanded-20260923.json",
        "incident-correlation-adversarial-20260923.json",
        "authorization-study-20260923.json",
        "reconciliation-evidence-audit-20260923.json",
    )
    for name in published_names:
        source = RESULTS / name
        destination = PUBLISHED / name
        move_one(source, destination, moved)
        if destination.exists():
            mapping[str(source.relative_to(ROOT))] = str(destination.relative_to(ROOT))

    dated = RUNS / "20260923"
    run_files = {
        "ai-context-live-20260923.json": dated / "ai-context-legacy" / "study.json",
        "ai-context-live-20260923-blinded-review.json": dated
        / "ai-context-legacy"
        / "blinded-review.json",
        "ai-context-live-20260923-answer-key.private.json": dated
        / "ai-context-legacy"
        / "answer-key.private.json",
        "ai-context-live-20260923-ollama.json": dated / "ai-context-ollama" / "study.json",
        "ai-context-live-20260923-ollama-blinded-review.json": dated
        / "ai-context-ollama"
        / "blinded-review.json",
        "ai-context-live-20260923-ollama-answer-key.private.json": dated
        / "ai-context-ollama"
        / "answer-key.private.json",
        "wazuh-events-live-20260923.json": dated / "live-reconciliation" / "event-capture.json",
    }
    for name, destination in run_files.items():
        source = RESULTS / name
        move_one(source, destination, moved)
        if destination.exists():
            mapping[str(source.relative_to(ROOT))] = str(destination.relative_to(ROOT))

    legacy_2022 = RUNS / "20260922" / "native-probe"
    for name, target in {
        "csg-pre-native-20260922.dump": legacy_2022 / "pre-native.dump",
        "research-service-drift-result-20260922.json": legacy_2022 / "service-drift.json",
    }.items():
        source = RESULTS / name
        move_one(source, target, moved)
        if target.exists():
            mapping[str(source.relative_to(ROOT))] = str(target.relative_to(ROOT))

    live_source = RESULTS / "live-telemetry-20260923"
    live_targets = {
        "research-complete-20260923.json": dated
        / "live-reconciliation"
        / "complete-historical"
        / "run.json",
        "research-delayed-20260923.json": dated
        / "live-reconciliation"
        / "delayed-historical"
        / "run.json",
        "research-source-unavailable-20260923.json": dated
        / "live-reconciliation"
        / "source-unavailable-historical"
        / "run.json",
        "research-verified-capture-drop-20260923.json": dated
        / "live-reconciliation"
        / "capture-drop-provisional"
        / "run.json",
        "research-verified-capture-drop-final-20260923.json": dated
        / "live-reconciliation"
        / "capture-drop-pending"
        / "run.json",
        "research-verified-capture-drop-final2-20260923.json": dated
        / "live-reconciliation"
        / "capture-drop-finalized"
        / "run.json",
        "research-verified-complete-20260923.json": dated
        / "live-reconciliation"
        / "complete-verified"
        / "run.json",
    }
    for name, destination in live_targets.items():
        source = live_source / name
        move_one(source, destination, moved)
        if destination.exists():
            mapping[str(source.relative_to(ROOT))] = str(destination.relative_to(ROOT))
    if live_source.exists() and not any(live_source.iterdir()):
        live_source.rmdir()

    for path in sorted({PUBLISHED, RUNS} | {item.parent for item in map(Path, [])}):
        path.mkdir(parents=True, exist_ok=True)

    for path in list(PUBLISHED.rglob("*.json")) + list(RUNS.rglob("*.json")):
        try:
            payload = json.loads(path.read_text(encoding="utf-8-sig"))
        except (UnicodeDecodeError, json.JSONDecodeError):
            continue
        updated = replace_paths(payload, mapping)
        path.write_text(json.dumps(updated, indent=2) + "\n", encoding="utf-8")

    catalog = {
        "schema_version": "csg-results-layout-v1",
        "generated_at": datetime.now(UTC).isoformat(),
        "published_directory": "experiments/results/published",
        "runs_directory": "experiments/results/runs",
        "moved_files": moved,
        "path_mapping": mapping,
    }
    (RESULTS / "catalog.json").write_text(json.dumps(catalog, indent=2) + "\n", encoding="utf-8")
    return catalog


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--apply", action="store_true", help="perform the migration")
    args = parser.parse_args()
    if not args.apply:
        print("Dry run only. Re-run with --apply to organize experiments/results.")
        return
    catalog = migrate()
    print(
        json.dumps(
            {
                "moved_files": len(catalog["moved_files"]),
                "catalog": "experiments/results/catalog.json",
            },
            indent=2,
        )
    )


if __name__ == "__main__":
    main()
