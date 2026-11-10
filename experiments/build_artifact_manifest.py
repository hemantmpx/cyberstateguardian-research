"""Create a SHA-256 catalog for an experiment run and its published records."""

from __future__ import annotations

import argparse
import hashlib
import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


def sha256(path: Path) -> str:
    hasher = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            hasher.update(block)
    return hasher.hexdigest()


def build(run_dir: Path, experiment_id: str, publications: list[Path], output: Path) -> dict[str, Any]:
    artifacts = []
    for path in sorted(run_dir.rglob("*")):
        if not path.is_file() or path == output or "__pycache__" in path.parts or path.suffix == ".pyc":
            continue
        artifacts.append({
            "path": str(path.relative_to(run_dir)),
            "size_bytes": path.stat().st_size,
            "sha256": sha256(path),
        })
    publication_hashes = {}
    for path in publications:
        if not path.is_file():
            raise FileNotFoundError(path)
        try:
            label = str(path.resolve().relative_to(Path.cwd().resolve()))
        except ValueError:
            label = str(path.resolve())
        publication_hashes[label] = sha256(path)
    return {
        "schema_version": "csg-run-artifact-manifest-v1",
        "experiment_id": experiment_id,
        "generated_at_utc": datetime.now(timezone.utc).isoformat(),
        "run_artifact_count": len(artifacts),
        "run_artifacts": artifacts,
        "publication_sha256": publication_hashes,
        "manifest_note": "The manifest does not hash itself; all other run files present at generation are listed.",
    }


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--run-dir", type=Path, required=True)
    parser.add_argument("--experiment-id", required=True)
    parser.add_argument("--publication", type=Path, action="append", default=[])
    args = parser.parse_args()
    run_dir = args.run_dir.resolve()
    output = run_dir / "artifact-manifest.json"
    result = build(run_dir, args.experiment_id, args.publication, output)
    output.write_text(json.dumps(result, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(json.dumps({"manifest": str(output), "run_artifact_count": result["run_artifact_count"]}, indent=2))


if __name__ == "__main__":
    main()
