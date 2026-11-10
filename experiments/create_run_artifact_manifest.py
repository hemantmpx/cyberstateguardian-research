"""Create a SHA-256 catalog for an experiment run directory."""

from __future__ import annotations

import argparse
import hashlib
import json
from datetime import datetime, timezone
from pathlib import Path


def digest(path: Path) -> str:
    value = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            value.update(chunk)
    return value.hexdigest()


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--run-dir", type=Path, required=True)
    parser.add_argument("--experiment-id", required=True)
    parser.add_argument("--analysis-tool", type=Path)
    args = parser.parse_args()
    run_dir = args.run_dir.resolve()
    if not run_dir.is_dir():
        raise SystemExit(f"Run directory does not exist: {run_dir}")

    files = [
        {
            "path": path.relative_to(run_dir).as_posix(),
            "bytes": path.stat().st_size,
            "sha256": digest(path),
        }
        for path in sorted(run_dir.rglob("*"))
        if path.is_file() and path.name != "artifact-manifest.json"
    ]
    manifest = {
        "schema_version": "csg-run-artifact-manifest-v1",
        "experiment_id": args.experiment_id,
        "generated_at_utc": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
        "files": files,
        "manifest_self_hash_excluded": True,
    }
    if args.analysis_tool:
        tool = args.analysis_tool.resolve()
        manifest["analysis_tool"] = {
            "path": tool.relative_to(Path.cwd()).as_posix(),
            "sha256": digest(tool),
        }

    output = run_dir / "analysis" / "artifact-manifest.json"
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(json.dumps(manifest, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(f"MANIFEST_CREATED={output}; FILES={len(files)}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
