"""Build a clean, reproducible source-and-results ZIP for research review."""

from __future__ import annotations

import argparse
import hashlib
import json
import tempfile
import zipfile
from datetime import UTC, datetime
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SOURCE_DIRECTORIES = {
    "backend",
    "change-records",
    "config",
    "dashboard",
    "docs",
    "docker",
    "experiments",
    "probe",
    "scripts",
    "tests",
}
SOURCE_FILES = {
    ".env.example",
    "BUILD_STATUS.md",
    "Makefile",
    "README.md",
    "RESEARCH_VERSION",
    "alembic.ini",
    "compose.yaml",
    "pyproject.toml",
}
EXCLUDED_PARTS = {
    ".git",
    ".venv",
    ".pytest_cache",
    ".mypy_cache",
    ".ruff_cache",
    "__pycache__",
    "node_modules",
    ".next",
    ".wazuh-lab",
    ".DS_Store",
    "cyberstateguardian.db",
}
EXCLUDED_PREFIXES = (
    "experiments/datasets/windows_apt_2025/raw/",
    "experiments/results/runs/",
)
INCLUDED_RUN_PREFIXES = (
    "experiments/results/runs/20260923/research-readiness-calibration/complete-005/",
)


def _research_version() -> str:
    return (ROOT / "RESEARCH_VERSION").read_text(encoding="utf-8").strip()


def _included(relative: str) -> bool:
    path = Path(relative)
    if any(part in EXCLUDED_PARTS for part in path.parts):
        return False
    if (
        relative.startswith("experiments/results/published/")
        and path.name.startswith("csg-research-artifact-")
        and path.suffix == ".zip"
    ):
        return False
    if relative.startswith(EXCLUDED_PREFIXES):
        return any(relative.startswith(prefix) for prefix in INCLUDED_RUN_PREFIXES)
    if path.parts and path.parts[0] == "experiments" and path.parts[1:3] == ("results", "runs"):
        return any(relative.startswith(prefix) for prefix in INCLUDED_RUN_PREFIXES)
    return path.parts[0] in SOURCE_DIRECTORIES or relative in SOURCE_FILES


def _source_files() -> list[Path]:
    candidates: set[Path] = set()
    for directory in SOURCE_DIRECTORIES:
        candidates.update(path for path in (ROOT / directory).rglob("*") if path.is_file())
    candidates.update(ROOT / name for name in SOURCE_FILES)
    return sorted(
        path
        for path in candidates
        if path.exists() and _included(path.relative_to(ROOT).as_posix())
    )


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _reproduction_text(version: str) -> str:
    return f"""# CyberStateGuardian Research Artifact

Research version: `{version}`

This archive intentionally excludes local secrets, virtual environments, databases, Wazuh runtime
data, browser dependencies, caches, and the external Windows-APT raw archive. Published summaries
and the validated `complete-005` calibration are included.

## Reproduce the software checks

```bash
python3.12 -m venv .venv
.venv/bin/python -m pip install -e '.[research,dev,probe]'
DATABASE_URL=sqlite:///./test.db .venv/bin/pytest -q
.venv/bin/ruff check backend probe experiments scripts tests
```

## Reproduce the local stack

```bash
python scripts/create_lab_env.py
docker compose up -d --build
python scripts/healthcheck.py --url http://localhost:8000/health
```

## Reproduce the Windows experiment

Use `docs/research-validation-protocol.md` and `docs/live-lab-setup.md`. The live Windows VM,
Wazuh deployment, credentials, and external raw dataset are not included in this archive. Acquire
or configure those inputs separately and record their hashes before running a formal campaign.
"""


def build(output: Path, version: str) -> dict[str, object]:
    output = output.resolve()
    files = _source_files()
    entries = [
        {
            "path": path.relative_to(ROOT).as_posix(),
            "sha256": _sha256(path),
            "bytes": path.stat().st_size,
        }
        for path in files
    ]
    manifest = {
        "schema_version": "csg-research-artifact-v1",
        "research_version": version,
        "generated_at": datetime.now(UTC).isoformat(),
        "included_file_count": len(entries),
        "included_files": entries,
        "excluded": {
            "secrets": [".env", "probe settings containing tokens"],
            "runtime": [".venv", ".wazuh-lab", "cyberstateguardian.db", "node_modules", "caches"],
            "external_data": ["experiments/datasets/windows_apt_2025/raw/"],
        },
    }

    output.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(prefix="csg-artifact-") as temporary:
        staging = Path(temporary)
        manifest_path = staging / "ARTIFACT_MANIFEST.json"
        manifest_path.write_text(json.dumps(manifest, indent=2) + "\n", encoding="utf-8")
        reproduction_path = staging / "REPRODUCE.md"
        reproduction_path.write_text(_reproduction_text(version), encoding="utf-8")
        with zipfile.ZipFile(output, "w", compression=zipfile.ZIP_DEFLATED) as archive:
            for path in files:
                archive.write(path, path.relative_to(ROOT).as_posix())
            archive.write(manifest_path, "ARTIFACT_MANIFEST.json")
            archive.write(reproduction_path, "REPRODUCE.md")
    return manifest


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--version", default=_research_version())
    parser.add_argument(
        "--output",
        type=Path,
        default=None,
        help=(
            "ZIP path; defaults to "
            "experiments/results/published/csg-research-artifact-<version>.zip"
        ),
    )
    args = parser.parse_args()
    output = args.output or Path("experiments/results/published") / (
        f"csg-research-artifact-{args.version}.zip"
    )
    manifest = build(output, args.version)
    print(f"wrote {manifest['included_file_count']} files to {output}")


if __name__ == "__main__":
    main()
