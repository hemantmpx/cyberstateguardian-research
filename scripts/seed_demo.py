from __future__ import annotations

from pathlib import Path

from experiments.runner.run_scenarios import ROOT, run_scenario

from csg.config import get_settings
from csg.db.repositories import CyberStateRepository
from csg.db.session import SessionLocal
from csg.domain.models import Host
from csg.services.incident_correlation import IncidentCorrelationService


def main() -> None:
    with SessionLocal() as session:
        repo = CyberStateRepository(session)
        repo.upsert_host(
            Host(
                host_id="win-lab-01",
                hostname="win11-arm-lab",
                role="windows-target",
                os="windows-11",
                architecture="arm64",
            ),
        )
        for scenario_path in sorted((ROOT / "experiments" / "scenarios").glob("*.json")):
            run = run_scenario(Path(scenario_path), ROOT)
            repo.create_experiment_run(run)
            for delta in run.actual_observations.get("deltas", []):
                from csg.domain.models import StateDelta

                repo.create_deltas([StateDelta.model_validate(delta)])

            for event in run.actual_observations.get("events", []):
                from csg.domain.models import NormalizedEvent

                repo.create_events([NormalizedEvent.model_validate(event)])

            for finding in run.actual_observations.get("findings", []):
                from csg.domain.models import Finding

                repo.create_finding(Finding.model_validate(finding))
        IncidentCorrelationService(get_settings()).correlate_backlog(repo, limit=500)
    print("seeded CyberStateGuardian demo data")


if __name__ == "__main__":
    main()
