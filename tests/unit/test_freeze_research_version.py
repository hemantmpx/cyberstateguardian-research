import json

from scripts import freeze_research_version
from scripts.freeze_research_version import ROOT, external_lab_snapshot, source_files


def test_freeze_hashes_live_wazuh_and_sysmon_configuration() -> None:
    frozen_paths = {path.relative_to(ROOT).as_posix() for path in source_files()}

    assert "config/sysmon-csg-lab.xml" in frozen_paths
    assert "config/wazuh/csg_research_rules.xml" in frozen_paths
    assert ".wazuh-lab/wazuh-docker/single-node/docker-compose.yml" in frozen_paths
    assert (
        ".wazuh-lab/wazuh-docker/single-node/config/wazuh_cluster/wazuh_manager.conf"
        in frozen_paths
    )


def test_docker_snapshot_captures_csg_and_wazuh_compose_projects(monkeypatch) -> None:
    commands = []

    def fake_run_command(command):
        commands.append(command)
        if command[-2:] == ["images", "-q"]:
            if "csg-wazuh" in command:
                return 0, "sha256:manager-image"
            return 0, "sha256:csg-api-image\nsha256:csg-worker-image"
        image_id = command[3]
        return 0, f'["local/{image_id}@sha256:digest"]'

    monkeypatch.setattr(freeze_research_version, "run_command", fake_run_command)

    snapshot = freeze_research_version.docker_snapshot()

    assert snapshot["available"] is True
    assert set(snapshot["csg_image_ids"]) == {"sha256:csg-api-image", "sha256:csg-worker-image"}
    assert snapshot["image_digests"] == {
        "sha256:manager-image": '["local/sha256:manager-image@sha256:digest"]'
    }
    assert len(commands) == 5
    assert "compose.yaml" in commands[0][-3]
    assert "-p" in commands[3] and "csg-wazuh" in commands[3]
    assert str(ROOT / ".wazuh-lab/wazuh-docker/single-node/docker-compose.yml") in commands[3]


def test_external_lab_snapshot_reads_windows_powershell_utf8_bom(tmp_path) -> None:
    path = tmp_path / "windows-environment.json"
    path.write_text(
        json.dumps(
            {
                "windows_build": "26200",
                "windows_architecture": "ARM64-based PC",
                "config_sha256": {"sysmon_value": "sysmon-hash", "wazuh_agent_value": "agent-hash"},
            }
        ),
        encoding="utf-8-sig",
    )

    snapshot = external_lab_snapshot(path)

    assert snapshot["windows_build"] == "26200"
    assert snapshot["windows_architecture"] == "ARM64-based PC"
    assert snapshot["sysmon_config_sha256"] == "sysmon-hash"
    assert snapshot["wazuh_agent_config_sha256"] == "agent-hash"
