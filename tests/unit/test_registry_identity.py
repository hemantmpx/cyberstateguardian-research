from csg.state.normalize import normalize_registry_key


def test_probe_user_hive_and_sysmon_sid_hive_share_exact_identity() -> None:
    sid = "S-1-5-21-100-200-300-1001"
    probe_key = (
        f"registry:HKU:\\{sid}\\Software\\Microsoft\\Windows\\CurrentVersion\\Run\\Updater"
    )
    sysmon_target = (
        f"HKU\\{sid}\\Software\\Microsoft\\Windows\\CurrentVersion\\Run\\Updater"
    )

    assert normalize_registry_key(probe_key) == normalize_registry_key(sysmon_target)
