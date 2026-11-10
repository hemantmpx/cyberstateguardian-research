from experiments.analyze_probe_overhead import summarize


def _row(pair_id, condition, cpu, probe_count, task_state):
    return {
        "pair_id": pair_id,
        "order_position": 1 if condition == "probe_off" else 2,
        "condition": condition,
        "host_cpu_percent": cpu,
        "available_memory_mib": 1000,
        "probe_cpu_percent_of_host_capacity": 1.5 if condition == "probe_on" else None,
        "probe_working_set_mib": 20 if condition == "probe_on" else 0.0,
        "wazuh_cpu_percent_of_host_capacity": 0.3,
        "wazuh_working_set_mib": 30,
        "probe_process_count": probe_count,
        "probe_task_state": task_state,
        "wazuh_service_state": "Running",
    }


def _metadata():
    return {
        "pairs": 1,
        "measurement_seconds_per_condition": 10,
        "sample_period_seconds": 5,
        "randomized_plan": [{"pair_id": "pair-01", "order": ["probe_off", "probe_on"]}],
        "windows": {"build": "test"},
        "status": "completed",
    }


def test_summary_uses_paired_block_medians_not_sample_count():
    samples = [
        _row("pair-01", "probe_off", 10, 0, "Disabled"),
        _row("pair-01", "probe_off", 12, 0, "Disabled"),
        _row("pair-01", "probe_on", 15, 1, "Running"),
        _row("pair-01", "probe_on", 17, 1, "Running"),
    ]
    result = summarize(samples, _metadata())
    assert result["pairs"][0]["conditions"]["probe_off"]["sample_count"] == 2
    assert result["pairs"][0]["on_minus_off"]["host_cpu_percent"] == 5.0
    assert result["aggregate"]["host_cpu_percent"]["paired_block_count"] == 1
    assert (
        result["condition_aggregate"]["probe_cpu_percent_of_host_capacity"]["probe_on"]["median"]
        == 1.5
    )
    assert (
        result["condition_aggregate"]["probe_cpu_percent_of_host_capacity"]["probe_off"]["median"]
        is None
    )


def test_summary_rejects_wazuh_outage():
    samples = [
        _row("pair-01", "probe_off", 10, 0, "Disabled"),
        _row("pair-01", "probe_off", 12, 0, "Disabled"),
        _row("pair-01", "probe_on", 15, 1, "Running"),
        _row("pair-01", "probe_on", 17, 1, "Running"),
    ]
    samples[0]["wazuh_service_state"] = "Stopped"
    try:
        summarize(samples, _metadata())
    except ValueError as exc:
        assert "Wazuh was not running" in str(exc)
    else:
        raise AssertionError("Wazuh outage must invalidate the pair")
