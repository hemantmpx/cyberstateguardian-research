from experiments.analyze_windows_distractor_campaign_v25 import (
    _physical_identities,
    exact_binomial_interval,
    normalize_task_name,
)


def test_exact_binomial_interval_boundary_cases():
    all_success = exact_binomial_interval(10, 10)
    no_success = exact_binomial_interval(0, 10)

    assert all_success is not None
    assert abs(all_success["lower"] - 0.6915028921812392) < 1e-10
    assert all_success["upper"] == 1.0
    assert no_success is not None
    assert no_success["lower"] == 0.0
    assert abs(no_success["upper"] - 0.3084971078187608) < 1e-10


def test_task_identity_ignores_windows_path_prefix_and_case():
    assert normalize_task_name("\\\\CSGAPTTaskABCD") == "csgapttaskabcd"


def test_alert_and_archive_representations_count_as_one_physical_event():
    identity = ["001", "security", "135693", "4698", "microsoft-windows-security-auditing"]
    documents = [
        {
            "document_found": True,
            "stable_windows_event_identity": identity,
            "index": "wazuh-alerts",
        },
        {
            "document_found": True,
            "stable_windows_event_identity": identity,
            "index": "wazuh-archives",
        },
    ]

    assert _physical_identities(documents) == [tuple(identity)]
