from csg import worker
from csg.config import Settings


def test_provider_failure_does_not_skip_local_reconciliation(db_session, monkeypatch):
    settings = Settings(CSG_WAZUH_SYNC_ENABLED=True, CSG_WAZUH_SYNC_HOST_IDS="offline-host")
    monkeypatch.setattr(worker, "get_settings", lambda: settings)
    monkeypatch.setattr(worker, "SessionLocal", lambda: db_session)
    monkeypatch.setattr(worker.signal, "signal", lambda *_: None)
    monkeypatch.setattr(worker.time, "sleep", lambda _: None)
    monkeypatch.setattr(worker, "STOP", False)
    processed = []

    async def unavailable(*_):
        raise ConnectionError("test outage")

    def process(*_):
        from csg.services.live_pipeline import LivePipelineResult

        processed.append(True)
        worker.STOP = True
        return LivePipelineResult()

    monkeypatch.setattr(worker.ProviderSyncService, "sync_host", unavailable)
    monkeypatch.setattr(worker.LivePipelineService, "process_backlog", process)
    worker.main()
    assert processed == [True]
