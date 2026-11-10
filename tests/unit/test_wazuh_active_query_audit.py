import httpx
import pytest
from scripts.verify_wazuh_active_eventchannel_query import (
    build_error_result,
    select_active_security_localfile_block,
    write_audit_result,
)


def test_active_security_block_preserves_runtime_fields() -> None:
    block = {
        "channel": "Security",
        "query": {"value": "Event[System/EventID=4698]"},
        "status": "active",
        "pending_restart": False,
    }

    selected = select_active_security_localfile_block(
        {"data": {"localfile": [block, {"channel": "System"}]}}
    )

    assert selected is block
    assert selected["status"] == "active"
    assert selected["pending_restart"] is False


@pytest.mark.parametrize("blocks", [[], [{"channel": "System"}], [{"channel": "Security"}] * 2])
def test_active_security_block_requires_exactly_one_match(blocks: list[dict]) -> None:
    with pytest.raises(ValueError, match="Expected one active Security localfile block"):
        select_active_security_localfile_block({"data": {"localfile": blocks}})


def test_error_result_keeps_safe_http_detail_and_expected_query_hash() -> None:
    request = httpx.Request("GET", "https://wazuh.example/agents/001/config/logcollector/localfile")
    response = httpx.Response(
        400,
        json={"title": "Bad Request", "detail": "Agent is disconnected", "token": "omit"},
        request=request,
    )
    error = httpx.HTTPStatusError("request failed", request=request, response=response)

    result = build_error_result(
        error,
        agent_id="001",
        api_path="/agents/001/config/logcollector/localfile",
        expected_query="Event[System/EventID=4698]",
    )

    assert result["http_status_code"] == 400
    assert result["response_detail"] == {
        "title": "Bad Request",
        "detail": "Agent is disconnected",
    }
    assert result["expected_query_sha256_normalized"]
    assert "token" not in result["response_detail"]


def test_error_result_is_written_for_failed_api_capture(tmp_path) -> None:
    result = build_error_result(
        RuntimeError("API host not resolvable"),
        agent_id="001",
        api_path="/agents/001/config/logcollector/localfile",
        expected_query=None,
    )
    output = tmp_path / "nested" / "error.json"

    write_audit_result(result, output)

    assert output.is_file()
    assert '"active_config_api_path"' in output.read_text(encoding="utf-8")
