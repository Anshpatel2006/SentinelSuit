from unittest.mock import Mock

import requests

from malware_platform.analysis import cape_client


def test_delete_tasks_returns_cape_disabled_response(monkeypatch):
    response = Mock()
    response.raise_for_status.return_value = None
    response.json.return_value = {
        "error": True,
        "error_value": "Task Deletion API is Disabled",
    }
    request = Mock(return_value=response)
    monkeypatch.setattr(requests, "get", request)

    result = cape_client.delete_tasks("1,2,3", "pending")

    request.assert_called_once_with(
        "http://127.0.0.1:8000/apiv2/tasks/delete/1,2,3/pending/",
        timeout=cape_client.REQUEST_TIMEOUT,
    )
    assert result["error_value"] == "Task Deletion API is Disabled"


def test_delete_tasks_rejects_empty_task_id():
    try:
        cape_client.delete_tasks("", "pending")
    except ValueError as error:
        assert str(error) == "task_id is required"
    else:
        raise AssertionError("Expected empty task IDs to be rejected")