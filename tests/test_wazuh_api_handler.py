import pytest
from unittest.mock import patch, MagicMock
import requests
from wazuh_api_handler import WazuhAPIHandler

@pytest.fixture
def handler_fixture():
    url = "https://api.example.com"
    headers = {"Authorization": "Bearer token"}
    username = "user"
    password = "pass"
    verify = True
    return WazuhAPIHandler(url, headers, username, password, verify)

def test_constructor_valid_inputs(handler_fixture):
    handler = handler_fixture
    assert handler.url == "https://api.example.com"
    assert handler.headers == {"Authorization": "Bearer token"}
    assert handler.username == "user"
    assert handler.password == "pass"
    assert handler.verify is True

def test_constructor_invalid_username():
    with pytest.raises(ValueError):
        WazuhAPIHandler("https://api.example.com", {"Authorization": "Bearer token"}, 123, "pass", True)

def test_constructor_invalid_password():
    with pytest.raises(ValueError):
        WazuhAPIHandler("https://api.example.com", {"Authorization": "Bearer token"}, "user", 123, True)

def test_constructor_invalid_headers():
    with pytest.raises(ValueError):
        WazuhAPIHandler("https://api.example.com", "invalid_headers", "user", "pass", True)

def test_change_header_valid(handler_fixture):
    handler = handler_fixture
    new_headers = {"Content-Type": "application/json"}
    handler.change_header(new_headers)
    assert handler.headers == new_headers

def test_change_header_invalid(handler_fixture):
    handler = handler_fixture
    with pytest.raises(ValueError):
        handler.change_header("invalid_header")

@patch("wazuh_api_handler.requests.get")
def test_get_valid_query(mock_get, handler_fixture):
    handler = handler_fixture
    mock_response = MagicMock()
    mock_response.status_code = 200
    mock_response.json.return_value = {"key": "value"}
    mock_get.return_value = mock_response

    query = "test_query"
    response = handler.get(query)

    mock_get.assert_called_once_with(
        handler.url,
        headers=handler.headers,
        auth=(handler.username, handler.password),
        json=query,
        verify=handler.verify
    )
    assert response.status_code == 200
    assert response.json() == {"key": "value"}

@patch("wazuh_api_handler.requests.get")
def test_get_invalid_query(mock_get, handler_fixture):
    handler = handler_fixture
    with pytest.raises(ValueError):
        handler.get(123)

@patch("wazuh_api_handler.requests.get")
def test_get_request_exception(mock_get, handler_fixture):
    handler = handler_fixture
    mock_get.side_effect = requests.exceptions.RequestException("Request failed")
    with pytest.raises(RuntimeError):
        handler.get("test_query")
