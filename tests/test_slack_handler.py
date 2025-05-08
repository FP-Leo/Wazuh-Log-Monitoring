import pytest
from unittest.mock import MagicMock, patch
import os
import sys
from rint_slack import RintSlack
from slack_sdk import errors
import tempfile

# Add parent directory to path to import module
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from rint_error_sdk import (EnvFileNotLoadedError, EnvVariableEmptyError, EnvVariableNotFoundError, 
                           SlackConnectionError, SlackMessageSendError)

# Test constants
TEST_TOKEN = "test-token"
TEST_CHANNEL = "test-channel"
TEST_MESSAGE = "Test message"
ENV_TOKEN = "env-token"
ENV_CHANNEL = "env-channel"

# Test fixtures
@pytest.fixture(autouse=True)
def clear_slack_env_variables():
    """Clear Slack-related environment variables before each test."""
    os.environ.pop("SLACK_TOKEN", None)
    os.environ.pop("SLACK_CHANNEL", None)

@pytest.fixture
def mock_slack_client():
    with patch("rint_slack.WebClient") as mock_webclient:
        mock_client = MagicMock()
        mock_webclient.return_value = mock_client
        yield mock_webclient, mock_client

# Test cases for __init__ when the environment file is not provided/loaded

def test_init_with_nonexistent_env_file():
    """Test initialization with non-existent env file."""
    with pytest.raises(EnvFileNotLoadedError):
        RintSlack(env="nonexistent_file.env")

def test_init_with_token_channel_and_invalid_env_file(mock_slack_client):
    """Test initialization with token and channel but missing env file."""
    mock_webclient, mock_client = mock_slack_client

    slack = RintSlack(token=TEST_TOKEN, channel=TEST_CHANNEL, env="nonexistent_file.env")
    
    assert slack._token == TEST_TOKEN
    assert slack._channel == TEST_CHANNEL
    mock_webclient.assert_called_once_with(token=TEST_TOKEN)

@pytest.mark.parametrize(
    "token, channel",
    [
        (None, None),  # Both None
        (TEST_TOKEN, None),  # Token provided, channel None
        (None, TEST_CHANNEL),  # Channel provided, token None
    ]
)
def test_init_with_invalid_env_file(token, channel):
    """Test initialization with missing env file in various argument scenarios."""
    with pytest.raises(EnvFileNotLoadedError):
        slack = RintSlack(token=token, channel=channel, env="nonexistent_file.env")

# Test cases for __init__ when the environment file is provided/loaded

def test_slack_default_env_success():
    """Test successful loading of default .env file. Found at "env-files/slack.env" """
    RintSlack()

########## Token - 1, Channel - 1

@pytest.mark.parametrize(
    "temp_env_file",
    [
        {"slack_token": ENV_TOKEN, "slack_channel": ENV_CHANNEL},   # Both values in env
        {"slack_token": "", "slack_channel": ENV_CHANNEL},          # Only channel in env
        {"slack_token": ENV_TOKEN, "slack_channel": ""},            # Only token in env
        {"slack_token": "", "slack_channel": ""},                   # Neither in env
    ],
    indirect=True
)
def test_init_with_provided_params_overrides_env(
    mock_slack_client, temp_env_file
):
    """Test that provided token and channel override env values."""
    mock_webclient, mock_client = mock_slack_client

    slack = RintSlack(token=TEST_TOKEN, channel=TEST_CHANNEL, env=temp_env_file)

    assert slack._token == TEST_TOKEN
    assert slack._channel == TEST_CHANNEL
    mock_webclient.assert_called_once_with(token=TEST_TOKEN)


########## Token - 1, Channel - 0
@pytest.mark.parametrize(
    "temp_env_file",
    [
        {"slack_token": ENV_TOKEN, "slack_channel": ENV_CHANNEL},   # full env
        {"slack_token": "", "slack_channel": ENV_CHANNEL},          # channel only in env
    ],
    indirect=True
)
def test_init_with_token_param_valid_env_cases(mock_slack_client, temp_env_file):
    """Test initialization with token param and valid/partial env."""
    mock_webclient, mock_client = mock_slack_client

    slack = RintSlack(token=TEST_TOKEN, env=temp_env_file)

    assert slack._token == TEST_TOKEN
    assert slack._channel == ENV_CHANNEL
    mock_webclient.assert_called_once_with(token=TEST_TOKEN)

@pytest.mark.parametrize(
    "temp_env_file",
    [
        {"slack_token": ENV_TOKEN, "slack_channel": ""},   # empty channel
        {"slack_token": "", "slack_channel": ""},          # both empty
    ],
    indirect=True
)
def test_init_with_token_param_invalid_env_cases(temp_env_file):
    """Test initialization with token param and invalid env (missing channel)."""
    with pytest.raises(EnvVariableEmptyError):
        RintSlack(token=TEST_TOKEN, env=temp_env_file)


########## Token - 0, Channel - 1
@pytest.mark.parametrize(
    "temp_env_file",
    [
        {"slack_token": ENV_TOKEN, "slack_channel": ENV_CHANNEL},  # full env
        {"slack_token": ENV_TOKEN, "slack_channel": ""},           # only token in env
    ],
    indirect=True
)
def test_init_with_channel_param_valid_env_cases(mock_slack_client, temp_env_file):
    """Test initialization with channel param and valid/partial env."""
    mock_webclient, mock_client = mock_slack_client

    slack = RintSlack(channel=TEST_CHANNEL, env=temp_env_file)

    assert slack._token == ENV_TOKEN
    assert slack._channel == TEST_CHANNEL
    mock_webclient.assert_called_once_with(token=ENV_TOKEN)

@pytest.mark.parametrize(
    "temp_env_file",
    [
        {"slack_token": "", "slack_channel": ENV_CHANNEL},  # only channel in env
        {"slack_token": "", "slack_channel": ""},           # both missing
    ],
    indirect=True
)
def test_init_with_channel_param_invalid_env_cases(temp_env_file):
    """Test initialization with channel param and invalid env (missing token)."""
    with pytest.raises(EnvVariableEmptyError):
        RintSlack(channel=TEST_CHANNEL, env=temp_env_file)


########## Token - 0, Channel - 0
@pytest.mark.parametrize("temp_env_file", [{"slack_token": ENV_TOKEN, "slack_channel": ENV_CHANNEL}], indirect=True)
def test_init_with_no_param_valid_env(mock_slack_client, temp_env_file):
    """Test initialization with provided token and channel."""
    mock_webclient, mock_client = mock_slack_client
    
    slack = RintSlack(env=temp_env_file)
    
    assert slack._token == ENV_TOKEN
    assert slack._channel == ENV_CHANNEL
    mock_webclient.assert_called_once_with(token=ENV_TOKEN)

@pytest.mark.parametrize(
    "temp_env_file",
    [
        {"slack_token": ENV_TOKEN, "slack_channel": ""},           # Only token in env
        {"slack_token": "", "slack_channel": ENV_CHANNEL},         # Only channel in env
        {"slack_token": "", "slack_channel": ""},                  # Neither in env
    ],
    indirect=True
)
def test_init_with_no_params_invalid_env_cases(temp_env_file):
    """Test init with no direct params and incomplete/empty env — should raise."""
    with pytest.raises(EnvVariableEmptyError):
        RintSlack(env=temp_env_file)

##########

@patch('rint_slack.WebClient')
@pytest.mark.parametrize("temp_env_file", [{"slack_token": ENV_TOKEN, "slack_channel": ENV_CHANNEL}], indirect=True)
def test_send_message_success(mock_webclient, temp_env_file):
    """Test successful message sending."""
    mock_client = MagicMock()
    mock_webclient.return_value = mock_client
    
    slack = RintSlack(env=temp_env_file)
    slack.send_message(TEST_MESSAGE)
    
    mock_client.chat_postMessage.assert_called_once_with(
        channel=ENV_CHANNEL, text=TEST_MESSAGE
    )

@pytest.mark.parametrize("temp_env_file", [{"slack_token": ENV_TOKEN, "slack_channel": ENV_CHANNEL}], indirect=True)
def test_send_message_slack_api_error(mock_slack_client, temp_env_file):
    """Test SlackMessageSendError is raised when Slack API error occurs during send."""
    mock_webclient, mock_client = mock_slack_client
    mock_client.chat_postMessage.side_effect = errors.SlackApiError("Test error", {"error": "test"})
    
    slack = RintSlack(env=temp_env_file)
    with pytest.raises(SlackMessageSendError):
        slack.send_message(TEST_MESSAGE)

@pytest.mark.parametrize("temp_env_file", [{"slack_token": ENV_TOKEN, "slack_channel": ENV_CHANNEL}], indirect=True)
def test_send_message_unexpected_error(mock_slack_client, temp_env_file):
    """Test SlackMessageSendError is raised when unexpected error occurs during send."""
    mock_webclient, mock_client = mock_slack_client
    mock_client.chat_postMessage.side_effect = Exception("Unexpected error")
    
    slack = RintSlack(env=temp_env_file)
    with pytest.raises(SlackMessageSendError):
        slack.send_message(TEST_MESSAGE)

@pytest.mark.parametrize("temp_env_file", [{"slack_token": "invalid-token", "slack_channel": ENV_CHANNEL}], indirect=True)
def test_connection_error_invalid_token(mock_slack_client, temp_env_file):
    """Should raise SlackConnectionError when token is invalid during connection."""
    mock_webclient, mock_client = mock_slack_client
    mock_client.auth_test.side_effect = errors.SlackApiError("Invalid auth", {"error": "invalid_auth"})

    with pytest.raises(SlackConnectionError):
        RintSlack(env=temp_env_file)

def test_generic_exception_during_webclient_init():
    """Test catching a generic exception during WebClient initialization."""
    with patch('rint_slack.WebClient', side_effect=Exception("Failed to initialize WebClient")):
        with pytest.raises(Exception):
            RintSlack(token=TEST_TOKEN, channel=TEST_CHANNEL)

@pytest.mark.parametrize("temp_env_file", [{"slack_token": ENV_TOKEN, "slack_channel": ENV_CHANNEL}], indirect=True)
def test_connection_success(mock_slack_client, temp_env_file):
    """Should successfully establish Slack connection when token is valid."""
    mock_webclient, mock_client = mock_slack_client
    mock_client.auth_test.return_value = {"ok": True}

    slack = RintSlack(env=temp_env_file)

    mock_client.auth_test.assert_called_once()
    assert slack._token == ENV_TOKEN
    assert slack._channel == ENV_CHANNEL

@pytest.mark.parametrize("temp_env_file", [{"slack_token": ENV_TOKEN, "slack_channel": ENV_CHANNEL}], indirect=True)
def test_send_message_long_text(mock_slack_client, temp_env_file):
    """Ensure long messages are still sent correctly."""
    mock_webclient, mock_client = mock_slack_client

    slack = RintSlack(env=temp_env_file)
    long_message = "A" * 4000  # Slack supports up to 4000 characters per message

    slack.send_message(long_message)
    mock_client.chat_postMessage.assert_called_once_with(
        channel=ENV_CHANNEL, text=long_message
    )

@pytest.mark.parametrize("temp_env_file", [{"slack_token": ENV_TOKEN, "slack_channel": ENV_CHANNEL}], indirect=True)
def test_send_message_special_characters(mock_slack_client, temp_env_file):
    """Send message containing special characters and emojis."""
    mock_webclient, mock_client = mock_slack_client
    
    slack = RintSlack(env=temp_env_file)
    special_message = "Hello, team! 💥🔥🚀 *Bold* _Italic_ ~Strike~ `code`"

    slack.send_message(special_message)
    mock_client.chat_postMessage.assert_called_once_with(
        channel=ENV_CHANNEL, text=special_message
    )

@pytest.mark.parametrize("malformed_lines,expected_exception", [
    # Missing '=' entirely
    (["SLACK_TOKEN", "SLACK_CHANNEL"], EnvVariableNotFoundError),
    
    # Incorrect delimiter (colon)
    (["SLACK_TOKEN:test", "SLACK_CHANNEL:general"], EnvVariableNotFoundError),

    # Empty key
    (["=somevalue", "SLACK_CHANNEL=general"], EnvVariableNotFoundError),

    # Empty value
    (["SLACK_TOKEN=", "SLACK_CHANNEL=general"], EnvVariableEmptyError),

    # Completely malformed (no structure)
    (["!!!bad_line@@@", "another bad line"], EnvVariableNotFoundError),

    # Valid token but missing channel
    (["SLACK_TOKEN=validtoken"], EnvVariableNotFoundError),

    # Valid keys but empty values
    (["SLACK_TOKEN=", "SLACK_CHANNEL="], EnvVariableEmptyError),
])
def test_init_with_various_malformed_env_files(malformed_lines, expected_exception):
    """Test initialization with various malformed .env file contents."""
    with tempfile.NamedTemporaryFile(delete=False, mode="w") as temp_file:
        for line in malformed_lines:
            temp_file.write(line + "\n")
        temp_file_path = temp_file.name

    try:
        with pytest.raises(expected_exception):
            RintSlack(env=temp_file_path)
    finally:
        os.remove(temp_file_path)
    
def test_get_channel_with_direct_param(mock_slack_client):
    """Test get_channel returns the channel provided during initialization."""
    mock_webclient, mock_client = mock_slack_client
    
    slack = RintSlack(token=TEST_TOKEN, channel=TEST_CHANNEL)
    
    assert slack.get_channel() == TEST_CHANNEL

@pytest.mark.parametrize("temp_env_file", [{"slack_token": ENV_TOKEN, "slack_channel": ENV_CHANNEL}], indirect=True)
def test_get_channel_from_env_file(mock_slack_client, temp_env_file):
    """Test get_channel returns the channel loaded from the environment file."""
    mock_webclient, mock_client = mock_slack_client
    
    slack = RintSlack(env=temp_env_file)
    
    assert slack.get_channel() == ENV_CHANNEL

@pytest.mark.parametrize("temp_env_file", [{"slack_token": ENV_TOKEN, "slack_channel": ENV_CHANNEL}], indirect=True)
def test_get_channel_param_overrides_env(mock_slack_client, temp_env_file):
    """Test get_channel returns the direct param value even when env file has a different value."""
    mock_webclient, mock_client = mock_slack_client
    
    slack = RintSlack(token=TEST_TOKEN, channel=TEST_CHANNEL, env=temp_env_file)
    
    assert slack.get_channel() == TEST_CHANNEL
