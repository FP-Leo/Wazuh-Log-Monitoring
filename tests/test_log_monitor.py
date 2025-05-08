import gc
import heapq
import sys
import time
import tracemalloc
import unittest
import pytest
import tempfile
import os
from datetime import datetime, timedelta
import requests
from unittest.mock import mock_open, patch, MagicMock, call

from log_monitor import LogCounter
from custom_errors import EnvVariableNotFoundError, NoCommunicationMethodEstablishedError
import log_monitor
from logger import LOGGING_CATEGORY
import importlib

# Fixtures
@pytest.fixture
def log_counter():
    """Create a LogCounter instance for testing."""
    counter = LogCounter()
    
    # Mock internal components to prevent actual external calls
    counter._slack_client = MagicMock()
    counter._smtp_client = MagicMock()
    counter._logger = MagicMock()
    counter._apiHandler = MagicMock()
    counter._envHandler = MagicMock()
    
    yield counter

@pytest.fixture
def agent_ids_file():
    """Create a temporary file with agent IDs for testing."""
    agent_ids = ["agent1", "agent2", "agent3"]
    
    with tempfile.NamedTemporaryFile(delete=False, mode="w") as temp_file:
        for agent_id in agent_ids:
            temp_file.write(f"{agent_id}\n")
        temp_file_path = temp_file.name
    
    yield temp_file_path, agent_ids
    
    # Force cleanup
    if os.path.exists(temp_file_path):
        os.remove(temp_file_path)

@pytest.fixture
def mock_env_vars():
    """Set mock environment variables for testing."""
    original_environ = os.environ.copy()
    os.environ["AGENT_LIST_FILE"] = "test_agents.txt"
    os.environ["DEFAULT_CHECK_INTERVAL"] = "600"
    os.environ["AGENT_CHECK_INTERVALS"] = "agent1:300,agent2:900"
    os.environ["WAZUH_URL"] = "https://test.com"
    os.environ["WAZUH_USERNAME"] = "test_user"
    os.environ["WAZUH_PASSWORD"] = "test_pass"
    
    yield
    
    os.environ.clear()
    os.environ.update(original_environ)

# Tests for __init__
def test_init():
    log_counter = LogCounter()
    assert log_counter._envHandler is None
    assert log_counter._logger is None
    assert log_counter._slack_client is None
    assert log_counter._smtp_client is None
    assert log_counter._apiHandler is None
    assert log_counter._agent_heap == []
    assert log_counter._next_check_times == {}

# Tests for __setup_env_handler
def test_setup_env_handler(log_counter):
    log_counter._LogCounter__setup_env_handler()
    assert log_counter._envHandler is not None

# Tests for __get_env_var
@patch("log_monitor.LogCounter._LogCounter__log")
def test_get_env_var_success(mock_log, log_counter):
    log_counter._envHandler.load_var.return_value = "test_value"
    
    result = log_counter._LogCounter__get_env_var("TEST_VAR")
    
    assert result == "test_value"
    log_counter._envHandler.load_var.assert_called_once_with("TEST_VAR")
    mock_log.assert_called_once()

@patch("log_monitor.LogCounter._LogCounter__log")
def test_get_env_var_default(mock_log, log_counter):
    log_counter._envHandler.load_var.side_effect = Exception("Variable not found")
    
    result = log_counter._LogCounter__get_env_var("TEST_VAR", default="default_value")
    
    assert result == "default_value"
    log_counter._envHandler.load_var.assert_called_once_with("TEST_VAR")
    mock_log.assert_called()

@patch("log_monitor.LogCounter._LogCounter__log")
def test_get_env_var_required(mock_log, log_counter):
    log_counter._envHandler.load_var.side_effect = Exception("Variable not found")
    
    with pytest.raises(EnvVariableNotFoundError):
        log_counter._LogCounter__get_env_var("TEST_VAR", required=True)
    
    log_counter._envHandler.load_var.assert_called_once_with("TEST_VAR")
    mock_log.assert_called()

# Tests for __setup_logger
@patch("log_monitor.Logger")
@patch("log_monitor.LogCounter._LogCounter__get_env_var")
def test_setup_logger_success(mock_get_env_var, mock_logger, log_counter):
    path = "logs/test.log"
    full_path = os.path.join(os.getcwd(), path)
    mock_get_env_var.side_effect = [path, "2"]
    mock_logger.return_value = MagicMock()
    
    result = log_counter._LogCounter__setup_logger()
    
    assert result is None

    mock_logger.assert_called_once_with(full_path, 2)
    assert log_counter._logger is mock_logger.return_value

@patch("log_monitor.Logger")
@patch("log_monitor.LogCounter._LogCounter__get_env_var")
def test_setup_logger_failure(mock_get_env_var, mock_logger, log_counter):
    mock_get_env_var.return_value = "logs/test.log"
    mock_logger.side_effect = Exception("Logger creation failed")
    
    result = log_counter._LogCounter__setup_logger()
    
    assert isinstance(result, str)
    assert "Failed to create logger" in result
    assert log_counter._logger is None

# Tests for __log
def test_log_with_logger(log_counter):
    log_counter._logger = MagicMock()
    
    log_counter._LogCounter__log("Test message", LOGGING_CATEGORY.INFO)
    
    log_counter._logger.write_log.assert_called_once_with(
        "LogCounter", LOGGING_CATEGORY.INFO, "Test message"
    )

def test_log_without_logger(log_counter):
    log_counter._logger = None
    
    # Should not raise exception
    result = log_counter._LogCounter__log("Test message")
    
    # Function returns None when logger is not set
    assert result is None

def test_log_exception(log_counter):
    log_counter._logger = MagicMock()
    log_counter._logger.write_log.side_effect = Exception("Log writing error")
    
    with pytest.raises(Exception) as excinfo:
        log_counter._LogCounter__log("Test message", LOGGING_CATEGORY.INFO)
    
    assert "Log writing error" in str(excinfo.value)
    log_counter._logger.write_log.assert_called_once()

def test_log_exception_handling(log_counter):
    log_counter._logger = MagicMock()
    log_counter._logger.write_log.side_effect = [Exception("First error"), None]  # Fail first, succeed second
    
    # First call should raise the exception
    with pytest.raises(Exception):
        log_counter._LogCounter__log("First message", LOGGING_CATEGORY.INFO)
    
    # Second call should succeed after exception was handled
    log_counter._LogCounter__log("Second message", LOGGING_CATEGORY.INFO)
    
    assert log_counter._logger.write_log.call_count == 2

# Tests for __setup_slack
@patch("log_monitor.SlackHandler")
def test_setup_slack_success(mock_slack, log_counter):
    mock_slack.return_value = MagicMock()
    
    result = log_counter._LogCounter__setup_slack()
    
    assert result is None
    assert log_counter._slack_client is mock_slack.return_value

@patch("log_monitor.SlackHandler")
def test_setup_slack_failure(mock_slack, log_counter):
    mock_slack.side_effect = Exception("Slack setup failed")
    
    result = log_counter._LogCounter__setup_slack()
    
    assert isinstance(result, str)
    assert "Failed to create slack client" in result
    assert log_counter._slack_client is None

# Tests for __send_slack_message
def test_send_slack_message_success(log_counter):
    result = log_counter._LogCounter__send_slack_message("Test message")
    
    assert result is True
    log_counter._slack_client.send_message.assert_called_once_with("Test message")

def test_send_slack_message_failure(log_counter):
    log_counter._slack_client.send_message.side_effect = Exception("Failed to send")
    
    result = log_counter._LogCounter__send_slack_message("Test message")
    
    assert result is False

def test_send_slack_message_no_client(log_counter):
    log_counter._slack_client = None
    
    result = log_counter._LogCounter__send_slack_message("Test message")
    
    assert result is False

# Tests for __setup_smtp
@patch("log_monitor.MailHandler")
def test_setup_smtp_success(mock_mail, log_counter):
    mock_mail.return_value = MagicMock()
    
    result = log_counter._LogCounter__setup_smtp()
    
    assert result is None
    assert log_counter._smtp_client is mock_mail.return_value

@patch("log_monitor.MailHandler")
def test_setup_smtp_failure(mock_mail, log_counter):
    mock_mail.side_effect = Exception("SMTP setup failed")
    
    result = log_counter._LogCounter__setup_smtp()
    
    assert isinstance(result, str)
    assert "Failed to create" in result
    assert log_counter._smtp_client is None

# Tests for __send_SMTP_Mail
def test_send_smtp_mail_success(log_counter):
    result = log_counter._LogCounter__send_SMTP_Mail(plain="Plain text", html="HTML text", subject="Subject")
    
    assert result is True
    log_counter._smtp_client.send_mail.assert_called_once_with(plain_msg="Plain text", html_msg="HTML text", subject="Subject")

def test_send_smtp_mail_failure(log_counter):
    log_counter._smtp_client.send_mail.side_effect = Exception("Failed to send")
    
    result = log_counter._LogCounter__send_SMTP_Mail(plain="Plain text", html="HTML text", subject="Subject")
    
    assert result is False

def test_send_smtp_mail_no_client(log_counter):
    log_counter._smtp_client = None
    
    result = log_counter._LogCounter__send_SMTP_Mail("Plain text", "HTML text", "Subject")
    
    assert result is False

def test_send_smtp_mail_no_content(log_counter):
    result = log_counter._LogCounter__send_SMTP_Mail(None, None, "Subject")
    
    assert result is False
    log_counter._smtp_client.send_mail.assert_not_called()

# Tests for __setup_basics
@patch("log_monitor.LogCounter._LogCounter__setup_logger")
@patch("log_monitor.LogCounter._LogCounter__setup_slack")
@patch("log_monitor.LogCounter._LogCounter__setup_smtp")
@patch("log_monitor.LogCounter._LogCounter__notify_channels")
def test_setup_basics_all_success(mock_notify, mock_setup_smtp, mock_setup_slack, mock_setup_logger, log_counter):
    """Test that when all setup methods succeed, notification is not attempted."""
    # Setup: All components initialize successfully
    mock_setup_logger.return_value = None  # No error
    mock_setup_slack.return_value = None   # No error
    mock_setup_smtp.return_value = None    # No error
    
    # Execute
    log_counter._LogCounter__setup_basics()
    
    # Assert
    mock_setup_logger.assert_called_once()
    mock_setup_slack.assert_called_once()
    mock_setup_smtp.assert_called_once()
    mock_notify.assert_not_called()  # No need to notify if all succeeds

@patch("log_monitor.LogCounter._LogCounter__setup_logger")
@patch("log_monitor.LogCounter._LogCounter__setup_slack")
@patch("log_monitor.LogCounter._LogCounter__setup_smtp")
@patch("log_monitor.LogCounter._LogCounter__notify_channels")
def test_setup_basics_some_failures_notification_success(mock_notify, mock_setup_smtp, mock_setup_slack, mock_setup_logger, log_counter):
    """Test that when some setup methods fail but notification succeeds, the process continues."""
    # Setup: Some components fail to initialize
    mock_setup_logger.return_value = "Logger error"
    mock_setup_slack.return_value = None  # No error
    mock_setup_smtp.return_value = "SMTP error"
    mock_notify.return_value = True  # Notification succeeds
    
    # Execute
    log_counter._LogCounter__setup_basics()
    
    # Assert
    mock_setup_logger.assert_called_once()
    mock_setup_slack.assert_called_once()
    mock_setup_smtp.assert_called_once()
    mock_notify.assert_called_once()
    assert "Logger error" in mock_notify.call_args[0][0]
    assert "SMTP error" in mock_notify.call_args[0][0]

@patch("log_monitor.LogCounter._LogCounter__setup_logger")
@patch("log_monitor.LogCounter._LogCounter__setup_slack")
@patch("log_monitor.LogCounter._LogCounter__setup_smtp")
@patch("log_monitor.LogCounter._LogCounter__notify_channels")
def test_setup_basics_all_failures(mock_notify, mock_setup_smtp, mock_setup_slack, mock_setup_logger, log_counter):
    """Test behavior when all setup methods fail."""
    # Setup: All components fail to initialize
    mock_setup_logger.return_value = "Logger error"
    mock_setup_slack.return_value = "Slack error"
    mock_setup_smtp.return_value = "SMTP error"
    mock_notify.return_value = True  # Notification succeeds
    
    # Execute & Assert
    with pytest.raises(Exception):
        log_counter._LogCounter__setup_basics()
    
    mock_setup_logger.assert_called_once()
    mock_setup_slack.assert_called_once()
    mock_setup_smtp.assert_called_once()

@patch("log_monitor.LogCounter._LogCounter__setup_logger")
@patch("log_monitor.LogCounter._LogCounter__setup_slack")
@patch("log_monitor.LogCounter._LogCounter__setup_smtp")
@patch("log_monitor.LogCounter._LogCounter__notify_channels")
def test_setup_basics_notification_failure(mock_notify, mock_setup_smtp, mock_setup_slack, mock_setup_logger, log_counter):
    """Test that when notification fails, NoCommunicationMethodEstablishedError is raised."""
    # Setup: Some components fail and notification also fails
    mock_setup_logger.return_value = "Logger error"
    mock_setup_slack.return_value = "Slack error"
    mock_setup_smtp.return_value = None  # No error
    mock_notify.return_value = False  # Notification fails
    
    # Execute & Assert
    with pytest.raises(NoCommunicationMethodEstablishedError):
        log_counter._LogCounter__setup_basics()
    
    mock_setup_logger.assert_called_once()
    mock_setup_slack.assert_called_once()
    mock_setup_smtp.assert_called_once()
    mock_notify.assert_called_once()
    assert "Logger error" in mock_notify.call_args[0][0]
    assert "Slack error" in mock_notify.call_args[0][0]

@patch("log_monitor.LogCounter._LogCounter__setup_logger")
@patch("log_monitor.LogCounter._LogCounter__setup_slack")
@patch("log_monitor.LogCounter._LogCounter__setup_smtp")
@patch("log_monitor.LogCounter._LogCounter__notify_channels")
def test_setup_basics_logger_success(mock_notify, mock_setup_smtp, mock_setup_slack, mock_setup_logger, log_counter):
    """Test that when notification fails, NoCommunicationMethodEstablishedError is raised."""
    # Setup: Some components fail and notification also fails
    mock_setup_logger.return_value = None 
    mock_setup_slack.return_value = "Slack error"
    mock_setup_smtp.return_value = "SMTP error"
    mock_notify.return_value = True

    log_counter._LogCounter__setup_basics()

    mock_setup_logger.assert_called_once()
    mock_setup_slack.assert_called_once()
    mock_setup_smtp.assert_called_once()
    mock_notify.assert_called_once()
    assert "SMTP error" in mock_notify.call_args[0][0]
    assert "Slack error" in mock_notify.call_args[0][0]

# Tests for __notify_channels
@patch("socket.gethostname", return_value="test-machine")
@patch("os.path.basename", return_value="test_script.py")
def test_notify_channels_slack_success(mock_basename, mock_hostname, log_counter):
    """Test notification via Slack succeeds."""
    # Setup
    log_counter._LogCounter__send_slack_message = MagicMock(return_value=True)
    log_counter._LogCounter__send_SMTP_Mail = MagicMock(return_value=True)
    
    # Execute
    result = log_counter._LogCounter__notify_channels("Test message")
    
    # Assert
    assert result is True
    expected_message = "Test message"
    log_counter._LogCounter__send_slack_message.assert_called_once_with(expected_message)
    log_counter._LogCounter__send_SMTP_Mail.assert_not_called()

@patch("socket.gethostname", return_value="test-machine")
@patch("os.path.basename", return_value="test_script.py")
def test_notify_channels_slack_fails_smtp_success(mock_basename, mock_hostname, log_counter):
    """Test notification falls back to SMTP when Slack fails."""
    # Setup
    log_counter._LogCounter__send_slack_message = MagicMock(return_value=False)
    log_counter._LogCounter__send_SMTP_Mail = MagicMock(return_value=True)
    
    # Execute
    result = log_counter._LogCounter__notify_channels("Test message")
    
    # Assert
    assert result is True
    expected_message = "Test message"
    smtp_msg = "Failed to send the following message to slack: \"" + expected_message + "\""
    log_counter._LogCounter__send_slack_message.assert_called_once_with(expected_message)
    log_counter._LogCounter__send_SMTP_Mail.assert_called_once_with(plain=smtp_msg)

@patch("socket.gethostname", return_value="test-machine")
@patch("os.path.basename", return_value="test_script.py")
def test_notify_channels_all_fail(mock_basename, mock_hostname, log_counter):
    """Test notification behavior when both Slack and SMTP fail."""
    # Setup
    log_counter._LogCounter__send_slack_message = MagicMock(return_value=False)
    log_counter._LogCounter__send_SMTP_Mail = MagicMock(return_value=False)
    log_counter._LogCounter__log = MagicMock(return_value=False)
    
    # Execute
    result = log_counter._LogCounter__notify_channels("Test message")
    
    # Assert
    assert result is False
    expected_message = "Test message"
    smtp_msg = "Failed to send the following message to slack: \"" + expected_message + "\""
    log_msg = "Failed to send the following message to slack and mail: \"" + expected_message + "\""
    log_counter._LogCounter__send_slack_message.assert_called_once_with(expected_message)
    log_counter._LogCounter__send_SMTP_Mail.assert_called_once_with(plain=smtp_msg)
    log_counter._LogCounter__log.assert_called_once_with(log_msg, LOGGING_CATEGORY.ERROR)
    
@pytest.mark.skip(reason="The feature got removed upon request") 
@patch("socket.gethostname")
@patch("os.path.basename", return_value="test_script.py")
def test_notify_channels_hostname_exception(mock_basename, mock_hostname, log_counter):
    """Test notification behavior when hostname retrieval fails."""
    # Setup
    mock_hostname.side_effect = Exception("Hostname error")
    log_counter._LogCounter__send_slack_message = MagicMock(return_value=True)
    log_counter._LogCounter__log = MagicMock()
    
    # Execute
    result = log_counter._LogCounter__notify_channels("Test message")
    
    # Assert
    assert result is True
    expected_message = "Test message"
    log_counter._LogCounter__send_slack_message.assert_called_once_with(expected_message)
    log_counter._LogCounter__log.assert_any_call(
        "Failed to retrieve machine name with the following error: Exception('Hostname error')",
        LOGGING_CATEGORY.WARNING
    )

@pytest.mark.skip(reason="The feature got removed upon request") 
@patch("socket.gethostname", return_value="test-machine")
@patch("os.path.basename")
def test_notify_channels_basename_exception(mock_basename, mock_hostname, log_counter):
    """Test notification behavior when script name retrieval fails."""
    # Setup
    mock_basename.side_effect = Exception("Basename error")
    log_counter._LogCounter__send_slack_message = MagicMock(return_value=True)
    log_counter._LogCounter__log = MagicMock()
    
    # Execute
    result = log_counter._LogCounter__notify_channels("Test message")
    
    # Assert
    assert result is True
    expected_message = "Test message"
    log_counter._LogCounter__send_slack_message.assert_called_once_with(expected_message)
    log_counter._LogCounter__log.assert_any_call(
        "Failed to retrieve script name with the following error: Exception('Basename error')",
        LOGGING_CATEGORY.WARNING
    )

# Tests for __setup_wazuh_handler
@patch("log_monitor.WAH")
@patch("log_monitor.LogCounter._LogCounter__get_env_var")
@patch("log_monitor.LogCounter._LogCounter__log")
def test_setup_wazuh_handler_success(mock_log, mock_get_env_var, mock_wazuh_handler, log_counter):
    """Test successful wazuh API handler initialization."""
    # Setup
    mock_get_env_var.side_effect = [
        "username",                # Username
        "password",                # Password
        "https://api.example.com",  # API URL
        "extra-files/root-ca.pem",  # Root CA file
    ]
    mock_handler_instance = MagicMock()
    mock_wazuh_handler.return_value = mock_handler_instance
    
    # Execute
    log_counter._LogCounter__setup_wazuh_handler()
    
    # Assert
    assert log_counter._apiHandler is mock_handler_instance
    mock_get_env_var.assert_has_calls([
        call("USERNAME", required=True, log_value=False),
        call("PASSWORD", required=True, log_value=False),
        call("WAZUH_URL", required=True, log_value=False),
        call("VERIFICATION_FILE", required=True, log_value=False)
    ], any_order=True)
    mock_log.assert_called_with("Successfully created API Handler.")

@patch("log_monitor.WAH")
@patch("log_monitor.LogCounter._LogCounter__get_env_var")
@patch("log_monitor.LogCounter._LogCounter__log")
@patch("log_monitor.LogCounter._LogCounter__notify_channels")
def test_setup_wazuh_handler_missing_env_vars(mock_notify, mock_log, mock_get_env_var, mock_wazuh_handler, log_counter):
    """Test failure due to missing required environment variables."""
    # Setup
    mock_get_env_var.side_effect = EnvVariableNotFoundError("WAZUH_URL not found")
    
    # Execute & Assert
    with pytest.raises(EnvVariableNotFoundError):
        log_counter._LogCounter__setup_wazuh_handler()
    
    mock_notify.assert_called_once()
    mock_wazuh_handler.assert_not_called()

@patch("log_monitor.WAH")
@patch("log_monitor.LogCounter._LogCounter__get_env_var")
@patch("log_monitor.LogCounter._LogCounter__log")
@patch("log_monitor.LogCounter._LogCounter__notify_channels")
def test_setup_wazuh_handler_init_exception(mock_notify, mock_log, mock_get_env_var, mock_wazuh_handler, log_counter):
    """Test handling of exceptions during API handler initialization."""
    # Setup
    mock_get_env_var.side_effect = [
        "username",                # Username
        "password",                # Password
        "extra-files/root-ca.pem",  # Verify SSL
        "https://api.example.com"  # API URL
    ]
    mock_wazuh_handler.side_effect = Exception("Connection failed")
    
    # Execute & Assert
    with pytest.raises(Exception):
        log_counter._LogCounter__setup_wazuh_handler()
    
    mock_notify.assert_called_once()
    mock_log.assert_called_once_with(f"Failed to create API Handler with the following error: Exception('Connection failed')", LOGGING_CATEGORY.ERROR)

# Tests for __load_agents
@patch("builtins.open", new_callable=mock_open, read_data="001,Agent One\n002,Agent Two\n003,Agent Three\n")
@patch("log_monitor.LogCounter._LogCounter__log")
def test_load_agents_success(mock_log, mock_open_file, log_counter):
    file_path = "test_agents.txt"
    expected_agents = {"001": "Agent One", "002": "Agent Two", "003": "Agent Three"}
    
    result = log_counter._LogCounter__load_agents(file_path)
    
    assert result == expected_agents
    mock_log.assert_any_call(f"Successfully loaded 3 unique agent ID(s) from {file_path}.")

@patch("log_monitor.LogCounter._LogCounter__log")
@patch("log_monitor.LogCounter._LogCounter__notify_channels")
def test_load_agents_file_not_found(mock_notify, mock_log, log_counter):
    with pytest.raises(FileNotFoundError):
        log_counter._LogCounter__load_agents("nonexistent_file.txt")
    
    mock_notify.assert_called_once()
    mock_log.assert_any_call("File: nonexistent_file.txt not found.", LOGGING_CATEGORY.ERROR)

@patch("log_monitor.LogCounter._LogCounter__log")
@patch("log_monitor.LogCounter._LogCounter__notify_channels")
@patch("builtins.open", side_effect=Exception("Unexpected error"))
def test_load_agents_unexpected_error(mock_open_file, mock_notify, mock_log, log_counter):
    with pytest.raises(Exception):
        log_counter._LogCounter__load_agents("test_agents.txt")
    
    mock_notify.assert_called_once()
    mock_log.assert_any_call("Failed to read AGENT_LIST_FILE with error: Exception('Unexpected error')", LOGGING_CATEGORY.ERROR)

@patch("log_monitor.LogCounter._LogCounter__log")
def test_load_agents_with_multiple_agents(mock_log, log_counter):
    """Test loading multiple agents from a temp file."""
    # Create a temp file with multiple agent entries
    agent_entries = [
        "001,Regular Agent", 
        "002,Special Agent",
        "003,Backend Agent",
        "004,Agent with underscore_name",
        "005,Agent-with-dash",
        "006,Agent.with.dots"
    ]
    
    with tempfile.NamedTemporaryFile(delete=False, mode="w") as temp_file:
        for entry in agent_entries:
            temp_file.write(f"{entry}\n")
        temp_file_path = temp_file.name
    
    try:
        # Test loading agents
        result = log_counter._LogCounter__load_agents(temp_file_path)
        
        # Verify all agents were loaded correctly
        expected = {
            "001": "Regular Agent",
            "002": "Special Agent",
            "003": "Backend Agent",
            "004": "Agent with underscore_name",
            "005": "Agent-with-dash",
            "006": "Agent.with.dots"
        }
        assert result == expected
        mock_log.assert_any_call(f"Successfully loaded 6 unique agent ID(s) from {temp_file_path}.")
    finally:
        # Clean up
        if os.path.exists(temp_file_path):
            os.remove(temp_file_path)

@patch("log_monitor.LogCounter._LogCounter__log")
def test_load_agents_with_whitespace_and_comments(mock_log, log_counter):
    """Test loading agents with whitespace and comment lines."""
    # Create a temp file with agent entries, blank lines and comments
    file_content = """
    # This is a comment
    001, Agent One
    
    002, Agent Two   
    # Another comment
        003, Agent Three  
    """
    
    with tempfile.NamedTemporaryFile(delete=False, mode="w") as temp_file:
        temp_file.write(file_content)
        temp_file_path = temp_file.name
    
    try:
        # Test loading agents
        result = log_counter._LogCounter__load_agents(temp_file_path)
        
        # Verify agents were loaded correctly, ignoring comments and whitespace
        expected = {
            "001": "Agent One",
            "002": "Agent Two",
            "003": "Agent Three"
        }
        assert result == expected
        mock_log.assert_any_call(f"Successfully loaded 3 unique agent ID(s) from {temp_file_path}.")
    finally:
        # Clean up
        if os.path.exists(temp_file_path):
            os.remove(temp_file_path)

@patch("log_monitor.LogCounter._LogCounter__log")
def test_load_agents_with_duplicates(mock_log, log_counter):
    """Test loading agents with duplicate IDs."""
    # Create a temp file with duplicate agent IDs
    file_content = """
    001,Agent One
    002,Agent Two
    001,Duplicate Agent
    003,Agent Three
    002,Another Duplicate
    """
    
    with tempfile.NamedTemporaryFile(delete=False, mode="w") as temp_file:
        temp_file.write(file_content)
        temp_file_path = temp_file.name
    
    try:
        # Test loading agents
        result = log_counter._LogCounter__load_agents(temp_file_path)
        
        # Verify duplicates are ignored (only first occurrence kept)
        expected = {
            "001": "Agent One",
            "002": "Agent Two",
            "003": "Agent Three"
        }
        assert result == expected
        
        # Check for warning logs about duplicates
        mock_log.assert_any_call("Duplicate Agent ID '001' found at line 4. Ignoring.", LOGGING_CATEGORY.WARNING)
        mock_log.assert_any_call("Duplicate Agent ID '002' found at line 6. Ignoring.", LOGGING_CATEGORY.WARNING)
        mock_log.assert_any_call(f"Successfully loaded 3 unique agent ID(s) from {temp_file_path}.")
    finally:
        # Clean up
        if os.path.exists(temp_file_path):
            os.remove(temp_file_path)

@patch("log_monitor.LogCounter._LogCounter__log")
def test_load_agents_with_large_file(mock_log, log_counter):
    """Test loading a large number of agents."""
    # Create a temp file with many agent entries
    agent_count = 1000
    
    with tempfile.NamedTemporaryFile(delete=False, mode="w") as temp_file:
        for i in range(agent_count):
            temp_file.write(f"{i:05d},Agent Number {i}\n")
        temp_file_path = temp_file.name
    
    try:
        # Test loading agents
        result = log_counter._LogCounter__load_agents(temp_file_path)
        
        # Verify all agents were loaded correctly
        assert len(result) == agent_count
        for i in range(agent_count):
            agent_id = f"{i:05d}"
            assert agent_id in result
            assert result[agent_id] == f"Agent Number {i}"
            
        mock_log.assert_any_call(f"Successfully loaded {agent_count} unique agent ID(s) from {temp_file_path}.")
    finally:
        # Clean up
        if os.path.exists(temp_file_path):
            os.remove(temp_file_path)

@patch("log_monitor.LogCounter._LogCounter__log")
def test_load_agents_with_invalid_format(mock_log, log_counter):
    """Test loading agents with invalid format lines."""
    # Create a temp file with some invalid format entries
    file_content = """
    001,Agent One
    invalid_line
    002,Agent Two
    003
    004,Agent Four,Extra Field
    005,Agent Five
    """
    
    with tempfile.NamedTemporaryFile(delete=False, mode="w") as temp_file:
        temp_file.write(file_content)
        temp_file_path = temp_file.name
    
    try:
        # Test loading agents
        result = log_counter._LogCounter__load_agents(temp_file_path)
        
        # Verify only valid entries were loaded
        expected = {
            "001": "Agent One",
            "002": "Agent Two",
            "004": "Agent Four,Extra Field",  # This will be included as is
            "005": "Agent Five"
        }
        assert result == expected
        
        # Check for warning logs about invalid formats
        mock_log.assert_any_call("Line 3 is not in expected 'id,label' format: 'invalid_line'", LOGGING_CATEGORY.WARNING)
        mock_log.assert_any_call("Line 5 is not in expected 'id,label' format: '003'", LOGGING_CATEGORY.WARNING)
        mock_log.assert_any_call(f"Successfully loaded 4 unique agent ID(s) from {temp_file_path}.")
    finally:
        # Clean up
        if os.path.exists(temp_file_path):
            os.remove(temp_file_path)

@patch("log_monitor.LogCounter._LogCounter__log")
def test_load_agents_with_non_numeric_ids(mock_log, log_counter):
    """Test loading agents with non-numeric IDs."""
    # Create a temp file with some non-numeric IDs
    file_content = """
    001,Agent One
    ABC,Invalid Agent
    002,Agent Two
    XYZ-123,Invalid Agent
    003,Agent Three
    """
    
    with tempfile.NamedTemporaryFile(delete=False, mode="w") as temp_file:
        temp_file.write(file_content)
        temp_file_path = temp_file.name
    
    try:
        # Test loading agents
        result = log_counter._LogCounter__load_agents(temp_file_path)
        
        # Verify only agents with numeric IDs were loaded
        expected = {
            "001": "Agent One",
            "002": "Agent Two",
            "003": "Agent Three"
        }
        assert result == expected
        
        # Check for warning logs about non-numeric IDs
        mock_log.assert_any_call("Agent ID 'ABC' at line 3 is not a valid numeric ID.", LOGGING_CATEGORY.WARNING)
        mock_log.assert_any_call("Agent ID 'XYZ-123' at line 5 is not a valid numeric ID.", LOGGING_CATEGORY.WARNING)
        mock_log.assert_any_call(f"Successfully loaded 3 unique agent ID(s) from {temp_file_path}.")
    finally:
        # Clean up
        if os.path.exists(temp_file_path):
            os.remove(temp_file_path)

@patch("log_monitor.LogCounter._LogCounter__log")
def test_load_agents_with_empty_fields(mock_log, log_counter):
    """Test loading agents with empty ID or label fields."""
    # Create a temp file with some empty fields
    file_content = """
    001,Agent One
    ,Empty ID
    002,
    003,Agent Three
    """
    
    with tempfile.NamedTemporaryFile(delete=False, mode="w") as temp_file:
        temp_file.write(file_content)
        temp_file_path = temp_file.name
    
    try:
        # Test loading agents
        result = log_counter._LogCounter__load_agents(temp_file_path)
        
        # Verify only complete entries were loaded
        expected = {
            "001": "Agent One",
            "003": "Agent Three"
        }
        assert result == expected
        
        # Check for warning logs about incomplete entries
        mock_log.assert_any_call("Incomplete agent info at line 3: ',Empty ID'", LOGGING_CATEGORY.WARNING)
        mock_log.assert_any_call("Incomplete agent info at line 4: '002,'", LOGGING_CATEGORY.WARNING)
        mock_log.assert_any_call(f"Successfully loaded 2 unique agent ID(s) from {temp_file_path}.")
    finally:
        # Clean up
        if os.path.exists(temp_file_path):
            os.remove(temp_file_path)

@patch("log_monitor.LogCounter._LogCounter__log")
def test_load_agents_empty_file(mock_log, log_counter):
    """Test loading agents from an empty file."""
    with tempfile.NamedTemporaryFile(delete=False, mode="w") as temp_file:
        temp_file_path = temp_file.name
    
    try:
        # Test loading agents from empty file
        result = log_counter._LogCounter__load_agents(temp_file_path)
        
        # Verify an empty dictionary is returned
        assert result == {}
        mock_log.assert_any_call(f"Successfully loaded 0 unique agent ID(s) from {temp_file_path}.")
    finally:
        # Clean up
        if os.path.exists(temp_file_path):
            os.remove(temp_file_path)

# Tests for __getDCI
@patch("log_monitor.LogCounter._LogCounter__log")
@patch("log_monitor.LogCounter._LogCounter__get_env_var", return_value="10")
def test_getDCI_success(mock_get_env_var, mock_log, log_counter):
    result = log_counter._LogCounter__getDCI()
    
    assert result == 600
    mock_get_env_var.assert_called_once_with("DEFAULT_CHECK_INTERVAL", default=900)
    mock_log.assert_called()

@patch("log_monitor.LogCounter._LogCounter__log")
@patch("log_monitor.LogCounter._LogCounter__get_env_var", return_value="invalid")
def test_getDCI_invalid_value(mock_get_env_var, mock_log, log_counter):
    result = log_counter._LogCounter__getDCI()
    
    assert result == 900  # Default value
    mock_get_env_var.assert_called_once_with("DEFAULT_CHECK_INTERVAL", default=900)
    mock_log.assert_called()

@patch("log_monitor.LogCounter._LogCounter__log")
@patch("log_monitor.LogCounter._LogCounter__get_env_var", return_value="-100")
def test_getDCI_negative_value(mock_get_env_var, mock_log, log_counter):
    result = log_counter._LogCounter__getDCI()
    
    assert result == 900  # Default value should be returned
    mock_get_env_var.assert_called_once_with("DEFAULT_CHECK_INTERVAL", default=900)
    mock_log.assert_any_call("DEFAULT_CHECK_INTERVAL must be a positive integer. Using default value of 900 seconds.", LOGGING_CATEGORY.WARNING)
    mock_log.assert_any_call("Succesfully set default checking interval to 900")

# Tests for __load_agent_check_intervals
@patch("log_monitor.LogCounter._LogCounter__log")
@patch("log_monitor.LogCounter._LogCounter__get_env_var", return_value="agent1:600,agent2:300")
def test_load_agent_check_intervals_success(mock_get_env_var, mock_log, log_counter):
    result = log_counter._LogCounter__load_agent_check_intervals(["agent1", "agent2", "agent3"])
    
    assert result == {"agent1": 600*60, "agent2": 300*60}
    mock_get_env_var.assert_called_once_with("AGENT_CHECK_INTERVALS")
    mock_log.assert_called()

@patch("log_monitor.LogCounter._LogCounter__log")
@patch("log_monitor.LogCounter._LogCounter__get_env_var", return_value="invalid_format")
def test_load_agent_check_intervals_invalid_format(mock_get_env_var, mock_log, log_counter):
    result = log_counter._LogCounter__load_agent_check_intervals(["agent1", "agent2", "agent3"])
    
    assert result == {}
    mock_get_env_var.assert_called_once_with("AGENT_CHECK_INTERVALS")
    mock_log.assert_called()

@patch("log_monitor.LogCounter._LogCounter__log")
@patch("log_monitor.LogCounter._LogCounter__get_env_var", return_value="agent1:600,agent4:300")
def test_load_agent_check_intervals_missing_agent(mock_get_env_var, mock_log, log_counter):
    """
    Test that a warning is logged when an agent in AGENT_CHECK_INTERVALS is not found in the agent_ids list.
    """
    # Given a list of agent IDs that doesn't include agent4
    agent_ids = ["agent1", "agent2", "agent3"]
    
    # When loading agent check intervals
    result = log_counter._LogCounter__load_agent_check_intervals(agent_ids)
    
    # Then only agent1 should be included in the result
    assert result == {"agent1": 600*60}
    mock_get_env_var.assert_called_once_with("AGENT_CHECK_INTERVALS")
    
    # And a warning should be logged about agent4 not being found
    expected_warning = "Agent agent4 specified in AGENT_CHECK_INTERVALS not found in the registered agent IDs. Maybe it was deleted?"
    
    # Find the relevant log call
    warning_logged = False
    for call in mock_log.call_args_list:
        args, kwargs = call
        if expected_warning in args[0]:
            warning_logged = True
            break
    
    assert warning_logged, "No warning logged for missing agent"

@patch("log_monitor.LogCounter._LogCounter__log")
@patch("log_monitor.LogCounter._LogCounter__get_env_var", return_value="agent1:foo,agent2:300")
def test_load_agent_check_intervals_invalid_interval(mock_get_env_var, mock_log, log_counter):
    """
    Test handling of invalid interval values in AGENT_CHECK_INTERVALS.
    Should log a warning and skip the invalid interval.
    """
    # Given a list of agent IDs
    agent_ids = ["agent1", "agent2", "agent3"]
    
    # When loading agent check intervals with an invalid interval value for agent1
    result = log_counter._LogCounter__load_agent_check_intervals(agent_ids)
    
    # Then only agent2 should be included in the result with a valid interval
    assert result == {"agent2": 300*60}
    mock_get_env_var.assert_called_once_with("AGENT_CHECK_INTERVALS")
    
    # And a warning should be logged about the invalid interval
    expected_warning = "Interval foo for agent agent1 is not a valid integer."
    
    # Find the relevant log call
    warning_logged = False
    for call in mock_log.call_args_list:
        args, kwargs = call
        if expected_warning in args[0]:
            warning_logged = True
            break
    
    assert warning_logged, "No warning logged for invalid interval"

@patch("log_monitor.LogCounter._LogCounter__log")
@patch("log_monitor.LogCounter._LogCounter__get_env_var", return_value=None)
def test_load_agent_check_intervals_not_specified(mock_get_env_var, mock_log, log_counter):
    """
    Test behavior when AGENT_CHECK_INTERVALS environment variable is not specified.
    Should log a warning and return an empty dictionary.
    """
    # Given a list of agent IDs
    agent_ids = ["agent1", "agent2", "agent3"]
    
    # When loading agent check intervals without specifying the environment variable
    result = log_counter._LogCounter__load_agent_check_intervals(agent_ids)
    
    # Then an empty dictionary should be returned
    assert result == {}
    mock_get_env_var.assert_called_once_with("AGENT_CHECK_INTERVALS")
    
    # And a warning should be logged about missing AGENT_CHECK_INTERVALS
    expected_warning = "Agent Check Intervals weren't specified in the .env file. If needed consider specifying it with 'AGENT_CHECK_INTERVALS='."
    mock_log.assert_any_call(expected_warning, LOGGING_CATEGORY.WARNING)

# Tests for __setup_query
@patch("log_monitor.LogCounter._LogCounter__log")
def test_setup_query(mock_log, log_counter):
    result = log_counter._LogCounter__setup_query(600, "agent1")
    
    assert "query" in result
    assert "bool" in result["query"]
    assert "must" in result["query"]["bool"]
    assert len(result["query"]["bool"]["must"]) == 2
    mock_log.assert_called_once()

# Tests for __refresh_agent_heap
@patch("log_monitor.LogCounter._LogCounter__log")
@patch("log_monitor.LogCounter._LogCounter__schedule_agent")
def test_refresh_agent_heap(mock_schedule_agent, mock_log, log_counter):
    log_counter._next_check_times = {"agent1": datetime.now(), "agent2": datetime.now()}
    
    log_counter._LogCounter__refresh_agent_heap(["agent1", "agent3"])
    
    assert "agent2" not in log_counter._next_check_times
    mock_schedule_agent.assert_called_once_with("agent3", 0)
    mock_log.assert_called()

@patch("log_monitor.LogCounter._LogCounter__log")
@patch("log_monitor.LogCounter._LogCounter__schedule_agent")
def test_refresh_agent_heap_no_changes(mock_schedule_agent, mock_log, log_counter):
    """Test refreshing agent heap when there are no changes to the agent list."""
    # Setup initial state with some agents
    agent_ids = ["agent1", "agent2", "agent3"]
    now = datetime.now()
    log_counter._agent_heap = [(now, "agent1"), (now, "agent2"), (now, "agent3")]
    log_counter._next_check_times = {"agent1": now, "agent2": now, "agent3": now}
    
    # Execute with the same list
    log_counter._LogCounter__refresh_agent_heap(agent_ids)
    
    # Assert no agents were added or removed
    assert len(log_counter._next_check_times) == 3
    assert set(log_counter._next_check_times.keys()) == set(agent_ids)
    mock_schedule_agent.assert_not_called()
    mock_log.assert_called_once()

@patch("log_monitor.LogCounter._LogCounter__log")
@patch("log_monitor.LogCounter._LogCounter__schedule_agent")
def test_refresh_agent_heap_add_and_remove(mock_schedule_agent, mock_log, log_counter):
    """Test refreshing agent heap when agents are both added and removed."""
    # Setup initial state
    now = datetime.now()
    log_counter._agent_heap = [(now, "agent1"), (now, "agent2"), (now, "agent3")]
    log_counter._next_check_times = {"agent1": now, "agent2": now, "agent3": now}
    
    # New list with agent2 removed and agent4 added
    new_agent_ids = ["agent1", "agent3", "agent4"]
    
    # Execute
    log_counter._LogCounter__refresh_agent_heap(new_agent_ids)
    
    # Assert agent2 was removed and agent4 was added
    assert "agent2" not in log_counter._next_check_times
    mock_schedule_agent.assert_called_once_with("agent4", 0)
    mock_log.assert_called_once()

@patch("log_monitor.LogCounter._LogCounter__log")
@patch("log_monitor.LogCounter._LogCounter__schedule_agent")
def test_refresh_agent_heap_multiple_new_agents(mock_schedule_agent, mock_log, log_counter):
    """Test refreshing agent heap when multiple new agents are added."""
    # Setup initial state
    now = datetime.now()
    log_counter._agent_heap = [(now, "agent1")]
    log_counter._next_check_times = {"agent1": now}
    
    # New list with multiple new agents
    new_agent_ids = ["agent1", "agent2", "agent3", "agent4"]
    
    # Execute
    log_counter._LogCounter__refresh_agent_heap(new_agent_ids)
    
    # Assert all new agents were scheduled
    assert mock_schedule_agent.call_count == 3
    mock_schedule_agent.assert_has_calls([
        call("agent2", 0),
        call("agent3", 0),
        call("agent4", 0)
    ], any_order=True)
    mock_log.assert_called_once()

@patch("log_monitor.LogCounter._LogCounter__log")
@patch("log_monitor.LogCounter._LogCounter__schedule_agent")
def test_refresh_agent_heap_all_new_agents(mock_schedule_agent, mock_log, log_counter):
    """Test refreshing agent heap when all agents are new."""
    # Setup empty initial state
    log_counter._agent_heap = []
    log_counter._next_check_times = {}
    
    # New list with all new agents
    new_agent_ids = ["agent1", "agent2", "agent3"]
    
    # Execute
    log_counter._LogCounter__refresh_agent_heap(new_agent_ids)
    
    # Assert all agents were scheduled
    assert mock_schedule_agent.call_count == 3
    mock_log.assert_called_once()

@patch("log_monitor.LogCounter._LogCounter__log")
@patch("log_monitor.LogCounter._LogCounter__schedule_agent")
def test_refresh_agent_heap_all_agents_removed(mock_schedule_agent, mock_log, log_counter):
    """Test refreshing agent heap when all existing agents are removed."""
    # Setup initial state with some agents
    now = datetime.now()
    log_counter._agent_heap = [(now, "agent1"), (now, "agent2")]
    log_counter._next_check_times = {"agent1": now, "agent2": now}
    
    # Execute with empty list
    log_counter._LogCounter__refresh_agent_heap([])
    
    # Assert all agents were removed
    assert len(log_counter._next_check_times) == 0
    assert len(log_counter._agent_heap) == 0
    mock_schedule_agent.assert_not_called()
    mock_log.assert_called_once()

@patch("log_monitor.LogCounter._LogCounter__log")
@patch("log_monitor.LogCounter._LogCounter__schedule_agent")
def test_refresh_agent_heap_heap_integrity(mock_schedule_agent, mock_log, log_counter):
    """Test that the agent heap maintains proper heap integrity after refresh."""
    # Setup initial state with agents having different times
    now = datetime.now()
    time1 = now + timedelta(seconds=10)
    time2 = now + timedelta(seconds=20)
    time3 = now + timedelta(seconds=30)
    
    log_counter._agent_heap = [(time1, "agent1"), (time2, "agent2"), (time3, "agent3")]
    log_counter._next_check_times = {"agent1": time1, "agent2": time2, "agent3": time3}
    
    # New list with agent2 removed and agent4 added
    new_agent_ids = ["agent1", "agent3", "agent4"]
    
    # Mock schedule_agent to add a specific time for the new agent
    time4 = now + timedelta(seconds=5)  # Earlier than all others
    def mock_schedule(agent_id, interval):
        if agent_id == "agent4":
            log_counter._next_check_times[agent_id] = time4
            log_counter._agent_heap.append((time4, agent_id))
    mock_schedule_agent.side_effect = mock_schedule
    
    # Execute
    log_counter._LogCounter__refresh_agent_heap(new_agent_ids)
    
    # Assert heap is properly structured
    # After heapify, agent4 should be first since it has the earliest time
    assert len(log_counter._agent_heap) == 3
    assert log_counter._agent_heap[0][1] == "agent4"
    mock_log.assert_called_once()

@patch("log_monitor.LogCounter._LogCounter__log")
def test_refresh_agent_heap_duplicate_agent_ids(mock_log, log_counter):
    """Test refreshing agent heap when the agent_ids list contains duplicates."""
    # Setup initial state
    now = datetime.now()
    log_counter._agent_heap = [(now, "agent1")]
    log_counter._next_check_times = {"agent1": now}
    
    # List with duplicate agent IDs
    agent_ids = ["agent1", "agent2", "agent1", "agent2"]
    
    # Execute
    log_counter._LogCounter__refresh_agent_heap(agent_ids)
    
    # Assert each new agent is scheduled only once
    assert set(log_counter._next_check_times.keys()) == {"agent1", "agent2"}

@patch("log_monitor.LogCounter._LogCounter__log")
@patch("log_monitor.LogCounter._LogCounter__schedule_agent")
def test_refresh_agent_heap_schedule_failure(mock_schedule_agent, mock_log, log_counter):
    """Test refreshing agent heap when scheduling a new agent fails."""
    # Setup initial state
    now = datetime.now()
    log_counter._agent_heap = [(now, "agent1")]
    log_counter._next_check_times = {"agent1": now}
    
    # Mock schedule_agent to raise an exception
    mock_schedule_agent.side_effect = Exception("Scheduling failed")
    
    # Execute
    with pytest.raises(Exception):
        log_counter._LogCounter__refresh_agent_heap(["agent1", "agent2"])
    
    # Assert agent1 is still present but agent2 was not added
    assert "agent1" in log_counter._next_check_times
    assert "agent2" not in log_counter._next_check_times
    mock_schedule_agent.assert_called_once_with("agent2", 0)

@patch("log_monitor.LogCounter._LogCounter__log")
@patch("log_monitor.LogCounter._LogCounter__schedule_agent")
def test_refresh_agent_heap_with_special_chars(mock_schedule_agent, mock_log, log_counter):
    """Test refreshing agent heap with agent IDs containing special characters."""
    # Setup initial state
    now = datetime.now()
    log_counter._agent_heap = [(now, "normal-agent")]
    log_counter._next_check_times = {"normal-agent": now}
    
    # List with agent IDs containing special characters
    agent_ids = ["normal-agent", "agent@with#special$chars", "agent with spaces"]
    
    # Execute
    log_counter._LogCounter__refresh_agent_heap(agent_ids)
    
    # Assert all agents were handled correctly
    assert mock_schedule_agent.call_count == 2
    mock_schedule_agent.assert_has_calls([
        call("agent@with#special$chars", 0),
        call("agent with spaces", 0)
    ], any_order=True)
    mock_log.assert_called_once()

@patch("log_monitor.LogCounter._LogCounter__log")
def test_refresh_agent_heap_case_sensitivity(mock_log, log_counter):
    """Test that agent heap refresh is case-sensitive with agent IDs."""
    # Setup initial state with lowercase agent IDs
    now = datetime.now()
    log_counter._agent_heap = [(now, "agent1"), (now, "agent2")]
    log_counter._next_check_times = {"agent1": now, "agent2": now}
    
    # New list with some uppercase agent IDs
    new_agent_ids = ["AGENT1", "agent2", "agent3"]
    
    # Execute
    log_counter._LogCounter__refresh_agent_heap(new_agent_ids)
    
    # Assert case-sensitive behavior
    assert "agent1" not in log_counter._next_check_times
    assert "AGENT1" in log_counter._next_check_times
    assert "agent2" in log_counter._next_check_times
    assert "agent3" in log_counter._next_check_times

# Tests for __check_agent_logs
@patch("log_monitor.LogCounter._LogCounter__log")
@patch("log_monitor.LogCounter._LogCounter__setup_query")
@patch("log_monitor.LogCounter._LogCounter__notify_channels")
def test_check_agent_logs_success(mock_notify, mock_setup_query, mock_log, log_counter):
    mock_setup_query.return_value = {"query": "test"}
    log_counter._apiHandler = MagicMock()
    log_counter._apiHandler.get.return_value.status_code = 200
    log_counter._apiHandler.get.return_value.json.return_value = {"count": 1}
    
    log_counter._LogCounter__check_agent_logs("agent1", "001", 600)
    
    log_counter._apiHandler.get.assert_called_once_with({"query": "test"})
    mock_notify.assert_not_called()
    mock_log.assert_called()

@patch("log_monitor.LogCounter._LogCounter__log")
@patch("log_monitor.LogCounter._LogCounter__setup_query")
@patch("log_monitor.LogCounter._LogCounter__notify_channels")
def test_check_agent_logs_no_logs(mock_notify, mock_setup_query, mock_log, log_counter):
    mock_setup_query.return_value = {"query": "test"}
    log_counter._apiHandler = MagicMock()
    log_counter._apiHandler.get.return_value.status_code = 200
    log_counter._apiHandler.get.return_value.json.return_value = {"count": 0}

    log_counter._LogCounter__check_agent_logs("agent1", "001", 600)
    
    mock_notify.assert_called_once()
    mock_log.assert_called()

@patch("log_monitor.LogCounter._LogCounter__log")
@patch("log_monitor.LogCounter._LogCounter__setup_query")
@patch("log_monitor.LogCounter._LogCounter__notify_channels")
def test_check_agent_logs_request_exception(mock_notify, mock_setup_query, mock_log, log_counter):
    mock_setup_query.return_value = {"query": "test"}
    log_counter._apiHandler = MagicMock()
    log_counter._apiHandler.get.side_effect = requests.exceptions.RequestException("Connection error")
    
    log_counter._LogCounter__check_agent_logs("agent1", "001", 600)
    
    mock_notify.assert_called_once()
    mock_log.assert_called()

@patch("log_monitor.LogCounter._LogCounter__log")
@patch("log_monitor.LogCounter._LogCounter__setup_query")
@patch("log_monitor.LogCounter._LogCounter__notify_channels")
def test_check_agent_logs_status_error(mock_notify, mock_setup_query, mock_log, log_counter):
    """Test handling of non-200 status codes from the API."""
    # Setup
    mock_setup_query.return_value = {"query": "test"}
    log_counter._apiHandler = MagicMock()
    
    # Create a response mock with status_code 403 and text 'Forbidden'
    mock_response = MagicMock()
    mock_response.status_code = 403
    mock_response.text = "Forbidden"
    log_counter._apiHandler.get.return_value = mock_response
    
    # Execute
    log_counter._LogCounter__check_agent_logs("agent1", "001", 600)
    
    # Assert
    expected_error_msg = "Failed to query agent agent1 [001]; response code: 403, full response: Forbidden"
    
    # Check that the error was logged
    mock_log.assert_any_call(expected_error_msg, LOGGING_CATEGORY.ERROR)
    
    # Check that notification channels were informed
    mock_notify.assert_called_once_with(expected_error_msg)

@patch("log_monitor.LogCounter._LogCounter__log")
@patch("log_monitor.LogCounter._LogCounter__setup_query")
@patch("log_monitor.LogCounter._LogCounter__notify_channels")
def test_check_agent_logs_unexpected_exception(mock_notify, mock_setup_query, mock_log, log_counter):
    """Test handling of unexpected exceptions during API call."""
    # Setup
    mock_setup_query.return_value = {"query": "test"}
    log_counter._apiHandler = MagicMock()
    log_counter._apiHandler.get.side_effect = ValueError("Unexpected error")
    
    # Execute
    log_counter._LogCounter__check_agent_logs("agent1", "001", 600)
    
    # Assert
    expected_error_msg = "Unexpected error while sending query request for agent agent1 [001]: ValueError('Unexpected error')"
    
    # Check that the error was logged
    mock_log.assert_any_call(expected_error_msg, LOGGING_CATEGORY.ERROR)
    
    # Check that notification channels were informed
    mock_notify.assert_called_once_with(expected_error_msg)

@patch("log_monitor.LogCounter._LogCounter__setup_query")
@patch("log_monitor.LogCounter._LogCounter__log")
@patch("log_monitor.LogCounter._LogCounter__notify_channels")
@patch("log_monitor.datetime")
def test_check_agent_logs_first_time_no_logs(mock_datetime, mock_notify, mock_log, mock_setup_query, log_counter):
    """Test first notification when an agent has no logs."""
    # Setup
    now = datetime(2025, 1, 1, 12, 0, 0)
    mock_datetime.now.return_value = now
    
    mock_setup_query.return_value = {"query": "test"}
    log_counter._apiHandler = MagicMock()
    log_counter._apiHandler.get.return_value.status_code = 200
    log_counter._apiHandler.get.return_value.json.return_value = {"count": 0}
    log_counter._non_active_agents = {}
    
    # Execute
    log_counter._LogCounter__check_agent_logs("TestAgent", "001", 600)
    
    # Assert
    expected_msg = "Agent: TestAgent [001] hasn't received any logs in 10.0 minutes."
    mock_log.assert_any_call(expected_msg, LOGGING_CATEGORY.WARNING)
    mock_notify.assert_called_once_with(expected_msg)
    
    # Check the non-active agents tracking is updated correctly
    assert "001" in log_counter._non_active_agents
    assert log_counter._non_active_agents["001"][0] == now
    assert log_counter._non_active_agents["001"][1] == 1

@patch("log_monitor.LogCounter._LogCounter__setup_query")
@patch("log_monitor.LogCounter._LogCounter__log")
@patch("log_monitor.LogCounter._LogCounter__notify_channels")
@patch("log_monitor.datetime")
def test_check_agent_logs_repeated_no_logs_before_wait_time(mock_datetime, mock_notify, mock_log, mock_setup_query, log_counter):
    """Test no repeated notification when wait time hasn't elapsed."""
    # Setup
    first_check = datetime(2025, 1, 1, 12, 0, 0)
    second_check = datetime(2025, 1, 1, 12, 5, 0)  # 5 minutes later (less than wait time)
    mock_datetime.now.return_value = second_check
    
    mock_setup_query.return_value = {"query": "test"}
    log_counter._apiHandler = MagicMock()
    log_counter._apiHandler.get.return_value.status_code = 200
    log_counter._apiHandler.get.return_value.json.return_value = {"count": 0}
    
    # Agent was already notified once
    log_counter._non_active_agents = {"001": [first_check, 1]}
    
    # Execute
    log_counter._LogCounter__check_agent_logs("TestAgent", "001", 301)
    
    # Assert - notification should not be sent again
    mock_notify.assert_not_called()
    
    # Check that _non_active_agents wasn't updated
    assert log_counter._non_active_agents["001"][0] == first_check
    assert log_counter._non_active_agents["001"][1] == 1

@patch("log_monitor.LogCounter._LogCounter__setup_query")
@patch("log_monitor.LogCounter._LogCounter__log")
@patch("log_monitor.LogCounter._LogCounter__notify_channels")
@patch("log_monitor.datetime")
def test_check_agent_logs_repeated_no_logs_after_wait_time(mock_datetime, mock_notify, mock_log, mock_setup_query, log_counter):
    """Test repeated notification when wait time has elapsed."""
    # Setup
    first_check = datetime(2025, 1, 1, 12, 0, 0)
    # Wait time is check_interval * noti_count = 10 * 1 = 10 minutes
    second_check = datetime(2025, 1, 1, 12, 11, 0)  # 11 minutes later (> wait time)
    mock_datetime.now.side_effect = [second_check]
    
    mock_setup_query.return_value = {"query": "test"}
    log_counter._apiHandler = MagicMock()
    log_counter._apiHandler.get.return_value.status_code = 200
    log_counter._apiHandler.get.return_value.json.return_value = {"count": 0}
    
    # Agent was already notified once
    log_counter._non_active_agents = {"001": [first_check, 1]}
    
    # Execute
    log_counter._LogCounter__check_agent_logs("TestAgent", "001", 10)
    
    # Assert
    expected_msg = "Agent: TestAgent [001] still hasn't received any logs."
    mock_log.assert_any_call(expected_msg, LOGGING_CATEGORY.WARNING)
    mock_notify.assert_called_once_with(expected_msg)
    
    # Check the non-active agents tracking is updated correctly
    assert log_counter._non_active_agents["001"][0] == second_check
    assert log_counter._non_active_agents["001"][1] == 2

@patch("log_monitor.LogCounter._LogCounter__setup_query")
@patch("log_monitor.LogCounter._LogCounter__log")
@patch("log_monitor.LogCounter._LogCounter__notify_channels")
@patch("log_monitor.datetime")
def test_check_agent_logs_recovery_after_no_logs(mock_datetime, mock_notify, mock_log, mock_setup_query, log_counter):
    """Test notification when an agent starts receiving logs again."""
    # Setup
    now = datetime(2025, 1, 1, 12, 0, 0)
    mock_datetime.now.return_value = now
    
    mock_setup_query.return_value = {"query": "test"}
    log_counter._apiHandler = MagicMock()
    log_counter._apiHandler.get.return_value.status_code = 200
    log_counter._apiHandler.get.return_value.json.return_value = {"count": 10}
    
    # Agent was previously not receiving logs
    log_counter._non_active_agents = {"001": [datetime(2025, 1, 1, 11, 0, 0), 2]}
    
    # Execute
    log_counter._LogCounter__check_agent_logs("TestAgent", "001", 10)
    
    # Assert
    expected_msg = "Agent: TestAgent [001] has started receiving logs again."
    mock_log.assert_any_call(expected_msg, LOGGING_CATEGORY.INFO)
    mock_notify.assert_called_once_with(expected_msg)
    
    # Check the agent was removed from _non_active_agents
    assert "001" not in log_counter._non_active_agents

@patch("log_monitor.LogCounter._LogCounter__setup_query")
@patch("log_monitor.LogCounter._LogCounter__log")
@patch("log_monitor.LogCounter._LogCounter__notify_channels")
@patch("log_monitor.datetime")
def test_check_agent_logs_already_active(mock_datetime, mock_notify, mock_log, mock_setup_query, log_counter):
    """Test no notification for already active agents."""
    # Setup
    now = datetime(2025, 1, 1, 12, 0, 0)
    mock_datetime.now.return_value = now
    
    mock_setup_query.return_value = {"query": "test"}
    log_counter._apiHandler = MagicMock()
    log_counter._apiHandler.get.return_value.status_code = 200
    log_counter._apiHandler.get.return_value.json.return_value = {"count": 10}
    
    # Agent was not previously tracked as inactive
    log_counter._non_active_agents = {}
    
    # Execute
    log_counter._LogCounter__check_agent_logs("TestAgent", "001", 900)
    
    # Assert - should log but not notify
    expected_msg = "Agent: TestAgent [001] has received 10 logs in the last 15.0 minutes."
    mock_log.assert_any_call(expected_msg, LOGGING_CATEGORY.INFO)
    mock_notify.assert_not_called()
    
    # Check _non_active_agents remains empty
    assert "001" not in log_counter._non_active_agents

@patch("log_monitor.LogCounter._LogCounter__setup_query")
@patch("log_monitor.LogCounter._LogCounter__log")
@patch("log_monitor.LogCounter._LogCounter__notify_channels")
@patch("log_monitor.datetime")
def test_check_agent_logs_progressive_wait_times(mock_datetime, mock_notify, mock_log, mock_setup_query, log_counter):
    """Test progressive wait times for repeated notifications."""
    # Setup for first check
    first_check = datetime(2025, 1, 1, 12, 0, 0)
    mock_datetime.now.return_value = first_check
    
    mock_setup_query.return_value = {"query": "test"}
    log_counter._apiHandler = MagicMock()
    log_counter._apiHandler.get.return_value.status_code = 200
    log_counter._apiHandler.get.return_value.json.return_value = {"count": 0}
    
    log_counter._non_active_agents = {}
    
    # First check - should notify immediately
    log_counter._LogCounter__check_agent_logs("TestAgent", "001", 600)
    
    # Assert first notification
    expected_msg = "Agent: TestAgent [001] hasn't received any logs in 10.0 minutes."
    mock_log.assert_any_call(expected_msg, LOGGING_CATEGORY.WARNING)
    mock_notify.assert_called_once_with(expected_msg)
    assert log_counter._non_active_agents["001"][1] == 1
    
    # Reset mocks for second check
    mock_log.reset_mock()
    mock_notify.reset_mock()
    
    # Second check - after first wait time (10 minutes)
    second_check = first_check + timedelta(minutes=11)
    mock_datetime.now.return_value = second_check
    
    log_counter._LogCounter__check_agent_logs("TestAgent", "001", 600)
    
    # Assert second notification
    expected_msg = "Agent: TestAgent [001] still hasn't received any logs."
    mock_log.assert_any_call(expected_msg, LOGGING_CATEGORY.WARNING)
    mock_notify.assert_called_once_with(expected_msg)
    assert log_counter._non_active_agents["001"][1] == 2
    
    # Reset mocks for third check
    mock_log.reset_mock()
    mock_notify.reset_mock()
    
    # Third check - before second wait time (20 minutes)
    third_check = second_check + timedelta(minutes=15)
    mock_datetime.now.return_value = third_check
    
    log_counter._LogCounter__check_agent_logs("TestAgent", "001", 600)
    
    # Assert no notification (not enough time passed)
    mock_notify.assert_not_called()
    assert log_counter._non_active_agents["001"][1] == 2  # Count remains unchanged
    
    # Reset mocks for fourth check
    mock_log.reset_mock()
    mock_notify.reset_mock()
    
    # Fourth check - after second wait time (20 minutes)
    fourth_check = second_check + timedelta(minutes=21)
    mock_datetime.now.return_value = fourth_check
    
    log_counter._LogCounter__check_agent_logs("TestAgent", "001", 600)
    
    # Assert third notification
    expected_msg = "Agent: TestAgent [001] still hasn't received any logs."
    mock_log.assert_any_call(expected_msg, LOGGING_CATEGORY.WARNING)
    mock_notify.assert_called_once_with(expected_msg)
    assert log_counter._non_active_agents["001"][1] == 3

@patch("log_monitor.LogCounter._LogCounter__setup_query")
@patch("log_monitor.LogCounter._LogCounter__log")
@patch("log_monitor.LogCounter._LogCounter__notify_channels")
def test_check_agent_logs_with_multiple__non_active_agents(mock_notify, mock_log, mock_setup_query, log_counter):
    """Test handling multiple non-active agents."""
    # Setup
    mock_setup_query.return_value = {"query": "test"}
    log_counter._apiHandler = MagicMock()
    log_counter._apiHandler.get.return_value.status_code = 200
    
    # Setup multiple agents with different states
    now = datetime.now()
    log_counter._non_active_agents = {
        "001": [now - timedelta(minutes=30), 2],  # Previously notified twice
        "002": [now - timedelta(minutes=5), 1],   # Recently notified once
        "003": [now - timedelta(hours=2), 5]      # Notified multiple times long ago
    }
    
    # Test agent1 starts receiving logs
    log_counter._apiHandler.get.return_value.json.return_value = {"count": 5}
    log_counter._LogCounter__check_agent_logs("Agent1", "001", 10)
    
    # Assert
    expected_msg = "Agent: Agent1 [001] has started receiving logs again."
    mock_log.assert_any_call(expected_msg, LOGGING_CATEGORY.INFO)
    mock_notify.assert_called_once_with(expected_msg)
    
    # Verify only agent1 was removed from tracking
    assert "001" not in log_counter._non_active_agents
    assert "002" in log_counter._non_active_agents
    assert "003" in log_counter._non_active_agents

@patch("log_monitor.LogCounter._LogCounter__setup_query")
@patch("log_monitor.LogCounter._LogCounter__log")
@patch("log_monitor.LogCounter._LogCounter__notify_channels")
@patch("log_monitor.datetime")
def test_check_agent_logs_no_logs_long_interval(mock_datetime, mock_notify, mock_log, mock_setup_query, log_counter):
    """Test notification for no logs with a very long check interval."""
    # Setup
    now = datetime(2025, 1, 1, 12, 0, 0)
    mock_datetime.now.return_value = now
    
    mock_setup_query.return_value = {"query": "test"}
    log_counter._apiHandler = MagicMock()
    log_counter._apiHandler.get.return_value.status_code = 200
    log_counter._apiHandler.get.return_value.json.return_value = {"count": 0}
    log_counter._non_active_agents = {}
    
    # Execute with a very long interval (24 hours)
    long_interval = 1440  # minutes (24 hours)
    log_counter._LogCounter__check_agent_logs("TestAgent", "001", long_interval)
    
    # Assert
    expected_msg = f"Agent: TestAgent [001] hasn't received any logs in {long_interval / 60} minutes."
    mock_log.assert_any_call(expected_msg, LOGGING_CATEGORY.WARNING)
    mock_notify.assert_called_once_with(expected_msg)

@patch("log_monitor.LogCounter._LogCounter__setup_query")
@patch("log_monitor.LogCounter._LogCounter__log")
@patch("log_monitor.LogCounter._LogCounter__notify_channels")
@patch("log_monitor.datetime")
def test_check_agent_logs_high_notification_count(mock_datetime, mock_notify, mock_log, mock_setup_query, log_counter):
    """Test behavior with a high notification count (long wait times)."""
    # Setup
    now = datetime(2025, 1, 1, 12, 0, 0)
    mock_datetime.now.return_value = now
    
    mock_setup_query.return_value = {"query": "test"}
    log_counter._apiHandler = MagicMock()
    log_counter._apiHandler.get.return_value.status_code = 200
    log_counter._apiHandler.get.return_value.json.return_value = {"count": 0}
    
    # Agent that has been notified many times
    previous_time = now - timedelta(days=10)
    log_counter._non_active_agents = {"001": [previous_time, 10]}
    
    # Execute
    check_interval = 30  # 30 minutes
    log_counter._LogCounter__check_agent_logs("TestAgent", "001", check_interval)
    
    # Assert - wait time would be 30 * 10 = 300 minutes (5 hours)
    # Since 10 days > 5 hours, notification should happen
    expected_msg = "Agent: TestAgent [001] still hasn't received any logs."
    mock_log.assert_any_call(expected_msg, LOGGING_CATEGORY.WARNING)
    mock_notify.assert_called_once_with(expected_msg)
    
    # Check the notification count increased
    assert log_counter._non_active_agents["001"][1] == 11

@patch("log_monitor.LogCounter._LogCounter__setup_query")
@patch("log_monitor.LogCounter._LogCounter__log")
@patch("log_monitor.LogCounter._LogCounter__notify_channels")
@patch("log_monitor.datetime")
def test_check_agent_logs_json_parse_error(mock_datetime, mock_notify, mock_log, mock_setup_query, log_counter):
    """Test handling of JSON parse errors in response."""
    # Setup
    now = datetime(2025, 1, 1, 12, 0, 0)
    mock_datetime.now.return_value = now
    
    mock_setup_query.return_value = {"query": "test"}
    log_counter._apiHandler = MagicMock()
    log_counter._apiHandler.get.return_value.status_code = 200
    log_counter._apiHandler.get.return_value.json.side_effect = ValueError("Invalid JSON")
    
    # Execute
    log_counter._LogCounter__check_agent_logs("TestAgent", "001", 10)
    
    # Assert
    expected_msg = "Unexpected error while sending query request for agent TestAgent [001]: ValueError('Invalid JSON')"
    mock_log.assert_any_call(expected_msg, LOGGING_CATEGORY.ERROR)
    mock_notify.assert_called_once_with(expected_msg)

# Tests for __schedule_agent
@patch("log_monitor.LogCounter._LogCounter__log")
def test_schedule_agent(mock_log, log_counter):
    before_time = datetime.now()
    log_counter._agent_heap = []
    log_counter._next_check_times = {}
    
    log_counter._LogCounter__schedule_agent("agent1", 600)
    
    assert "agent1" in log_counter._next_check_times
    assert log_counter._next_check_times["agent1"] > before_time
    assert len(log_counter._agent_heap) == 1
    mock_log.assert_called_once()

@patch("log_monitor.LogCounter._LogCounter__log")
def test_schedule_agent_invalid_interval(mock_log, log_counter):
    log_counter._agent_heap = []
    log_counter._next_check_times = {}
    
    log_counter._LogCounter__schedule_agent("agent1", -1)
    
    assert "agent1" not in log_counter._next_check_times
    mock_log.assert_called()

# Tests for __start_log_counter
@patch("log_monitor.LogCounter._LogCounter__refresh_agent_heap")
@patch("log_monitor.LogCounter._LogCounter__check_agent_logs")
@patch("log_monitor.LogCounter._LogCounter__schedule_agent")
@patch("log_monitor.datetime")
@patch("time.sleep")
def test_start_log_counter(mock_sleep, mock_datetime, mock_schedule, mock_check_logs, mock_refresh, log_counter):
    mock_datetime.now.side_effect = [
        datetime(2025, 1, 1, 12, 0, 0),
        datetime(2025, 1, 1, 12, 0, 31),
        datetime(2025, 1, 1, 13, 0, 1)
    ]
    log_counter._agent_heap = [(datetime(2025, 1, 1, 12, 0, 30), "001")]
    log_counter._next_check_times = {"001": datetime(2025, 1, 1, 12, 0, 30)}
    
    log_counter._LogCounter__start_log_counter(600, {"001": 300}, {"001": "agent1"})
    
    mock_refresh.assert_called_once()
    mock_check_logs.assert_called_once_with("agent1", "001", 300)
    mock_schedule.assert_called_once_with("001", 300)
    mock_sleep.assert_called()

@patch("log_monitor.LogCounter._LogCounter__refresh_agent_heap")
@patch("log_monitor.LogCounter._LogCounter__check_agent_logs")
@patch("log_monitor.LogCounter._LogCounter__schedule_agent")
@patch("log_monitor.datetime")
@patch("time.sleep")
def test_start_log_counter_ignores_outdated_schedules(mock_sleep, mock_datetime, mock_schedule, mock_check_logs, mock_refresh, log_counter):
    """Test that the scheduler ignores agents whose scheduled times have been updated."""
    # Setup
    mock_datetime.now.side_effect = [
        datetime(2025, 1, 1, 12, 0, 0),  # Initial time
        datetime(2025, 1, 1, 12, 0, 30),   # Time when checking the heap
        datetime(2025, 1, 1, 13, 0, 1)   # Time when checking the heap
    ]
    
    # Initial heap with one scheduled check
    original_time = datetime(2025, 1, 1, 12, 0, 30)
    log_counter._agent_heap = [(original_time, "001")]
    
    # But the agent's actual scheduled time has been updated
    updated_time = datetime(2025, 1, 1, 12, 1, 0)  # Different from the one in the heap
    log_counter._next_check_times = {"001": updated_time}
    
    log_counter._LogCounter__start_log_counter(600, {"001": 300}, {"001": "agent1"})
    
    
    # Assert - check_logs should not be called since the scheduled time was outdated
    mock_refresh.assert_called_once()
    mock_check_logs.assert_not_called()
    mock_schedule.assert_not_called()
    mock_sleep.assert_has_calls([call(5)])

@patch("log_monitor.LogCounter._LogCounter__refresh_agent_heap")
@patch("log_monitor.LogCounter._LogCounter__check_agent_logs")
@patch("log_monitor.LogCounter._LogCounter__schedule_agent")
@patch("log_monitor.datetime")
@patch("time.sleep")
def test_start_log_counter_high_agent_volume(mock_sleep, mock_datetime, mock_schedule, mock_check_logs, mock_refresh, log_counter):
    """Test log counter handling a large number of agents all scheduled close together."""
    # Setup
    start_time = datetime(2025, 1, 1, 12, 0, 0)
    mock_datetime.now.side_effect = [
        start_time,  # Initial time
        datetime(2025, 1, 1, 12, 0, 1),  # First check time
        datetime(2025, 1, 1, 13, 0, 1)   # Termination time
    ]
    
    # Set up 100 agents all scheduled within 1 second of each other
    log_counter._agent_heap = []
    log_counter._next_check_times = {}
    agents = {}
    for i in range(100):
        agent_id = f"agent{i}"
        scheduled_time = datetime(2025, 1, 1, 12, 0, 0) + timedelta(milliseconds=i*10)
        agents[i] = agent_id
        log_counter._next_check_times[i] = scheduled_time
        log_counter._agent_heap.append((scheduled_time, i))
    
    heapq.heapify(log_counter._agent_heap)
    
    # Agent intervals - vary between 60 and 900 seconds
    agent_intervals = {f"agent{i}": 60 + (i % 15) * 60 for i in range(100)}
    
    # Execute
    log_counter._LogCounter__start_log_counter(
        600,           # default check interval
        agent_intervals,  # agent check intervals
        agents           # agent ids
    )
    
    # Assert
    mock_refresh.assert_called_once()
    assert mock_check_logs.call_count == 100, f"Expected 100 agent checks, got {mock_check_logs.call_count}"
    assert mock_schedule.call_count == 100, f"Expected 100 agent schedules, got {mock_schedule.call_count}"
    # Verify it slept after processing all agents
    mock_sleep.assert_called()

@patch("log_monitor.LogCounter._LogCounter__refresh_agent_heap")
@patch("log_monitor.LogCounter._LogCounter__check_agent_logs")
@patch("log_monitor.LogCounter._LogCounter__schedule_agent")
@patch("log_monitor.datetime")
@patch("time.sleep")
def test_start_log_counter_with_clock_jump_forward(mock_sleep, mock_datetime, mock_schedule, mock_check_logs, mock_refresh, log_counter):
    """Test log counter behavior when system time jumps forward (e.g., daylight saving changes)."""
    # Setup - simulate a significant time jump forward
    mock_datetime.now.side_effect = [
        datetime(2025, 3, 29, 1, 59, 0),    # Initial time
        datetime(2025, 3, 29, 3, 0, 0),     # Time jumped forward by 1 hour (DST change)
        datetime(2025, 3, 29, 3, 59, 1)     # Termination check
    ]
    
    # Agents scheduled before the time jump
    log_counter._agent_heap = [
        (datetime(2025, 3, 29, 2, 15, 0), "001"),  # This would be "skipped" due to time jump
        (datetime(2025, 3, 29, 2, 30, 0), "002"),  # This would be "skipped" due to time jump
        (datetime(2025, 3, 29, 3, 15, 0), "003")   # This would be processed normally
    ]
    log_counter._next_check_times = {
        "001": datetime(2025, 3, 29, 2, 15, 0),
        "002": datetime(2025, 3, 29, 2, 30, 0),
        "003": datetime(2025, 3, 29, 3, 15, 0)
    }
    
    # Execute
    log_counter._LogCounter__start_log_counter(
        600,  # default check interval
        {"001": 300, "001": 300, "003": 300},  # agent check intervals
        {"001": "agent1", "002": "agent2", "003":"agent3"}  # agent ids
    )
    
    # Assert - all agents scheduled before current time should be checked
    mock_refresh.assert_called_once()
    assert mock_check_logs.call_count == 0
    assert mock_schedule.call_count == 0

@patch("log_monitor.LogCounter._LogCounter__refresh_agent_heap")
@patch("log_monitor.LogCounter._LogCounter__check_agent_logs")
@patch("log_monitor.LogCounter._LogCounter__schedule_agent")
@patch("log_monitor.datetime")
@patch("time.sleep")
def test_start_log_counter_with_clock_jump_backward(mock_sleep, mock_datetime, mock_schedule, mock_check_logs, mock_refresh, log_counter):
    """Test log counter behavior when system time jumps backward (e.g., daylight saving ends)."""
    # Setup - simulate a time jump backward
    mock_datetime.now.side_effect = [
        datetime(2025, 10, 25, 2, 59, 0),   # Initial time
        datetime(2025, 10, 25, 2, 0, 0),    # Time jumped backward by 1 hour (DST end)
        datetime(2025, 10, 25, 2, 15, 0),
        datetime(2025, 10, 25, 2, 30, 0),   
        datetime(2025, 10, 25, 4, 0, 1)     # Termination check
    ]
    
    # Agents scheduled before and after the time jump
    log_counter._agent_heap = [
        (datetime(2025, 10, 25, 2, 15, 0), "001"),  # After time jump, this appears in the future again
        (datetime(2025, 10, 25, 2, 30, 0), "002")   # After time jump, this appears in the future again
    ]
    log_counter._next_check_times = {
        "001": datetime(2025, 10, 25, 2, 15, 0),
        "002": datetime(2025, 10, 25, 2, 30, 0)
    }
    
    # Execute
    log_counter._LogCounter__start_log_counter(
        600,  # default check interval
        {"001": 300, "002": 300},  # agent check intervals
        {"001": "agent1", "002": "agent2"}  # agent ids
    )
    
    # Assert - no agents should be checked since they now appear to be in the future
    mock_refresh.assert_called_once()
    assert mock_check_logs.call_count == 2
    mock_check_logs.assert_has_calls([
        call("agent1","001", 300),
        call("agent2","002", 300),
    ], any_order=True)
    assert mock_schedule.call_count == 2
    mock_sleep.assert_called()

@patch("log_monitor.LogCounter._LogCounter__refresh_agent_heap")
@patch("log_monitor.LogCounter._LogCounter__check_agent_logs")
@patch("log_monitor.LogCounter._LogCounter__schedule_agent")
@patch("log_monitor.datetime")
@patch("time.sleep")
def test_start_log_counter_staggered_scheduling(mock_sleep, mock_datetime, mock_schedule, mock_check_logs, mock_refresh, log_counter):
    """Test log counter with staggered agent schedules to avoid processing peaks."""
    # Setup - time sequence that allows processing agents in batches
    mock_datetime.now.side_effect = [
        datetime(2025, 1, 1, 12, 0, 0),   # Initial time
        datetime(2025, 1, 1, 12, 0, 30),  # First batch time
        datetime(2025, 1, 1, 12, 1, 0),   # Second batch time
        datetime(2025, 1, 1, 12, 1, 30),  # Third batch time
        datetime(2025, 1, 1, 12, 2, 0),   # Fourth batch time
        datetime(2025, 1, 1, 13, 0, 1)    # Termination time
    ]
    
    log_counter._agent_heap = []
    log_counter._next_check_times = {}
    agents = {}
    agent_intervals = {}

    # Assign agents to staggered batches
    stagger_times = [
        datetime(2025, 1, 1, 12, 0, 30),
        datetime(2025, 1, 1, 12, 1, 0),
        datetime(2025, 1, 1, 12, 1, 30),
        datetime(2025, 1, 1, 12, 2, 0),
    ]

    agent_index = 1
    for stagger_time in stagger_times:
        for _ in range(10):
            agent_id = str(agent_index)  # e.g., "1", "2", ..., "40"
            agents[agent_id] = f"label{agent_index}"
            log_counter._agent_heap.append((stagger_time, agent_id))
            log_counter._next_check_times[agent_id] = stagger_time
            agent_intervals[agent_id] = 300  # 5-minute interval
            agent_index += 1

    heapq.heapify(log_counter._agent_heap)

    # Execute
    log_counter._LogCounter__start_log_counter(
        default_check_interval=600,  # 10 minutes
        agent_check_intervals=agent_intervals,
        agents=agents
    )

    # Assert
    mock_refresh.assert_called_once()
    assert mock_check_logs.call_count == 40, f"Expected 40 agent checks, got {mock_check_logs.call_count}"
    assert mock_schedule.call_count == 40, f"Expected 40 agent schedules, got {mock_schedule.call_count}"
    assert mock_sleep.call_count >= 4, f"Expected at least 4 sleep calls, got {mock_sleep.call_count}"

@patch("log_monitor.LogCounter._LogCounter__refresh_agent_heap")
@patch("log_monitor.LogCounter._LogCounter__check_agent_logs")
@patch("log_monitor.LogCounter._LogCounter__schedule_agent")
@patch("log_monitor.datetime")
@patch("time.sleep")
def test_start_log_counter_with_dynamic_agent_changes(mock_sleep, mock_datetime, mock_schedule, mock_check_logs, mock_refresh, log_counter):
    """Test log counter with dynamic changes to agent list between iterations."""
    
    # Create a sequence that allows for multiple iterations
    mock_datetime.now.side_effect = [
        # First iteration
        datetime(2025, 1, 1, 12, 0, 0),   # Start time
        datetime(2025, 1, 1, 12, 0, 1),   # Initial time
        datetime(2025, 1, 1, 12, 0, 30),  # First check time
        datetime(2025, 1, 1, 13, 0, 1),   # Termination time for first run
        
        # Second iteration
        datetime(2025, 1, 1, 13, 0, 0),   # Start time again
        datetime(2025, 1, 1, 13, 0, 2),   # Initial time for second run
        datetime(2025, 1, 1, 13, 0, 30),  # First check time for second run
        datetime(2025, 1, 1, 14, 0, 1)    # Termination time for second run
    ]
    
    # Initial state with 3 agents for the first run
    log_counter._agent_heap = [
        (datetime(2025, 1, 1, 12, 0, 30), "001"),
        (datetime(2025, 1, 1, 12, 0, 30), "002"),
        (datetime(2025, 1, 1, 12, 0, 30), "003")
    ]
    log_counter._next_check_times = {
        "001": datetime(2025, 1, 1, 12, 0, 30),
        "002": datetime(2025, 1, 1, 12, 0, 30),
        "003": datetime(2025, 1, 1, 12, 0, 30)
    }
    
    # Define agent intervals
    agent_intervals = {"001": 300, "002": 300, "003": 300, "004": 300}
    
    # First iteration: 3 agents
    initial_agent_ids = {"001" : "agent1", "002": "agent2", "003": "agent3"}
    
    # Second iteration: different agent list (agent2 removed, agent4 added)
    updated_agent_ids = {"001" : "agent1", "002": "agent2", "004": "agent4"}
    
    # Mock schedule_agent to avoid actually modifying the heap during the test
    original_schedule_agent = log_counter._LogCounter__schedule_agent
    
    # Execute the first run with initial agent list
    log_counter._LogCounter__start_log_counter(
        600,  # default check interval
        agent_intervals,  # agent check intervals
        initial_agent_ids  # initial agent ids
    )
    
    # Verify first run processed the initial agents
    mock_refresh.assert_called_once_with(initial_agent_ids.keys())
    assert mock_check_logs.call_count == 3
    mock_check_logs.assert_any_call("agent1", "001", 300)
    mock_check_logs.assert_any_call("agent2", "002", 300)
    mock_check_logs.assert_any_call("agent3", "003", 300)
    
    # Reset mocks and set up for second run
    mock_refresh.reset_mock()
    mock_check_logs.reset_mock()
    mock_schedule.reset_mock()
    
    # Update agent heap for second run
    log_counter._agent_heap = [
        (datetime(2025, 1, 1, 13, 0, 30), "001"),
        (datetime(2025, 1, 1, 13, 0, 30), "002"),
        (datetime(2025, 1, 1, 13, 0, 30), "004")
    ]
    log_counter._next_check_times = {
        "001": datetime(2025, 1, 1, 13, 0, 30),
        "002": datetime(2025, 1, 1, 13, 0, 30),
        "004": datetime(2025, 1, 1, 13, 0, 30)
    }
    
    # Execute the second run with updated agent list
    log_counter._LogCounter__start_log_counter(
        600,  # default check interval
        agent_intervals,  # agent check intervals
        updated_agent_ids  # updated agent ids
    )
    
    # Assert second run
    mock_refresh.assert_called_once_with(updated_agent_ids.keys())
    assert mock_check_logs.call_count == 3
    mock_check_logs.assert_any_call("agent1", "001", 300)
    mock_check_logs.assert_any_call("agent2", "002", 300)
    mock_check_logs.assert_any_call("agent4", "004", 300)
    assert mock_check_logs.call_count == 3
    
    # Ensure agent3 was not checked in the second run
    for call_args in mock_check_logs.call_args_list:
        assert "agent3" not in call_args[0][0], "agent3 should not be checked in second run"

@patch("log_monitor.LogCounter._LogCounter__refresh_agent_heap")
@patch("log_monitor.LogCounter._LogCounter__check_agent_logs")
@patch("log_monitor.LogCounter._LogCounter__schedule_agent")
@patch("log_monitor.datetime")
@patch("time.sleep")
def test_start_log_counter_with_similar_scheduled_agents(mock_sleep, mock_datetime, mock_schedule, mock_check_logs, mock_refresh, log_counter):
    """Test log counter with very similar but non-identical scheduled times."""
    # Setup
    mock_datetime.now.side_effect = [
        datetime(2025, 1, 1, 12, 0, 0), # Start time
        datetime(2025, 1, 1, 12, 0, 0),
        datetime(2025, 1, 1, 12, 0, 1),
        datetime(2025, 1, 1, 12, 0, 2),
        datetime(2025, 1, 1, 12, 0, 3),
        datetime(2025, 1, 1, 12, 0, 4),
        datetime(2025, 1, 1, 12, 0, 5),
        datetime(2025, 1, 1, 12, 0, 6),
        datetime(2025, 1, 1, 12, 0, 7),
        datetime(2025, 1, 1, 12, 0, 8),
        datetime(2025, 1, 1, 12, 0, 9),
        datetime(2025, 1, 1, 12, 0, 10),
        datetime(2025, 1, 1, 13, 0, 1),  # Termination time
    ]
    
    # Create 10 agents with very close but slightly different scheduled times
    # Will test if the heap ordering is maintained correctly
    log_counter._agent_heap = []
    log_counter._next_check_times = {}
    
    base_time = datetime(2025, 1, 1, 12, 0, 1)
    agents = {}
    for i in range(10):
        agents[i] = f"agent{i}"
        # Schedule each agent 1 millisecond apart
        scheduled_time = base_time + timedelta(milliseconds=i)
        log_counter._next_check_times[i] = scheduled_time
        log_counter._agent_heap.append((scheduled_time, i))
    
    heapq.heapify(log_counter._agent_heap)
    
    # All use the same interval
    agent_intervals = {i: 300 for i in range(10)}
    
    # Execute
    log_counter._LogCounter__start_log_counter(
        600,  # default check interval
        agent_intervals,  # agent check intervals
        agents  # agent ids
    )
    
    # Assert - should check all agents in correct order
    mock_refresh.assert_called_once()
    assert mock_check_logs.call_count == 10
    
    # Check they were processed in order
    expected_calls = [call(f"agent{i}", i, 300) for i in range(10)]
    mock_check_logs.assert_has_calls(expected_calls, any_order=False)
    
    # Check they were all scheduled
    assert mock_schedule.call_count == 10

@patch("log_monitor.LogCounter._LogCounter__refresh_agent_heap")
@patch("log_monitor.LogCounter._LogCounter__check_agent_logs")
@patch("log_monitor.LogCounter._LogCounter__schedule_agent")
@patch("log_monitor.datetime")
@patch("time.sleep")
def test_start_log_counter_resilience_to_sleep_interruptions(mock_sleep, mock_datetime, mock_schedule, mock_check_logs, mock_refresh, log_counter):
    """Test log counter resilience when sleep is interrupted."""
    
    # Set up a sequence where time advances differently than expected sleeps
    mock_datetime.now.side_effect = [
        datetime(2025, 1, 1, 12, 0, 0),   # Start time
        datetime(2025, 1, 1, 12, 0, 0),   # Initial time
        datetime(2025, 1, 1, 12, 0, 5),   # Advanced 5s (during 10s sleep)
        datetime(2025, 1, 1, 12, 0, 15),  # Advanced 10s (during 5s sleep)
        datetime(2025, 1, 1, 13, 0, 1)    # Termination time
    ]
    
    # Set up sleep to simulate interruptions
    mock_sleep.side_effect = [None, KeyboardInterrupt, None]
    
    # Set up agents with future scheduled times
    log_counter._agent_heap = [
        (datetime(2025, 1, 1, 12, 0, 10), "001"),  # 10s in future
        (datetime(2025, 1, 1, 12, 0, 20), "002")   # 20s in future
    ]
    log_counter._next_check_times = {
        "001": datetime(2025, 1, 1, 12, 0, 10),
        "002": datetime(2025, 1, 1, 12, 0, 20)
    }
    
    # Execute - should handle the sleep interruption gracefully
    with pytest.raises(KeyboardInterrupt):
        log_counter._LogCounter__start_log_counter(
            600,  # default check interval
            {"001": 300, "002": 300},  # agent check intervals
            {"001": "agent1", "002":"agent2"}  # agent ids
        )
    
    # Assert - should have attempted to sleep until next agent but got interrupted
    mock_refresh.assert_called_once()
    mock_sleep.assert_called_with(5)  # Should try to sleep until agent1's time
    assert mock_check_logs.call_count == 0  # No agents checked before interruption

@patch("log_monitor.LogCounter._LogCounter__refresh_agent_heap")
@patch("log_monitor.LogCounter._LogCounter__check_agent_logs")
@patch("log_monitor.LogCounter._LogCounter__schedule_agent")
@patch("log_monitor.datetime")
@patch("time.sleep")
def test_start_log_counter_with_varying_check_intervals(mock_sleep, mock_datetime, mock_schedule, mock_check_logs, mock_refresh, log_counter):
    """Test log counter with highly varying check intervals."""
    # Setup
    mock_datetime.now.side_effect = [
        datetime(2025, 1, 1, 12, 0, 0),  # Start time
        datetime(2025, 1, 1, 12, 0, 1),  # First check
        datetime(2025, 1, 1, 12, 0, 2),  # Second check
        datetime(2025, 1, 1, 12, 0, 3),  # Third check
        datetime(2025, 1, 1, 13, 0, 1)   # Termination time
    ]
    
    # Set up agents with scheduled times all at current time
    current_time = datetime(2025, 1, 1, 12, 0, 1)
    log_counter._agent_heap = [
        (current_time, "001"),  # Very short interval (5 seconds)
        (current_time, "002"),  # Medium interval (5 minutes)
        (current_time, "003")   # Very long interval (1 hour)
    ]
    log_counter._next_check_times = {
        "001": current_time,
        "002": current_time,
        "003": current_time
    }
    
    # Define highly varying intervals
    agent_intervals = {
        "001": 5,       # 5 seconds
        "002": 300,     # 5 minutes
        "003": 3600     # 1 hour
    }
    
    # Track reschedule times to verify correct intervals
    scheduled_times = {}
    
    def track_schedule(agent_id, interval):
        scheduled_times[agent_id] = interval
    
    mock_schedule.side_effect = track_schedule
    
    # Execute
    log_counter._LogCounter__start_log_counter(
        600,  # default check interval
        agent_intervals,  # agent check intervals
        {"001": "agent1", "002":"agent2", "003":"agent3"}  # agent ids
    )
    
    # Assert
    mock_refresh.assert_called_once()
    assert mock_check_logs.call_count == 3
    assert mock_schedule.call_count == 3
    
    # Verify each agent was rescheduled with its own interval
    assert scheduled_times["001"] == 5
    assert scheduled_times["002"] == 300
    assert scheduled_times["003"] == 3600

@patch("log_monitor.LogCounter._LogCounter__refresh_agent_heap")
@patch("log_monitor.LogCounter._LogCounter__check_agent_logs")
@patch("log_monitor.LogCounter._LogCounter__schedule_agent")
@patch("log_monitor.datetime")
@patch("time.sleep")
def test_start_log_counter_heap_auto_correction(mock_sleep, mock_datetime, mock_schedule, mock_check_logs, mock_refresh, log_counter):
    """Test log counter's ability to auto-correct heap inconsistencies."""
    # Setup - times are not in proper order, testing if heap property is maintained
    mock_datetime.now.side_effect = [
        datetime(2025, 1, 1, 12, 0, 0),  # Start time
        datetime(2025, 1, 1, 12, 0, 10),  # Check time
        datetime(2025, 1, 1, 13, 0, 1)    # Termination time
    ]
    
    # Deliberately set up an inconsistent heap (not sorted by time)
    log_counter._agent_heap = [
        (datetime(2025, 1, 1, 12, 0, 30), "003"),  # This should be last
        (datetime(2025, 1, 1, 12, 0, 10), "001"),  # This should be first
        (datetime(2025, 1, 1, 12, 0, 20), "002")   # This should be middle
    ]
    log_counter._next_check_times = {
        "001": datetime(2025, 1, 1, 12, 0, 10),
        "002": datetime(2025, 1, 1, 12, 0, 20),
        "003": datetime(2025, 1, 1, 12, 0, 30)
    }
    
    # Force a heapify to correct the heap
    heapq.heapify(log_counter._agent_heap)
    
    # Execute
    log_counter._LogCounter__start_log_counter(
        600,  # default check interval
        {"001": 300, "002": 300, "003": 300},  # agent check intervals
        {"001":"agent1", "002":"agent2", "003":"agent3"}  # agent ids
    )
    
    # Assert - should process agent1 first despite the original order
    mock_refresh.assert_called_once()
    first_check = mock_check_logs.call_args_list[0]
    assert first_check[0][0] == "agent1", f"Expected agent1 to be checked first, but got {first_check[0][0]}"

@patch("log_monitor.LogCounter._LogCounter__refresh_agent_heap")
@patch("log_monitor.LogCounter._LogCounter__check_agent_logs")
@patch("log_monitor.LogCounter._LogCounter__schedule_agent")
@patch("log_monitor.datetime")
@patch("time.sleep")
@patch("log_monitor.LogCounter._LogCounter__log")
def test_start_log_counter_error_resilience(mock_log, mock_sleep, mock_datetime, mock_schedule, mock_check_logs, mock_refresh, log_counter):
    """Test log counter resilience when check_agent_logs throws errors."""
    # Setup
    mock_datetime.now.side_effect = [
        datetime(2025, 1, 1, 12, 0, 0),  # Start time
        datetime(2025, 1, 1, 12, 0, 5),  # Check time
        datetime(2025, 1, 1, 13, 0, 1)   # Termination time
    ]
    
    # Set up agents all ready to be processed
    ready_time = datetime(2025, 1, 1, 12, 0, 0)
    log_counter._agent_heap = [
        (ready_time, "001"),  # Will succeed
        (ready_time, "002"),  # Will fail with exception
        (ready_time, "003")   # Should still be processed after agent2's error
    ]
    log_counter._next_check_times = {
        "001": ready_time,
        "002": ready_time,
        "003": ready_time
    }
    
    # Make agent2 fail during check
    def check_side_effect(agent_name, agent_id, interval):
        if agent_id == "002":
            raise ValueError("Test error for agent2")
    
    mock_check_logs.side_effect = check_side_effect
    
    # Execute - should continue processing despite agent2's error
    log_counter._LogCounter__start_log_counter(
        600,  # default check interval
        {"001": 300, "002": 300, "003": 300},  # agent check intervals
        {"001":"agent1", "002":"agent2", "003":"agent3"}  # agent ids
    )
    
    # Assert
    mock_refresh.assert_called_once()
    assert mock_check_logs.call_count == 3  # All agents should be attempted
    
    # agent1 and agent3 should be scheduled even though agent2 failed
    assert mock_schedule.call_count == 3
    mock_schedule.assert_any_call("001", 300)
    mock_schedule.assert_any_call("003", 300)
    
    # Error should be logged
    mock_log.assert_any_call("Failed to check logs for agent agent2 [002] with the following error: ValueError('Test error for agent2')", LOGGING_CATEGORY.ERROR)

@patch("log_monitor.LogCounter._LogCounter__refresh_agent_heap")
@patch("log_monitor.LogCounter._LogCounter__check_agent_logs")
@patch("log_monitor.LogCounter._LogCounter__schedule_agent")
@patch("log_monitor.datetime")
@patch("time.sleep")
def test_start_log_counter_with_time_skew_correction(mock_sleep, mock_datetime, mock_schedule, mock_check_logs, mock_refresh, log_counter):
    """Test log counter's ability to handle system time skews."""

    # Time sequence that goes backward briefly, then forward again
    mock_datetime.now.side_effect = [
        datetime(2025, 1, 1, 12, 0, 0),   # Start time
        datetime(2025, 1, 1, 12, 0, 0),   # Initial time
        datetime(2025, 1, 1, 12, 0, 10),  # First check - forward 10s
        datetime(2025, 1, 1, 12, 0, 5),   # Unexpected - backward 5s
        datetime(2025, 1, 1, 12, 0, 15),  # Forward again
        datetime(2025, 1, 1, 13, 0, 1)    # Termination time
    ]
    
    # Set up agents with scheduled times that will be affected by time skew
    log_counter._agent_heap = [
        (datetime(2025, 1, 1, 12, 0, 5), "001"),   # Before time skew
        (datetime(2025, 1, 1, 12, 0, 8), "002"),   # During skew backward
        (datetime(2025, 1, 1, 12, 0, 12), "003")   # After time skew recovery
    ]
    log_counter._next_check_times = {
        "001": datetime(2025, 1, 1, 12, 0, 5),
        "002": datetime(2025, 1, 1, 12, 0, 8),
        "003": datetime(2025, 1, 1, 12, 0, 12)
    }
    
    # Execute - should handle the time skew gracefully
    log_counter._LogCounter__start_log_counter(
        600,  # default check interval
        {"001": 300, "002": 300, "003": 300},  # agent check intervals
        {"001":"agent1", "002":"agent2", "003":"agent3"}  # agent ids
    )
    
    # Assert - all agents should eventually be processed despite time skew
    mock_refresh.assert_called_once()
    assert mock_check_logs.call_count == 3  # All agents should be processed
    assert mock_schedule.call_count == 3

# Tests for main
@patch("log_monitor.LogCounter._LogCounter__setup_env_handler")
@patch("log_monitor.LogCounter._LogCounter__setup_basics")
@patch("log_monitor.LogCounter._LogCounter__setup_wazuh_handler")
@patch("log_monitor.LogCounter._LogCounter__get_env_var")
@patch("log_monitor.LogCounter._LogCounter__load_agents")
@patch("log_monitor.LogCounter._LogCounter__getDCI")
@patch("log_monitor.LogCounter._LogCounter__load_agent_check_intervals")
@patch("log_monitor.LogCounter._LogCounter__start_log_counter")
@patch("log_monitor.datetime")
def test_main(mock_datetime, mock_start, mock_load_intervals, mock_get_dci, mock_load_ids, mock_get_env, mock_setup_wazuh, mock_setup_basics, mock_setup_env, log_counter):
    mock_get_env.return_value = "agent_list.txt"
    full_path = os.path.join(os.getcwd(), "agent_list.txt")
    agents = {"001":"agent1", "002":"agent2"}
    mock_load_ids.return_value = agents
    mock_get_dci.return_value = 600
    mock_load_intervals.return_value = {"001": 300}
    mock_datetime.now.return_value = datetime(2025, 1, 1, 12, 0, 0)
    mock_start.side_effect = KeyboardInterrupt()
    
    with pytest.raises(KeyboardInterrupt):
        log_counter.main()
    
    mock_setup_env.assert_called_once()
    mock_setup_basics.assert_called_once()
    mock_setup_wazuh.assert_called_once()
    mock_get_env.assert_called_with("AGENT_LIST_FILE", required=True)
    mock_load_ids.assert_called_once_with(full_path)
    mock_get_dci.assert_called_once()
    mock_load_intervals.assert_called_once_with(agents.keys())
    mock_start.assert_called_once_with(600, {"001": 300}, {"001":"agent1", "002":"agent2"})

@patch("log_monitor.LogCounter._LogCounter__setup_env_handler")
@patch("log_monitor.LogCounter._LogCounter__setup_basics")
@patch("log_monitor.LogCounter._LogCounter__setup_wazuh_handler")
@patch("log_monitor.LogCounter._LogCounter__get_env_var")
@patch("log_monitor.LogCounter._LogCounter__load_agents")
@patch("log_monitor.LogCounter._LogCounter__getDCI")
@patch("log_monitor.LogCounter._LogCounter__load_agent_check_intervals")
@patch("log_monitor.LogCounter._LogCounter__start_log_counter")
@patch("log_monitor.LogCounter._LogCounter__notify_channels")
@patch("log_monitor.LogCounter._LogCounter__log")
@patch("time.sleep")
@patch("log_monitor.datetime")
def test_main_with_empty_agent_list(mock_datetime, mock_sleep, mock_log, mock_notify, mock_start, 
                                    mock_load_intervals, mock_get_dci, mock_load_ids, mock_get_env, 
                                    mock_setup_wazuh, mock_setup_basics, mock_setup_env, log_counter):
    # Setup - simulate empty agent list
    mock_get_env.return_value = "agent_list.txt"
    agents = {"001":"agent1"}
    mock_load_ids.side_effect = [{}, agents]  # First empty, then with an agent on retry
    mock_get_dci.return_value = 600
    mock_load_intervals.return_value = {}
    mock_datetime.now.return_value = datetime(2025, 1, 1, 12, 0, 0)
    
    # Set up the side effect to exit after first sleep
    mock_start.side_effect = KeyboardInterrupt()
    
    # Execute - should raise KeyboardInterrupt after handling empty list
    with pytest.raises(KeyboardInterrupt):
        log_counter.main()
    
    # Assert - check proper setup and notification for empty list
    mock_setup_env.assert_called_once()
    mock_setup_basics.assert_called_once()
    mock_setup_wazuh.assert_called_once()
    mock_get_env.assert_called_with("AGENT_LIST_FILE", required=True)
    
    # Verify load_agent_ids was called twice (initial + retry)
    assert mock_load_ids.call_count == 2
    
    # Verify notification was sent about empty list
    expected_msg = "Agent list is empty. No agents to check. Sleeping for 1 hour to retry."
    mock_notify.assert_called_with(expected_msg)
    mock_log.call_count == 3 # Two for setup, once for empty list
    
    # Verify sleep was called with 3600 seconds (1 hour)
    mock_sleep.assert_called_with(3600)
    
    # Verify that after retry, normal process resumed
    mock_load_intervals.assert_called_once_with(agents.keys())

# Missing cases

# Edge Cases for Agent Heap Management
@patch("log_monitor.LogCounter._LogCounter__log")
def test_refresh_agent_heap_empty_list(mock_log, log_counter):
    """Test refreshing agent heap with an empty list of agents."""
    # Setup initial state with some agents
    log_counter._agent_heap = [(datetime.now(), "agent1"), (datetime.now(), "agent2")]
    log_counter._next_check_times = {"agent1": datetime.now(), "agent2": datetime.now()}
    
    # Execute with empty list
    log_counter._LogCounter__refresh_agent_heap([])
    
    # Assert all agents are removed
    assert len(log_counter._next_check_times) == 0
    mock_log.assert_called()

@patch("log_monitor.LogCounter._LogCounter__log")
def test_refresh_agent_heap_large_number_agents(mock_log, log_counter):
    """Test refreshing agent heap with a large number of agents."""
    # Create a large number of agents (performance test)
    initial_agents = [f"agent{i}" for i in range(1000)]
    log_counter._next_check_times = {agent: datetime.now() for agent in initial_agents}
    
    # Execute with a subset of agents
    new_agents = [f"agent{i}" for i in range(500, 1500)]  # 500 existing, 500 new
    
    log_counter._LogCounter__refresh_agent_heap(new_agents)
    
    # Assert correct agents remain
    assert len(log_counter._next_check_times) == 1000
    for i in range(500, 1500):
        assert f"agent{i}" in log_counter._next_check_times
    for i in range(0, 500):
        assert f"agent{i}" not in log_counter._next_check_times
    mock_log.assert_called()

# Error Handling Tests
@patch("log_monitor.LogCounter._LogCounter__log")
def test_schedule_agent_with_zero_interval(mock_log, log_counter):
    """Test scheduling agent with zero interval."""
    # Setup
    log_counter._agent_heap = []
    log_counter._next_check_times = {}
    agent_id = "agent1"
    
    # Execute
    log_counter._LogCounter__schedule_agent(agent_id, 0)
    
    # Assert
    assert agent_id in log_counter._next_check_times
    assert len(log_counter._agent_heap) == 1
    mock_log.assert_called()

@patch("log_monitor.LogCounter._LogCounter__log")
def test_schedule_agent_with_very_large_interval(mock_log, log_counter):
    """Test scheduling agent with very large interval."""
    # Setup
    log_counter._agent_heap = []
    log_counter._next_check_times = {}
    agent_id = "agent1"
    very_large_interval = 10**8  # Over 3 years
    
    # Execute
    log_counter._LogCounter__schedule_agent(agent_id, very_large_interval)
    
    # Assert
    assert agent_id in log_counter._next_check_times
    # Check if time is correctly far in the future
    time_diff = log_counter._next_check_times[agent_id] - datetime.now()
    assert time_diff.days > 1000
    mock_log.assert_called()

# Performance Tests for __check_agent_logs
@patch("log_monitor.LogCounter._LogCounter__setup_query")
@patch("log_monitor.LogCounter._LogCounter__log")
@patch("time.time")
def test_check_agent_logs_performance(mock_time, mock_log, mock_setup_query, log_counter):
    """Test performance of check_agent_logs."""
    # Setup
    mock_setup_query.return_value = {"query": "test"}
    log_counter._apiHandler = MagicMock()
    mock_response = MagicMock()
    mock_response.status_code = 200
    mock_response.json.return_value = {"count": 1000}
    log_counter._apiHandler.get.return_value = mock_response
    
    # Time calls for performance tracking
    mock_time.side_effect = [100.0, 100.2]  # Simulating 200ms execution time
    
    # Execute
    log_counter._LogCounter__check_agent_logs("agent1", "001", 600)
    
    # Assert that execution completes
    log_counter._apiHandler.get.assert_called_once()
    # Check for any performance logging (implementation dependent)
    mock_log.assert_called()

# Edge Cases in Query Setup
@patch("log_monitor.LogCounter._LogCounter__log")
def test_setup_query_with_special_chars(mock_log, log_counter):
    """Test query setup with agent IDs containing special characters."""
    # Special characters that might cause issues in queries
    agent_id = "agent-with_special.chars:@123"
    check_interval = 600
    
    # Execute
    query = log_counter._LogCounter__setup_query(check_interval, agent_id)
    
    # Assert query is properly constructed
    assert query["query"]["bool"]["must"][1]["term"]["agent.id"] == agent_id
    mock_log.assert_called_once()

# Edge Cases in API Response Handling
@patch("log_monitor.LogCounter._LogCounter__setup_query")
@patch("log_monitor.LogCounter._LogCounter__log")
@patch("log_monitor.LogCounter._LogCounter__notify_channels")
def test_check_agent_logs_unexpected_response_format(mock_notify, mock_log, mock_setup_query, log_counter):
    """Test handling of unexpected API response format."""
    # Setup
    mock_setup_query.return_value = {"query": "test"}
    log_counter._apiHandler = MagicMock()
    mock_response = MagicMock()
    mock_response.status_code = 200
    mock_response.json.return_value = {"unexpected": "format"}  # Missing expected 'count'
    log_counter._apiHandler.get.return_value = mock_response
    
    # Execute
    log_counter._LogCounter__check_agent_logs("agent1", "001", 600)
    
    # Assert that default count of 0 is used, triggering a warning message
    mock_notify.assert_called_once()
    warning_logged = False
    for call in mock_log.call_args_list:
        args = call[0]
        if args[0] == "Agent: agent1 [001] hasn't received any logs in 10.0 minutes.":
            warning_logged = True
            break
    assert warning_logged, "Expected warning message not logged"

# Time-related tests
@patch("log_monitor.LogCounter._LogCounter__log")
@patch("log_monitor.LogCounter._LogCounter__check_agent_logs")
@patch("log_monitor.LogCounter._LogCounter__schedule_agent")
@patch("log_monitor.datetime")
@patch("time.sleep", return_value=None)  # Don't actually sleep in tests
def test_start_log_counter_with_same_scheduled_times(mock_sleep, mock_datetime, mock_schedule, mock_check_logs, mock_log, log_counter):
    """Test when multiple agents have the same scheduled check time."""
    # Setup: Two agents with identical scheduled times
    same_time = datetime(2025, 1, 1, 12, 0, 30)
    mock_datetime.now.side_effect = [
        datetime(2025, 1, 1, 12, 0, 0),  # Start time
        datetime(2025, 1, 1, 12, 0, 0),  # Initial time
        datetime(2025, 1, 1, 12, 0, 31),  # Time when checking the heap
        datetime(2025, 1, 1, 13, 0, 1)   # Time for termination check
    ]
    
    # Two agents with the same scheduled time
    log_counter._agent_heap = [(same_time, "001"), (same_time, "002")]
    log_counter._next_check_times = {
        "001": same_time,
        "002": same_time
    }
    
    # Execute
    log_counter._LogCounter__start_log_counter(
        600,  # default check interval
        {"001": 300, "002": 600},  # agent check intervals
        {"001":"agent1", "002":"agent2"},  # agent ids
    )
    
    # Assert: Both agents should have been checked
    assert mock_check_logs.call_count == 2
    mock_check_logs.assert_any_call("agent1", "001", 300)
    mock_check_logs.assert_any_call("agent2", "002", 600)
    
    # Both agents should have been rescheduled
    assert mock_schedule.call_count == 2
    mock_schedule.assert_any_call("001", 300)
    mock_schedule.assert_any_call("002", 600)

@patch("log_monitor.LogCounter._LogCounter__refresh_agent_heap")
@patch("log_monitor.LogCounter._LogCounter__check_agent_logs")
@patch("log_monitor.LogCounter._LogCounter__schedule_agent")
@patch("log_monitor.datetime")
@patch("time.sleep")
@patch("heapq.heappop")
def test_start_log_counter_with_heap_corruption(mock_heappop, mock_sleep, mock_datetime, mock_schedule, mock_check_logs, mock_refresh, log_counter):
    """Test when the heap gets corrupted and raises an exception."""
    # Setup
    mock_datetime.now.side_effect = [
        datetime(2025, 1, 1, 12, 0, 0),   # Start time
        datetime(2025, 1, 1, 12, 0, 0),  # Initial time
        datetime(2025, 1, 1, 12, 0, 31)   # Time when checking the heap
    ]
    log_counter._agent_heap = [(datetime(2025, 1, 1, 12, 0, 30), "001")]
    log_counter._next_check_times = {"001": datetime(2025, 1, 1, 12, 0, 30)}
    
    # Simulate heap corruption
    mock_heappop.side_effect = IndexError("heap is empty")
    
    # Execute
    with pytest.raises(IndexError):
        log_counter._LogCounter__start_log_counter(
            600,
            {"001": 300},
            {"001":"agent1"}
        )
    
    # Assert
    mock_refresh.assert_called_once()
    mock_check_logs.assert_not_called()

# Test for API Handler setup with custom verification path
@patch("log_monitor.WAH")
@patch("log_monitor.LogCounter._LogCounter__get_env_var")
@patch("log_monitor.LogCounter._LogCounter__log")
def test_setup_wazuh_handler_with_custom_verify_path(mock_log, mock_get_env_var, mock_wazuh_handler, log_counter):
    """Test setup of API Handler with custom SSL verification path."""
    # Setup
    mock_get_env_var.side_effect = [
        "username",                # Username
        "password",                # Password
        "https://api.example.com",  # API URL
        "extra-files/root-ca.pem",  # Custom CA path
    ]
    mock_handler_instance = MagicMock()
    mock_wazuh_handler.return_value = mock_handler_instance
    
    # Execute
    log_counter._LogCounter__setup_wazuh_handler()
    
    # Assert
    mock_wazuh_handler.assert_called_once()
    # Verify that the expected verification path is passed
    call_args = mock_wazuh_handler.call_args[0]
    assert call_args[4] == os.path.join(os.getcwd(), "extra-files/root-ca.pem")  # 5th argument is 'verify'

# Test main method with an exception during setup
@patch("log_monitor.LogCounter._LogCounter__setup_env_handler")
@patch("log_monitor.LogCounter._LogCounter__setup_basics", side_effect=Exception("Setup failed"))
def test_main_exception_during_setup(mock_setup_basics, mock_setup_env, log_counter):
    """Test main method handles exceptions during setup."""
    with pytest.raises(Exception) as exc_info:
        log_counter.main()
    
    assert "Setup failed" in str(exc_info.value)
    mock_setup_env.assert_called_once()
    mock_setup_basics.assert_called_once()

# Test timeout prevention
@patch("log_monitor.LogCounter._LogCounter__log")
@patch("log_monitor.LogCounter._LogCounter__check_agent_logs")
@patch("log_monitor.datetime")
@patch("time.sleep")
def test_start_log_counter_prevents_infinite_loop(mock_sleep, mock_datetime, mock_check_logs, mock_log, log_counter):
    """Test that log_counter avoids infinite loops even if the clock doesn't advance."""
    # Setup - all time checks return the same time
    fixed_time = datetime(2025, 1, 1, 12, 0, 0)
    mock_datetime.now.side_effect = [
        datetime(2025, 1, 1, 11, 0, 0),
        datetime(2025, 1, 1, 12, 0, 0),
        datetime(2025, 1, 1, 12, 0, 1)
    ]
    
    # Set up agents that should be processed
    log_counter._agent_heap = [
        (fixed_time - timedelta(seconds=10), "001"),
        (fixed_time - timedelta(seconds=5), "002")
    ]
    log_counter._next_check_times = {
        "001": fixed_time - timedelta(seconds=10),
        "002": fixed_time - timedelta(seconds=5)
    }
    
    # Mock schedule_agent to prevent adding back to the heap
    log_counter._LogCounter__schedule_agent = MagicMock()
    
    # Execute with a timeout
    log_counter._LogCounter__start_log_counter(
        600,
        {},
        {"001":"agent1", "002":"agent2"}  # agent ids
    )
    
# Tests for Empty Agent Scenarios
@patch("log_monitor.LogCounter._LogCounter__log")
@patch("log_monitor.LogCounter._LogCounter__get_env_var")
@patch("log_monitor.LogCounter._LogCounter__notify_channels")
def test_load_agent_ids_empty_file(mock_notify, mock_get_env, mock_log, log_counter):
    """Test behavior when the agent list file is empty."""
    # Create an empty file
    with tempfile.NamedTemporaryFile(delete=False) as temp_file:
        temp_file_path = temp_file.name
    
    try:
        # Test loading an empty agent list file
        result = log_counter._LogCounter__load_agents(temp_file_path)
        
        # Should return empty list but not raise an error
        assert result == {}
        mock_log.assert_any_call(f"Successfully loaded 0 unique agent ID(s) from {temp_file_path}.")
        mock_notify.assert_not_called()
    finally:
        # Clean up
        if os.path.exists(temp_file_path):
            os.remove(temp_file_path)

@patch("log_monitor.LogCounter._LogCounter__refresh_agent_heap")
@patch("log_monitor.LogCounter._LogCounter__check_agent_logs")
@patch("log_monitor.datetime")
@patch("time.sleep")
def test_start_log_counter_with_no_agents(mock_sleep, mock_datetime, mock_check_logs, mock_refresh, log_counter):
    """Test the log counter behavior when no agents are configured."""
    # Setup
    mock_datetime.now.side_effect = [
        datetime(2025, 1, 1, 12, 0, 0),  # start time
        datetime(2025, 1, 1, 12, 0, 0),  # Initial time
        datetime(2025, 1, 1, 12, 0, 10),  # Time when checking the heap
        datetime(2025, 1, 1, 13, 0, 1)   # Time for termination check
    ]
    
    # Empty agent heap and tracking dict
    log_counter._agent_heap = []
    log_counter._next_check_times = {}
    
    # Execute - should just refresh and then sleep
    log_counter._LogCounter__start_log_counter(
        600,  # default check interval
        {},    # empty agent check intervals
        {}    # empty agent ids
    )
    
    # Assert - should have refreshed but not checked any agents
    mock_refresh.assert_called_once()
    mock_check_logs.assert_not_called()
    mock_sleep.assert_called_with(5)

# Tests for Time-based Scenarios
@patch("log_monitor.LogCounter._LogCounter__refresh_agent_heap")
@patch("log_monitor.LogCounter._LogCounter__check_agent_logs")
@patch("log_monitor.LogCounter._LogCounter__schedule_agent")
@patch("log_monitor.datetime")
@patch("time.sleep")
def test_start_log_counter_day_boundary_transition(mock_sleep, mock_datetime, mock_schedule, mock_check_logs, mock_refresh, log_counter):
    """Test transitions across day boundaries."""
    # Setup - time sequence that crosses day boundary
    day1_time = datetime(2025, 1, 1, 23, 59, 0)  # Just before midnight
    day2_time = datetime(2025, 1, 2, 0, 0, 10)   # Just after midnight
    mock_datetime.now.side_effect = [
        day1_time,  # Start time
        day1_time,  # Initial time
        day2_time,  # Time when checking the heap
        datetime(2025, 1, 2, 0, 59, 1)   # Time for termination check
    ]
    
    # Agent scheduled just before midnight
    scheduled_time = datetime(2025, 1, 1, 23, 59, 30)
    log_counter._agent_heap = [(scheduled_time, "001")]
    log_counter._next_check_times = {"001": scheduled_time}
    
    # Execute
    log_counter._LogCounter__start_log_counter(
        600,  # default check interval
        {"001": 300},  # agent check intervals
        {"001":"agent1"},  # agent ids
    )
    
    # Assert - agent should be checked across midnight boundary
    mock_refresh.assert_called_once()
    mock_check_logs.assert_called_once_with("agent1", "001", 300)
    mock_schedule.assert_called_once_with("001", 300)

@patch("log_monitor.LogCounter._LogCounter__refresh_agent_heap")
@patch("log_monitor.LogCounter._LogCounter__check_agent_logs")
@patch("log_monitor.LogCounter._LogCounter__schedule_agent")
@patch("log_monitor.datetime")
@patch("time.sleep")
def test_precise_scheduling_behavior(mock_sleep, mock_datetime, mock_schedule, mock_check_logs, mock_refresh, log_counter):
    """Test precise scheduling with multiple agents at different times."""
    # Setup - sequence of times for precise scheduling test
    mock_datetime.now.side_effect = [
        datetime(2025, 1, 1, 12, 0, 0),  # start time
        datetime(2025, 1, 1, 12, 0, 0),   # Initial time
        datetime(2025, 1, 1, 12, 0, 15),  # Time for agent1
        datetime(2025, 1, 1, 12, 0, 30),  # Time for agent2
        datetime(2025, 1, 1, 12, 0, 45),  # Time for agent3
        datetime(2025, 1, 1, 13, 0, 1)    # Termination check
    ]
    
    # Agents scheduled at 15-second intervals
    log_counter._agent_heap = [
        (datetime(2025, 1, 1, 12, 0, 15), "001"),
        (datetime(2025, 1, 1, 12, 0, 30), "002"),
        (datetime(2025, 1, 1, 12, 0, 45), "003")
    ]
    log_counter._next_check_times = {
        "001": datetime(2025, 1, 1, 12, 0, 15),
        "002": datetime(2025, 1, 1, 12, 0, 30),
        "003": datetime(2025, 1, 1, 12, 0, 45)
    }
    
    # Mock schedule_agent to avoid adding back to the heap
    log_counter._LogCounter__schedule_agent = MagicMock()
    
    # Execute
    log_counter._LogCounter__start_log_counter(
        600,  # default check interval
        {"001": 60, "002": 120, "003": 180},  # different intervals
        {"001":"agent1", "002":"agent2", "003":"agent3"}  # agent ids
    )
    
    # Assert - agents should be checked in exact order with correct timing
    mock_refresh.assert_called_once()
    assert mock_check_logs.call_count == 3
    mock_check_logs.assert_has_calls([
        call("agent1", "001", 60),
        call("agent2", "002", 120),
        call("agent3", "003", 180)
    ])
    mock_sleep.assert_has_calls([call(15), call(15), call(15)])

# Complex API Interaction Tests
@patch("log_monitor.LogCounter._LogCounter__setup_query")
@patch("log_monitor.LogCounter._LogCounter__log")
@patch("log_monitor.LogCounter._LogCounter__notify_channels")
def test_check_agent_logs_api_timeout(mock_notify, mock_log, mock_setup_query, log_counter):
    """Test handling of API timeout scenarios."""
    # Setup
    mock_setup_query.return_value = {"query": "test"}
    log_counter._apiHandler = MagicMock()
    log_counter._apiHandler.get.side_effect = requests.exceptions.Timeout("Connection timed out")
    
    # Execute
    log_counter._LogCounter__check_agent_logs("agent1", "001", 600)
    
    # Assert that timeout is properly handled
    expected_error = "Failed to send query request for agent agent1 [001] with the following error: Timeout('Connection timed out')"
    mock_notify.assert_called_once()
    mock_log.assert_has_calls([call("Sending query request for 001."),call(expected_error, LOGGING_CATEGORY.ERROR), call("Finished control of agent agent1 [001].")])

@patch("log_monitor.LogCounter._LogCounter__setup_query")
@patch("log_monitor.LogCounter._LogCounter__log")
@patch("log_monitor.LogCounter._LogCounter__notify_channels")
def test_check_agent_logs_partial_data(mock_notify, mock_log, mock_setup_query, log_counter):
    """Test handling of partial data in API response."""
    # Setup - response has some data but missing count
    mock_setup_query.return_value = {"query": "test"}
    log_counter._apiHandler = MagicMock()
    mock_response = MagicMock()
    mock_response.status_code = 200
    mock_response.json.return_value = {
        "hits": {"total": {"value": 5}},  # Alternative format that doesn't use 'count'
        "took": 123
    }
    log_counter._apiHandler.get.return_value = mock_response
    
    # Execute
    log_counter._LogCounter__check_agent_logs("agent1", "001", 600)
    
    # Assert that function handles missing 'count' field gracefully
    mock_notify.assert_called_once()
    mock_log.assert_any_call("Agent: agent1 [001] hasn't received any logs in 10.0 minutes.", LOGGING_CATEGORY.WARNING)

# Performance Thresholds for Memory Tests
def test_memory_usage_thresholds():
    """Test memory usage with defined thresholds."""
    
    # Force garbage collection before starting
    gc.collect()
    tracemalloc.start()
    
    # Create LogCounter instance
    counter = LogCounter()
    counter._logger = MagicMock()
    
    # Create baseline snapshot
    baseline = tracemalloc.take_snapshot()
    
    # Add agents in batches and measure after each batch
    agent_counts = [100, 1000, 5000, 10000]
    memory_usage = []
    
    for count in agent_counts:
        # Add agents to reach desired count
        start_idx = len(counter._next_check_times)
        for i in range(start_idx, count):
            check_time = datetime.now() + timedelta(seconds=i*100)
            counter._next_check_times[f"agent{i}"] = check_time
            heapq.heappush(counter._agent_heap, (check_time, f"agent{i}"))
        
        # Measure memory at this count
        snapshot = tracemalloc.take_snapshot()
        stats = snapshot.compare_to(baseline, 'lineno')
        
        # Get total memory usage for relevant files
        total_memory = 0
        for stat in stats:
            if 'log_monitor.py' in str(stat.traceback):
                total_memory += stat.size
        
        memory_usage.append(total_memory)
        
        # Verify heap integrity at each stage
        assert len(counter._agent_heap) == count
        assert len(counter._next_check_times) == count
    
    # Define acceptable memory thresholds (in bytes)
    # These thresholds should be adjusted based on actual performance requirements
    max_allowed = {
        100: 100 * 1024,      # ~100KB for 100 agents
        1000: 500 * 1024,     # ~500KB for 1000 agents
        5000: 2 * 1024 * 1024, # ~2MB for 5000 agents
        10000: 4 * 1024 * 1024 # ~4MB for 10000 agents
    }
    
    # Check memory usage against thresholds
    for i, count in enumerate(agent_counts):
        print(f"Memory for {count} agents: {memory_usage[i]/1024:.2f} KB")
        assert memory_usage[i] <= max_allowed[count], f"Memory usage for {count} agents exceeds threshold"
    
    # Clean up
    tracemalloc.stop()