import os
import time
import pytest
import tempfile
import requests
import threading
from unittest.mock import patch, MagicMock
from datetime import datetime, timedelta

from log_monitor import LogCounter
from logger import LOGGING_CATEGORY
from custom_errors import EnvVariableNotFoundError

# Fixtures
@pytest.fixture
def mock_env_file():
    """Create a temporary environment file for testing."""
    with tempfile.NamedTemporaryFile(mode='w', delete=False) as f:
        f.write("LOG_FILE_PATH=test_logs.log\n")
        f.write("LOGGING_LEVEL=2\n")
        f.write("DEFAULT_CHECK_INTERVAL=300\n")
        f.write("WAZUH_URL=https://test-wazuh-api.local\n")
        f.write("USERNAME=test_user\n")
        f.write("PASSWORD=test_pass\n")
        f.write("SLACK_WEBHOOK_URL=https://hooks.slack.com/services/test\n")
        f.write("SMTP_SERVER=test-smtp.local\n")
        f.write("SMTP_PORT=25\n")
        f.write("SMTP_USERNAME=test_smtp\n")
        f.write("SMTP_PASSWORD=test_smtp_pass\n")
        f.write("SMTP_FROM=test@example.com\n")
        f.write("SMTP_TO=admin@example.com\n")
        temp_file_path = f.name
    
    yield temp_file_path
    
    if os.path.exists(temp_file_path):
        os.remove(temp_file_path)

@pytest.fixture
def agent_list_file():
    """Create a temporary agent list file for testing."""
    with tempfile.NamedTemporaryFile(mode='w', delete=False) as f:
        f.write("agent1\n")
        f.write("agent2\n")
        f.write("agent3\n")
        temp_file_path = f.name
    
    yield temp_file_path
    
    if os.path.exists(temp_file_path):
        os.remove(temp_file_path)

@pytest.fixture
def modified_agent_list_file(agent_list_file):
    """Create a modified version of the agent list file after a delay."""
    def modify_file():
        time.sleep(2)  # Wait to simulate file changes during execution
        with open(agent_list_file, 'w') as f:
            f.write("agent1\n")
            f.write("agent4\n")  # agent2 removed, agent4 added
            f.write("agent3\n")
    
    threading_event = threading.Thread(target=modify_file)
    threading_event.daemon = True
    
    yield threading_event

@pytest.fixture
def log_counter_with_mocks():
    """Create a LogCounter instance with mocked dependencies."""
    counter = LogCounter()
    
    # Mock the environment handler setup
    with patch.object(counter, '_LogCounter__setup_env_handler') as mock_setup_env:
        mock_setup_env.return_value = None
        
        # Mock the basic setup components
        with patch.object(counter, '_LogCounter__setup_basics') as mock_setup_basics:
            mock_setup_basics.return_value = None
            
            # Mock the API handler setup
            with patch.object(counter, '_LogCounter__setup_wazuh_handler') as mock_setup_wazuh:
                mock_setup_wazuh.return_value = None
                
                # Initialize internal mocks
                counter._envHandler = MagicMock()
                counter._logger = MagicMock()
                counter._slack_client = MagicMock()
                counter._smtp_client = MagicMock()
                counter._apiHandler = MagicMock()
                
                yield counter

# Integration Tests
@patch('log_monitor.EH')
def test_integration_env_handler_setup(mock_env_handler_class, mock_env_file):
    """Test integration with environment handler setup."""
    # Arrange
    counter = LogCounter()
    mock_env_handler_instance = MagicMock()
    mock_env_handler_class.return_value = mock_env_handler_instance
    
    # Act
    counter._LogCounter__setup_env_handler(env=mock_env_file)
    
    # Assert
    mock_env_handler_class.assert_called_once_with(env=mock_env_file)
    assert counter._envHandler == mock_env_handler_instance

@patch('log_monitor.LogCounter._LogCounter__notify_channels')
@patch('log_monitor.LogCounter._LogCounter__setup_env_handler')
def test_integration_load_agent_ids(mock_setup_env, mock_notify, log_counter_with_mocks, agent_list_file):
    """Test integration with loading agent IDs from file."""
    # Arrange
    counter = log_counter_with_mocks
    expected_agents = ["agent1", "agent2", "agent3"]
    
    # Act
    actual_agents = counter._LogCounter__load_agent_ids(agent_list_file)
    
    # Assert
    assert actual_agents == expected_agents
    counter._logger.write_log.assert_any_call("LogCounter", LOGGING_CATEGORY.INFO, "Successfully loaded Agent List File's Path.")

@patch('requests.Response')
def test_integration_check_agent_logs_success(mock_response, log_counter_with_mocks):
    """Test successful integration with Wazuh API for checking agent logs."""
    # Arrange
    counter = log_counter_with_mocks
    mock_response.status_code = 200
    mock_response.json.return_value = {"count": 10}
    counter._apiHandler.get.return_value = mock_response
    
    # Act
    counter._LogCounter__check_agent_logs("agent1", 600)
    
    # Assert
    counter._apiHandler.get.assert_called_once()
    counter._logger.write_log.assert_any_call("LogCounter", LOGGING_CATEGORY.INFO, "Agent: agent1 has received 10 logs in the last 600")
    # Verify no notifications were sent for successful check
    counter._slack_client.send_message.assert_not_called()
    counter._smtp_client.send_mail.assert_not_called()

@patch('requests.Response')
def test_integration_check_agent_logs_no_logs(mock_response, log_counter_with_mocks):
    """Test integration with Wazuh API when no logs are found for an agent."""
    # Arrange
    counter = log_counter_with_mocks
    mock_response.status_code = 200
    mock_response.json.return_value = {"count": 0}
    counter._apiHandler.get.return_value = mock_response
    
    # Act
    counter._LogCounter__check_agent_logs("agent1", 600)
    
    # Assert
    counter._logger.write_log.assert_any_call("LogCounter", LOGGING_CATEGORY.WARNING, "Agent: agent1 hasn't received any logs in 600")
    # Verify notification was sent
    assert counter._slack_client.send_message.called or counter._smtp_client.send_mail.called

@patch('requests.Response')
def test_integration_check_agent_logs_api_error(mock_response, log_counter_with_mocks):
    """Test integration with Wazuh API when the API returns an error."""
    # Arrange
    counter = log_counter_with_mocks
    mock_response.status_code = 403
    mock_response.text = "Forbidden"
    counter._apiHandler.get.return_value = mock_response
    
    # Act
    counter._LogCounter__check_agent_logs("agent1", 600)
    
    # Assert
    counter._logger.write_log.assert_any_call("LogCounter", LOGGING_CATEGORY.ERROR, 
                                          "Failed to query agent agent1; response code: 403, full response: Forbidden")
    # Verify notification was sent
    assert counter._slack_client.send_message.called or counter._smtp_client.send_mail.called

@patch('requests.exceptions.RequestException')
def test_integration_check_agent_logs_connection_error(mock_exception, log_counter_with_mocks):
    """Test integration with Wazuh API when a connection error occurs."""
    # Arrange
    counter = log_counter_with_mocks
    counter._apiHandler.get.side_effect = requests.exceptions.RequestException("Connection failed")

    # Act
    counter._LogCounter__check_agent_logs("agent1", 600)

    # Assert log was written with expected error content
    error_logged = False
    for call in counter._logger.write_log.call_args_list:
        args, _ = call
        if (
            "LogCounter" in args
            and LOGGING_CATEGORY.ERROR in args
            and "Failed to query agent agent1" in args[2]
        ):
            error_logged = True
            break

    assert error_logged, "Expected error log not found in logger calls"

    # Assert at least one notification method was called
    slack_called = counter._slack_client.send_message.called if counter._slack_client else False
    smtp_called = counter._smtp_client.send_mail.called if counter._smtp_client else False

    assert slack_called or smtp_called, "Expected a notification to be sent via Slack or SMTP"

@patch('log_monitor.datetime')
@patch('time.sleep')
def test_integration_scheduler_with_agent_updates(mock_sleep, mock_datetime, log_counter_with_mocks):
    """Test integration of the scheduler with agent updates."""
    # Arrange
    counter = log_counter_with_mocks
    
    # Set up sequence of times
    current_time = datetime(2025, 1, 1, 12, 0, 0)
    mock_datetime.now.side_effect = [
        current_time,  # Initial time
        current_time + timedelta(seconds=30),  # First check
        current_time + timedelta(seconds=3700)  # Exit condition (>3600s)
    ]
    
    # Initial agents
    agent_ids = ["agent1", "agent2"]
    default_check_interval = 300
    agent_check_intervals = {"agent1": 600}
    
    # Patch methods
    with patch.object(counter, '_LogCounter__refresh_agent_heap') as mock_refresh:
        with patch.object(counter, '_LogCounter__check_agent_logs') as mock_check_logs:
            with patch.object(counter, '_LogCounter__schedule_agent') as mock_schedule:
                # Act
                counter._LogCounter__start_log_counter(
                    default_check_interval, 
                    agent_check_intervals,
                    agent_ids, 
                    current_time
                )
                
                # Assert
                mock_refresh.assert_called_once_with(agent_ids)
                # Check proper exit due to time condition
                assert mock_datetime.now.call_count == 3

@patch('log_monitor.LogCounter._LogCounter__get_env_var')
def test_integration_load_agent_check_intervals(mock_get_env_var, log_counter_with_mocks):
    """Test integration of loading agent check intervals from environment."""
    # Arrange
    counter = log_counter_with_mocks
    agent_ids = ["agent1", "agent2", "agent3"]
    mock_get_env_var.return_value = "agent1:10,agent2:20,invalid:format,unknown:30"
    
    # Act
    intervals = counter._LogCounter__load_agent_check_intervals(agent_ids)
    
    # Assert
    assert "agent1" in intervals
    assert "agent2" in intervals
    assert "unknown" not in intervals  # Should be excluded as not in agent_ids
    assert intervals["agent1"] == 600  # 10 minutes converted to seconds
    assert intervals["agent2"] == 1200  # 20 minutes converted to seconds
    counter._logger.write_log.assert_any_call("LogCounter", LOGGING_CATEGORY.WARNING, 
                                          "Agent unknown specified in AGENT_CHECK_INTERVALS not found in the registered agent IDs. Maybe it was deleted?")

@patch('time.sleep')
@patch('log_monitor.LogCounter._LogCounter__notify_channels')
@patch('log_monitor.datetime')
def test_integration_main_with_empty_agent_list(mock_now, mock_notify, mock_sleep, log_counter_with_mocks):
    """Test main function's handling of an empty agent list."""
    counter = log_counter_with_mocks

    with patch.object(counter, '_LogCounter__get_env_var') as mock_get_env_var, \
         patch.object(counter, '_LogCounter__load_agent_ids') as mock_load_ids, \
         patch.object(counter, '_LogCounter__start_log_counter') as mock_start_counter:

        mock_get_env_var.return_value = "empty_agents.txt"

        # First call returns empty list, second call returns one agent
        mock_load_ids.side_effect = [[], ["agent1"]]

        # Raise KeyboardInterrupt as soon as __start_log_counter is called (safe exit)
        mock_start_counter.side_effect = KeyboardInterrupt()

        start_time = datetime(2025, 1, 1, 12, 0, 0)
        mock_now.now.return_value = start_time

        with pytest.raises(KeyboardInterrupt):
            counter.main()

        # --- Assertions ---
        expected_msg = "Agent list is empty. No agents to check. Sleeping for 1 hour to retry."
        mock_notify.assert_called_once_with(expected_msg)
        mock_sleep.assert_called_with(3600)  # Sleeps only once for empty agent list
        assert mock_load_ids.call_count == 2      # One empty, one real
        mock_start_counter.assert_called_once_with(
            900, {}, ["agent1"],  # assumes default interval and no custom agent intervals
            start_time=start_time
        )

@patch('log_monitor.datetime')
@patch('time.sleep')
@patch('log_monitor.LogCounter._LogCounter__check_agent_logs')
def test_integration_scheduler_with_varying_intervals(mock_check_logs, mock_sleep, mock_datetime, log_counter_with_mocks):
    """Test integration of scheduler with varying check intervals."""
    # Arrange
    counter = log_counter_with_mocks
    
    # Set up sequence of times
    current_time = datetime(2025, 1, 1, 12, 0, 0)
    mock_datetime.now.side_effect = [
        current_time,  # Initial time
        current_time + timedelta(seconds=10),  # First check
        current_time + timedelta(seconds=20),  # Second check
        current_time + timedelta(seconds=3700)  # Exit condition
    ]
    
    # Setup initial heap with agents due at different times
    agent1_time = current_time + timedelta(seconds=10)
    agent2_time = current_time + timedelta(seconds=20)
    
    counter._agent_heap = [
        (agent1_time, "agent1"),
        (agent2_time, "agent2")
    ]
    counter._next_check_times = {
        "agent1": agent1_time,
        "agent2": agent2_time
    }
    
    # Agent check intervals
    agent_ids = ["agent1", "agent2"]
    default_check_interval = 300
    agent_check_intervals = {
        "agent1": 60,  # 1 minute
        "agent2": 120  # 2 minutes
    }
    
    # Act
    with patch.object(counter, '_LogCounter__schedule_agent') as mock_schedule:
        counter._LogCounter__start_log_counter(
            default_check_interval,
            agent_check_intervals,
            agent_ids,
            current_time
        )
        
        # Assert
        assert mock_check_logs.call_count == 2
        # Check that agents were scheduled with their specific intervals
        mock_schedule.assert_any_call("agent1", 60)
        mock_schedule.assert_any_call("agent2", 120)

# End-to-end test simulation
@patch('log_monitor.LogCounter._LogCounter__get_env_var')
@patch('log_monitor.LogCounter._LogCounter__start_log_counter')
@patch("log_monitor.datetime")
def test_integration_end_to_end_flow(mock_now, mock_start, mock_get_env, log_counter_with_mocks, agent_list_file):
    """Test the end-to-end flow of the LogCounter main function."""
    counter = log_counter_with_mocks

    # Provide expected env var values
    mock_get_env.side_effect = lambda var_name, required=False, default=None: {
        "AGENT_LIST_FILE": agent_list_file,
        "DEFAULT_CHECK_INTERVAL": "300"
    }.get(var_name, default)

    with patch.object(counter, '_LogCounter__load_agent_ids') as mock_load_ids, \
         patch.object(counter, '_LogCounter__getDCI') as mock_get_dci, \
         patch.object(counter, '_LogCounter__load_agent_check_intervals') as mock_load_intervals:

        mock_load_ids.return_value = ["agent1", "agent2", "agent3"]
        mock_get_dci.return_value = 300
        mock_load_intervals.return_value = {"agent1": 600, "agent2": 1200}

        # Simulate clean exit from scheduler
        mock_start.side_effect = KeyboardInterrupt()

        current_time = datetime(2025, 1, 1, 12, 0, 0)
        mock_now.now.return_value = current_time

        # Act & Assert
        with pytest.raises(KeyboardInterrupt):
            counter.main()

        # Assertions
        mock_load_ids.assert_called_once_with(agent_list_file)
        mock_get_dci.assert_called_once()
        mock_load_intervals.assert_called_once_with(["agent1", "agent2", "agent3"])
        mock_start.assert_called_once()

        # Deep check args to __start_log_counter
        args, kwargs = mock_start.call_args
        assert args[0] == 300  # default_check_interval
        assert args[1] == {"agent1": 600, "agent2": 1200}  # agent_check_intervals
        assert args[2] == ["agent1", "agent2", "agent3"]  # agent_ids
        assert "start_time" in kwargs
        assert kwargs["start_time"] == current_time