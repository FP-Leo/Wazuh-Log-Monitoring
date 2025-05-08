#!/usr/bin/env python3

import os
import tempfile
import sys
from pathlib import Path
import re
import pytest
from logger import Logger, LOGGING_CATEGORY
import datetime
import threading

# Add parent directory to path to import Logger
sys.path.append(str(Path(__file__).parent.parent))

@pytest.fixture
def test_file():
    """Create a temporary file for testing."""
    temp_file = tempfile.NamedTemporaryFile(delete=False).name
    yield temp_file
    # Cleanup after test
    if os.path.exists(temp_file):
        os.remove(temp_file)

@pytest.mark.parametrize("level", [0, 1, 2, 3])
def test_init_valid_params(test_file, level):
    """Test initialization with valid parameters."""
    logger = Logger(test_file, logging_level=level)
    assert logger.log_file == test_file
    assert logger.logging_level == level
    assert os.path.exists(test_file)

@pytest.mark.parametrize("level", [-1, 4, "invalid", 2.5])
def test_init_invalid_params(test_file, level):
    """Test initialization with invalid parameters."""
    with pytest.raises(ValueError):
        Logger(test_file, logging_level=level)

def test_log_file_creation(test_file):
    """Test that log file is created if it doesn't exist."""
    if os.path.exists(test_file):
        os.remove(test_file)
    logger = Logger(test_file)
    assert os.path.exists(test_file)

def test_file_cant_be_created():
    """Test initialization when log file can't be created."""
    # Use a path in a non-existent directory
    invalid_path = "/nonexistent_directory/test.log"
    
    # On Windows, use a different invalid path format
    if os.name == 'nt':
        invalid_path = "Z:\\nonexistent\\dir\\test.log"
    
    with pytest.raises(IOError):
        Logger(invalid_path)

def test_non_string_log_file():
    """Test initialization with a non-string log file path."""
    with pytest.raises(ValueError):
        Logger(123)  # Integer instead of string
    
    with pytest.raises(ValueError):
        Logger(None)  # None instead of string
        
    with pytest.raises(ValueError):
        Logger([])  # List instead of string

def test_empty_string_log_file():
    """Test initialization with an empty string as log file path."""
    with pytest.raises(ValueError):
        Logger("")

def test_concurrent_loggers(test_file):
    """Test multiple loggers writing to the same file."""
    logger1 = Logger(test_file, logging_level=3)
    logger2 = Logger(test_file, logging_level=3)
    
    logger1.write_log("Logger1", LOGGING_CATEGORY.ERROR, "Error from logger 1")
    logger2.write_log("Logger2", LOGGING_CATEGORY.WARNING, "Warning from logger 2")
    
    with open(test_file, 'r') as f:
        lines = f.readlines()
    
    assert len(lines) == 2
    assert "Logger1: ERROR" in lines[0]
    assert "Logger2: WARNING" in lines[1]

def test_long_log_message(test_file):
    """Test writing a very long log message."""
    logger = Logger(test_file, logging_level=1)
    long_message = "A" * 1000  # 1000 character message
    
    logger.write_log("TestModule", LOGGING_CATEGORY.ERROR, long_message)
    
    with open(test_file, 'r') as f:
        content = f.read()
    
    assert long_message in content

def test_special_characters_in_message(test_file):
    """Test writing messages with special characters."""
    logger = Logger(test_file, logging_level=1)
    special_msg = "Special chars: !@#$%^&*()_+{}|:<>?[];',./\\`~"
    
    logger.write_log("TestModule", LOGGING_CATEGORY.ERROR, special_msg)
    
    with open(test_file, 'r') as f:
        content = f.read()
    
    assert special_msg in content

@pytest.mark.parametrize("level, category, should_log", [
    (0, LOGGING_CATEGORY.ERROR, False),   # Level 0 logs nothing
    (0, LOGGING_CATEGORY.WARNING, False), 
    (0, LOGGING_CATEGORY.INFO, False),
    (1, LOGGING_CATEGORY.ERROR, True),    # Level 1 logs errors only
    (1, LOGGING_CATEGORY.WARNING, False),
    (1, LOGGING_CATEGORY.INFO, False),
    (2, LOGGING_CATEGORY.ERROR, True),    # Level 2 logs errors and warnings
    (2, LOGGING_CATEGORY.WARNING, True),
    (2, LOGGING_CATEGORY.INFO, False),
    (3, LOGGING_CATEGORY.ERROR, True),    # Level 3 logs everything
    (3, LOGGING_CATEGORY.WARNING, True),
    (3, LOGGING_CATEGORY.INFO, True),
])
def test_log_levels(test_file, level, category, should_log):
    """Test that logs are written based on logging level settings."""
    if os.path.exists(test_file):
        os.remove(test_file)
        
    logger = Logger(test_file, logging_level=level)
    logger.write_log("TestModule", category, "Test message")
    
    file_exists = os.path.exists(test_file)
    file_has_content = os.path.getsize(test_file) > 0 if file_exists else False
    
    assert file_has_content == should_log, f"Failed with level {level}, category {category.name}"

def test_invalid_category(test_file):
    """Test handling of invalid category."""
    logger = Logger(test_file)
    with pytest.raises(ValueError):
        logger.write_log("TestModule", "InvalidCategory", "Test message")

def test_logs_end_with_newline(test_file):
    logger = Logger(test_file, logging_level=3)
    logger.write_log("TestModule", LOGGING_CATEGORY.INFO, "Check newline")
    with open(test_file) as f:
        content = f.read()
    assert content.endswith("\n")

def test_log_timestamp_is_valid(test_file):
    logger = Logger(test_file, logging_level=3)
    logger.write_log("TestModule", LOGGING_CATEGORY.ERROR, "Message")

    with open(test_file) as f:
        log_line = f.readline()
        timestamp_str = log_line.split(" ")[0] + " " + log_line.split(" ")[1]
        try:
            datetime.datetime.strptime(timestamp_str, "%Y/%m/%d %H:%M:%S")
        except ValueError:
            pytest.fail(f"Invalid timestamp format: {timestamp_str}")

def test_log_format_error(test_file):
    """Test the format of ERROR log entries."""
    logger = Logger(test_file, logging_level=3)
    logger.write_log("TestModule", LOGGING_CATEGORY.ERROR, "Error message")
    
    with open(test_file, 'r') as f:
        log_content = f.read()
    
    # Check log format using regex
    pattern = r"\d{4}/\d{2}/\d{2} \d{2}:\d{2}:\d{2} TestModule: ERROR - Error message"
    assert re.match(pattern, log_content.strip()), f"Log format incorrect: {log_content}"

def test_log_format_warning(test_file):
    """Test the format of WARNING log entries."""
    logger = Logger(test_file, logging_level=3)
    logger.write_log("TestModule", LOGGING_CATEGORY.WARNING, "Warning message")
    
    with open(test_file, 'r') as f:
        log_content = f.read()
    
    # Check log format using regex
    pattern = r"\d{4}/\d{2}/\d{2} \d{2}:\d{2}:\d{2} TestModule: WARNING - Warning message"
    assert re.match(pattern, log_content.strip()), f"Log format incorrect: {log_content}"

def test_log_format_info(test_file):
    """Test the format of INFO log entries."""
    logger = Logger(test_file, logging_level=3)
    logger.write_log("TestModule", LOGGING_CATEGORY.INFO, "Info message")
    
    with open(test_file, 'r') as f:
        log_content = f.read()
    
    # Check log format using regex
    pattern = r"\d{4}/\d{2}/\d{2} \d{2}:\d{2}:\d{2} TestModule: INFO - Info message"
    assert re.match(pattern, log_content.strip()), f"Log format incorrect: {log_content}"

@pytest.mark.parametrize("invalid_name", [None, "", 123, [], {}, 0, False])
def test_invalid_ar_name(test_file, invalid_name):
    """Test that ValueError is raised when ar_name is not a non-empty string."""
    logger = Logger(test_file)
    with pytest.raises(ValueError, match="ar_name must be a non-empty string"):
        logger.write_log(invalid_name, LOGGING_CATEGORY.ERROR, "Test message")

@pytest.mark.parametrize("invalid_msg", [None, "", 123, [], {}, 0, False])
def test_invalid_msg(test_file, invalid_msg):
    """Test that ValueError is raised when msg is not a non-empty string."""
    logger = Logger(test_file)
    with pytest.raises(ValueError, match="msg must be a non-empty string"):
        logger.write_log("TestModule", LOGGING_CATEGORY.ERROR, invalid_msg)

def test_generic_exception_handling(test_file, monkeypatch, capsys):
    """Test handling of generic exceptions during logging."""
    # Create a custom exception for testing
    class TestLoggingError(Exception):
        pass
    
    # Create a logger
    logger = Logger(test_file)
    
    # Define a custom mock for open that raises our test exception
    original_open = open
    def mock_open(*args, **kwargs):
        if args[0] == test_file and 'a+' in kwargs.get('mode', ''):
            raise TestLoggingError("Test logging error")
        return original_open(*args, **kwargs)
    
    # Replace the built-in open function with our mock
    monkeypatch.setattr("builtins.open", mock_open)
    
    # Verify that our exception is raised and error message is printed
    with pytest.raises(TestLoggingError, match="Test logging error"):
        logger.write_log("TestModule", LOGGING_CATEGORY.ERROR, "Test message")
    
    # Check that the error was printed to stdout
    captured = capsys.readouterr()
    assert "Logging error: Test logging error" in captured.out
        
def test_multiple_log_entries(test_file):
    """Test writing multiple log entries."""
    logger = Logger(test_file, logging_level=3)
    logger.write_log("Module1", LOGGING_CATEGORY.ERROR, "Error 1")
    logger.write_log("Module2", LOGGING_CATEGORY.WARNING, "Warning 1")
    logger.write_log("Module3", LOGGING_CATEGORY.INFO, "Info 1")
    
    with open(test_file, 'r') as f:
        lines = f.readlines()
    
    assert len(lines) == 3
    assert "ERROR - Error 1" in lines[0]
    assert "WARNING - Warning 1" in lines[1]
    assert "INFO - Info 1" in lines[2]

def test_file_not_accessible(test_file):
    """Test when log file exists but is not accessible."""
    # Create the file first
    logger = Logger(test_file)
    
    # Make file read-only
    os.chmod(test_file, 0o444)  # Read-only for all users
    
    # Try to write to the read-only file
    with pytest.raises(PermissionError):
        logger.write_log("TestModule", LOGGING_CATEGORY.ERROR, "This should fail")

    # Restore permissions for cleanup
    os.chmod(test_file, 0o666)  # Read/write for all users

def test_thread_safety(test_file):
    """Test logger behavior with multiple threads writing concurrently."""
    logger = Logger(test_file, logging_level=3)

    def log_messages():
        for _ in range(100):
            logger.write_log("Thread", LOGGING_CATEGORY.INFO, "Thread-safe test")

    threads = [threading.Thread(target=log_messages) for _ in range(5)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join()

    with open(test_file, 'r') as f:
        lines = f.readlines()

    assert len(lines) == 500, f"Length of lines are {len(lines)}"  # 5 threads * 100 messages each

@pytest.mark.skip(reason="Performance test, may take time")
def test_high_volume_logging(test_file):
    """Test logger performance with a high volume of log entries."""
    logger = Logger(test_file, logging_level=3)

    for i in range(10000):
        logger.write_log("StressTest", LOGGING_CATEGORY.INFO, f"Message {i}")

    with open(test_file, 'r') as f:
        lines = f.readlines()

    assert len(lines) == 10000