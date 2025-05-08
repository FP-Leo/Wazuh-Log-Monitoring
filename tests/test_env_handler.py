import pytest
import os
from unittest.mock import patch
from env_handler import EnvHandler
from custom_errors import EnvFileNotLoadedError, EnvVariableEmptyError, EnvVariableNotFoundError
import tempfile
import threading

@pytest.fixture
def mock_load_dotenv():
    with patch('env_handler.load_dotenv') as mock:
        mock.return_value = True
        yield mock

@pytest.fixture
def mock_getenv():
    with patch('os.getenv') as mock:
        yield mock

@pytest.fixture
def valid_handler():
    return EnvHandler("valid/path")

@pytest.fixture
def invalid_handler(mock_load_dotenv):
    mock_load_dotenv.return_value = False
    return EnvHandler("invalid/path")

def test_init_valid_path(mock_load_dotenv, valid_handler):
    mock_load_dotenv.assert_called_once_with("valid/path")
    assert valid_handler._file_loaded is True

def test_init_invalid_type():
    with pytest.raises(TypeError):
        EnvHandler(123)  # Not a string

def test_load_var_exists(mock_load_dotenv, valid_handler, mock_getenv):
    # Arrange
    mock_getenv.return_value = "test_value"
    
    # Act
    result = valid_handler.load_var("TEST_VAR")
    
    # Assert
    mock_getenv.assert_called_once_with("TEST_VAR")
    assert result == "test_value"

def test_load_var_not_found(mock_load_dotenv, valid_handler, mock_getenv):
    # Arrange
    mock_getenv.return_value = None
    
    # Act & Assert
    with pytest.raises(EnvVariableNotFoundError):
        valid_handler.load_var("MISSING_VAR")

def test_load_var_empty(mock_load_dotenv, valid_handler, mock_getenv):
    # Arrange
    mock_getenv.return_value = ""
    
    # Act & Assert
    with pytest.raises(EnvVariableEmptyError):
        valid_handler.load_var("EMPTY_VAR")

def test_load_var_with_special_characters(mock_load_dotenv, valid_handler, mock_getenv):
    # Arrange
    var_name = "SPECIAL_!@#$%^&*()_VAR"
    mock_getenv.return_value = "special_value"
    
    # Act
    result = valid_handler.load_var(var_name)
    
    # Assert
    mock_getenv.assert_called_once_with(var_name)
    assert result == "special_value"

def test_load_multiple_vars(mock_load_dotenv, valid_handler, mock_getenv):
    # Arrange
    mock_getenv.side_effect = ["value1", "value2", "value3"]
    
    # Act
    result1 = valid_handler.load_var("VAR1")
    result2 = valid_handler.load_var("VAR2")
    result3 = valid_handler.load_var("VAR3")
    
    # Assert
    assert mock_getenv.call_count == 3
    assert result1 == "value1"
    assert result2 == "value2"
    assert result3 == "value3"

@patch.dict(os.environ, {"REAL_TEST_VAR": "real_value"})
def test_load_var_with_real_env_var():
    # Create a temporary .env file
    with tempfile.NamedTemporaryFile(mode='w', delete=False) as temp_env:
        temp_env.write("REAL_TEST_VAR=file_value\n")
        temp_env_path = temp_env.name
    
    try:
        # Using a real environment variable without mocking
        handler = EnvHandler(temp_env_path)
        
        # Act & Assert
        assert handler.load_var("REAL_TEST_VAR") == "real_value"
    finally:
        # Clean up
        os.unlink(temp_env_path)

def test_with_real_env_file():
    # Create a temporary .env file
    with tempfile.NamedTemporaryFile(mode='w', delete=False) as temp_env:
        temp_env.write("TEMP_TEST_VAR=temp_value\n")
        temp_env_path = temp_env.name
    
    try:
        # Test with the real file
        handler = EnvHandler(temp_env_path)
        assert handler._file_loaded is True
        assert handler.load_var("TEMP_TEST_VAR") == "temp_value"
    finally:
        # Clean up
        os.unlink(temp_env_path)

def test_load_var_unicode(mock_load_dotenv, valid_handler, mock_getenv):
    # Arrange
    mock_getenv.return_value = "值"  # Chinese character
    
    # Act
    result = valid_handler.load_var("UNICODE_VAR")
    
    # Assert
    assert result == "值"
    
def test_init_non_string_types():
    """Test that various non-string types raise TypeError."""
    non_string_values = [
        123,               # int
        3.14,              # float
        True,              # bool
        ["/path/to/env"],  # list
        {"/path/to/env"},  # set
        {"path": "/path/to/env"},  # dict
        None,              # None
        (),                # empty tuple
        bytes("path", "utf-8")  # bytes
    ]
    
    for value in non_string_values:
        with pytest.raises(TypeError):
            EnvHandler(value)

def test_load_var_with_whitespace(mock_load_dotenv, valid_handler, mock_getenv):
    """Test that whitespace in environment variable values is preserved."""
    mock_getenv.return_value = "  value with spaces  "
    result = valid_handler.load_var("WHITESPACE_VAR")
    assert result == "  value with spaces  "

def test_with_nonexistent_file():
    """Test with a file that doesn't exist."""
    with pytest.raises(EnvFileNotLoadedError):
        handler = EnvHandler("/path/that/does/not/exist")
        assert handler._file_loaded is False

def test_with_empty_env_file():
    """Test with an empty environment file."""
    with tempfile.NamedTemporaryFile(mode='w', delete=False) as temp_env:
        temp_env_path = temp_env.name
    
    with pytest.raises(EnvFileNotLoadedError):
        handler = EnvHandler(temp_env_path)
        assert handler._file_loaded is False
        handler.load_var("ANY_VAR")
    
    os.unlink(temp_env_path)

def test_with_malformed_env_file():
    with tempfile.NamedTemporaryFile(mode='w', delete=False) as temp_env:
        temp_env.write("DUPLICATE_KEY=value1\nDUPLICATE_KEY=value2\nINVALID_LINE\n")
        temp_env_path = temp_env.name
    
    try:
        handler = EnvHandler(temp_env_path)
        assert handler._file_loaded is True
        # Since dot-env typically uses the last value for duplicate keys
        assert handler.load_var("DUPLICATE_KEY") == "value2"
        # Test that invalid line raises an error
        with pytest.raises(EnvVariableNotFoundError):
            handler.load_var("INVALID_LINE")
    finally:
        os.unlink(temp_env_path)

def test_with_invalid_syntax_in_env_file():
    with tempfile.NamedTemporaryFile(mode='w', delete=False) as temp_env:
        temp_env.write("INVALID_LINE\nMISSING_EQUALS\nKEY_ONLY=\n")
        temp_env_path = temp_env.name
    
    try:
        handler = EnvHandler(temp_env_path)
        assert handler._file_loaded is True
        with pytest.raises(EnvVariableNotFoundError):
            handler.load_var("INVALID_LINE")
        with pytest.raises(EnvVariableNotFoundError):
            handler.load_var("MISSING_EQUALS")
        with pytest.raises(EnvVariableEmptyError):
            handler.load_var("KEY_ONLY")
    finally:
        os.unlink(temp_env_path)

def test_with_large_env_file():
    with tempfile.NamedTemporaryFile(mode='w', delete=False) as temp_env:
        for i in range(10000):
            temp_env.write(f"VAR{i}=value{i}\n")
        temp_env_path = temp_env.name
    
    try:
        handler = EnvHandler(temp_env_path)
        assert handler._file_loaded is True
        for i in range(10000):
            assert handler.load_var(f"VAR{i}") == f"value{i}"
    finally:
        os.unlink(temp_env_path)

def test_concurrent_variable_loading(mock_load_dotenv, valid_handler, mock_getenv):
    mock_getenv.return_value = "test_value"
    
    def load_var():
        assert valid_handler.load_var("TEST_VAR") == "test_value"
    
    threads = [threading.Thread(target=load_var) for _ in range(10)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join()