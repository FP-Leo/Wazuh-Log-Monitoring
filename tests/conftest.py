import sys
import os
import pytest
import tempfile

@pytest.fixture
def temp_env_file(request):
    """Fixture to create a temporary .env file for testing."""
    with tempfile.NamedTemporaryFile(delete=False) as temp_file:
        for key in request.param:
            temp_file.write(f"{key}={request.param[key]}\n".encode())
        temp_file_path = temp_file.name
    
    yield temp_file_path
    
    # Force cleanup to remove stale files
    if os.path.exists(temp_file_path):
        os.remove(temp_file_path)

@pytest.fixture()
def clear_env_variables():
    os.environ.clear()
    
