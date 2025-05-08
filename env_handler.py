#!/usr/bin/python3
import os
from dotenv import load_dotenv
from custom_errors import EnvFileNotLoadedError, EnvVariableEmptyError, EnvVariableNotFoundError

"""
A handler for managing environment variables loaded from .env files.
This class provides functionality to safely load .env files and retrieve
environment variables with appropriate error handling.
Attributes
----------
    _file_loaded : bool
        Indicates whether the .env file was successfully loaded.
    Parameters
----------
    env : str
        The file path to the .env file to be loaded.
    TypeError
        If the provided environment file path is not a string.
    EnvFileNotLoadedError
        If the .env file fails to load.
Examples
--------
>>> env_handler = EnvHandler(".env")
>>> api_key = env_handler.load_var("API_KEY")
"""

class EnvHandler:
    def __init__(self, env: str):
        """
        Initialize the environment handler by loading environment variables from a file.
        Parameters
        ----------
        env : str
            Path to the environment file (.env) to be loaded.
        Raises
        ------
        TypeError
            If the provided environment path is not a string.
        Returns
        -------
        None
            This method doesn't return anything but sets up the environment variables.
        Notes
        -----
        The method uses load_dotenv to load environment variables from the specified file.
        The _file_loaded attribute will contain the result of the load_dotenv operation.
        """
        if not isinstance(env, str):
            raise TypeError("Environment's File Path should be a string.")
        
        self._file_loaded = load_dotenv(env)

        if not self._file_loaded:
            raise EnvFileNotLoadedError("Failed to load .env file. Ensure the file exists and is correctly formatted.")

    # Function to load a variable from the .env file.
    def load_var(self, var: str):
        """
        Loads a variable from the .env file.

        Raises
        ------
        EnvFileNotLoadedError:
            If the .env file is missing or incorrectly formatted.
        EnvironmentVariableNotFoundError:
            If it fails to fetch the variable from the .env file.
        EnvVariableEmptyError:
            If the variable is empty.
        """
        value = os.getenv(var)

        if value is None:
            raise EnvVariableNotFoundError(f"Environment variable {var} is missing.")
        
        if value == "":
            raise EnvVariableEmptyError(f"Environment variable {var} is empty.")
        
        return value