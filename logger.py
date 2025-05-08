#!/usr/bin/python3
"""
    LOGGER

    This module provides a custom logging class for RINT projects. 

    Classes
    ----------
        LOGGING_CATEGORY: 
            Enum representing log levels (ERROR, WARNING, INFO).
        Logger: 
            Custom logger that writes logs to a file based on severity level.

    Usage
    ----------
    ```python
    logger = Logger("app.log", logging_level=2)
    logger.write_log("MainModule", LOGGING_CATEGORY.ERROR, "An error occurred.")
    ```
"""
from enum import Enum
import datetime
import os
import time
import threading

# Class Declaration Section
class LOGGING_CATEGORY(Enum):
    """Enum representing log categories for logging."""
    ERROR = 1
    WARNING = 2
    INFO = 3


class Logger:
    """
    A custom Logger made for RINT projects.

    Attributes
    ----------
    log_file: str
        Path to the log file.
    logging_level: int
        Determines the log detail level:
            0 - Don't log anything ( NOT RECOMMENDED)
            1 - Log only errors.
            2 - Log errors and warnings.
            3 - Log errors, warnings, and information.
    
    Methods
    -------
    write_log(ar_name: str, category: LOGGING_CATEGORY, msg:str)
        Writes a log entry to the log file.
    """

    def __init__(self, log_file: str, logging_level=1):
        """
        Initializes the logger.

        Parameters:
        ----------
        log_file: str
            Path to the log file.
        logging_level: int, optional
            Specifies log verbosity (default is 1).
        
        Raises
        ------
        ValueError
            If logging_level isn't an integer or if it's out of range.
        
        """
        acceptable_values = {0, 1, 2, 3}
        if not isinstance(logging_level, int) or logging_level not in acceptable_values:
            raise ValueError(f"Logging level must be one of {acceptable_values}.")
        
        if not isinstance(log_file, str) or not log_file:
            raise ValueError("Log file must be a non-empty string.")
        
        self.logging_level = logging_level
        self.log_file = log_file
        
        # Add lock for thread safety
        self._lock = threading.Lock()
        
        # Ensure the log file is writable
        self.__ensure_log_file()

    def __ensure_log_file(self):
        """
        Ensures the log file exists and is writable.
        
        Raises
        ------
        IOError
            If the log file can't be created or accessed.
        """
        with self._lock:
            try:
                if not os.path.exists(self.log_file):
                    with open(self.log_file, "w") as _:
                        pass  # Create empty file
            except Exception as e:
                raise IOError(f"Unable to access or create log file '{self.log_file}': {e}")

    # Function to write logs to file
    def write_log(self, ar_name: str, category: LOGGING_CATEGORY, msg:str):
        """
        Writes a log entry to the log file.

        Parameters:
        ----------
        ar_name: str
            The name of the module or function writing the log.
        category: LOGGING_CATEGORY
            The log category (ERROR, WARNING, INFO).
        msg: str
            The log message.

        Returns
        -------
        bool
            True if the log was written successfully, False otherwise.
        
        Raises
        ------
        ValueError
            If ar_name or msg is not a non-empty string, or if category is not a valid LOGGING_CATEGORY.
        PermissionError
            If the log file is locked by another process.
        Exception
            For any other exceptions that occur during logging.
        """
        if not isinstance(ar_name, str) or not ar_name:
            raise ValueError("ar_name must be a non-empty string.")

        if not isinstance(category, LOGGING_CATEGORY):
            raise ValueError("Invalid category. Must be an instance of LOGGING_CATEGORY.")
        
        if not isinstance(msg, str) or not msg:
            raise ValueError("msg must be a non-empty string.")
        
        if  self.logging_level == 0 or \
            (category == LOGGING_CATEGORY.WARNING and self.logging_level < 2) or \
            (category == LOGGING_CATEGORY.INFO and self.logging_level < 3):
            return False

        # Use lock to ensure thread-safe file access
        with self._lock:
            max_retries = 5
            retry_count = 0
            backoff_time = 0.1
            
            while retry_count < max_retries:
                try:
                    with open(self.log_file, mode="a+", encoding="utf-8") as log_file:
                        timestamp = datetime.datetime.now().strftime('%Y/%m/%d %H:%M:%S')
                        log_file.write(f"{timestamp} {ar_name}: {category.name} - {msg}\n")
                    return True # Successfully wrote to file
                except PermissionError:
                    # File might be locked by another process (not thread)
                    retry_count += 1
                    if retry_count >= max_retries:
                        raise PermissionError(f"Log file '{self.log_file}' is locked by another process.")
                    time.sleep(backoff_time)
                    backoff_time *= 2  # Exponential backoff
                except Exception as e:
                    raise e