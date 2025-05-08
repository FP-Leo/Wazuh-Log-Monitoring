#!/usr/bin/python3
"""
slack_handler.py

This module provides the SlackHandler class for handling sending messages to Slack channel.
It supports loading configuration from a .env file and includes error handling
for various potential issues such as missing environment variables and Slack
connection errors.

Classes
----------
SlackHandler:
    Custom slack connector to establish connection with the provided token and channel or the ones fetched from the .env file.

Usage:
```python
slack = SlackHandler()
slack.send_message("Hello World.")
```

Exceptions:
-----------
EnvFileNotLoadedError
    Raised when the .env file is missing or incorrectly formatted.
EnvironmentVariableNotFoundError
    Raised when an environment variable is missing from the .env file.
SlackConnectionError
    Raised when there is an issue connecting to the Slack server.
SlackMessageSendError
    Raised when there is an issue sending a message to the Slack server.
"""

from slack_sdk import WebClient
from slack_sdk import errors
from dotenv import load_dotenv
import os
from custom_errors import (
    EnvFileNotLoadedError,
    EnvVariableNotFoundError,
    SlackConnectionError,
    SlackMessageSendError)
from env_handler import EnvHandler

class SlackHandler:
    """
    Custom slack connector to establish connection with the provided token and channel or the ones fetched from the .env file.
    
    Attributes
    ----------
    token: str
        It represents the token that is going to be used to establish connection to slack.
    channel: str
        It represents the channel that is going to recieve the texts after the connection is established.
    env: str
        It represents the path to the .env file that contains the token and channel information.

    Methods
    -------
    send_message(text: str):
        Sends the text to the specified channel using the already established connection.
    """
    def __init__(self, token: str | None = None, channel: str | None = None, env: str = "env-files/slack.env"):
        """
        Initializes the instance.

        Parameters:
        ----------
        token: str, optional
            The token that's going to be used for connecting to slack. If not provided it'll be fetched from the .env file.
        channel: str, optional
            The channel that's going to recieve the texts. If not provided it'll be fetched from the .env file.
        env: str, optional
            The path to the .env file. Must be relative (default is "env-files/slack.env"). Script uses os.path.join on os.getcwd and the env argument to create the full path.
        """
        self._token = token
        self._channel = channel
        
        try:
            full_path = os.path.join(os.getcwd(), env)
            try:
                self.EH = EnvHandler(env=full_path)
            except Exception as e:
                if not token or not channel:
                    raise e

            if self._token is None:
                self._token = self.EH.load_var("SLACK_TOKEN")
            
            if self._channel is None:
                self._channel = self.EH.load_var("SLACK_CHANNEL")
        except EnvFileNotLoadedError:
            if self._token is None or self._channel is None:
                raise EnvFileNotLoadedError(f"Env file not found at {env}. Please provide a valid path.")
        except EnvVariableNotFoundError as e:
            raise EnvVariableNotFoundError(f"Environment variable not found: {str(e)}")
    
        self._client = self.__establish_Slack_Connection()

    # Function to establish connection with slack.
    def __establish_Slack_Connection(self):
        """
        Establishes connection with Slack. 

        Raises
        ------
        SlackConnectionError:
            If it fails to connect to Slack or runs into an unexpected connection error.
        """      
        try:
            client = WebClient(token=self._token)
            client.auth_test()
            return client
        except errors.SlackApiError as e:
            raise SlackConnectionError(f"Failed to connect to Slack: {str(e)}")
        except Exception as e:
            raise SlackConnectionError(f"Unexpected connection error: {str(e)}")
    
    # Function to send a message to a SLACK channel.
    def send_message(self, text):
        """
        Sends the text to the specified channel.

        Raises
        ------
        SlackMessageSendError:
            If it fails to send the text or runs into an unexpected error.
        """      
        try:
            self._client.chat_postMessage(channel=self._channel, text=text)
        except errors.SlackApiError as e:
            raise SlackMessageSendError(f"Failed to send message to Slack: {str(e)}")
        except Exception as e:
            raise SlackMessageSendError(f"Unexpected error: {str(e)}")
        
    def get_channel(self):
        """
        Returns the channel name.

        Returns
        -------
        str
            The channel name.
        """
        return self._channel
