#!/usr/bin/python3

class EnvFileNotLoadedError(Exception):
    """Custom error class to raise errors when the script fails to read .env file."""
    pass

class EnvVariableNotFoundError(Exception):
    """Custom error class to raise errors when a variable is not found in the .env file."""
    pass

class EnvVariableEmptyError(Exception):
    """Custom error class to raise errors when a variable is empty in the .env file."""
    pass

class SlackConnectionError(Exception):
    """Raised when there is an issue connecting to Slack (e.g., invalid token, network error)."""
    pass

class SlackMessageSendError(Exception):
    """Raised when there is an issue sending a message to the specified Slack channel."""
    pass

class SMTPConnectionError(Exception):
    """Custom error class to raise errors when the SMTP connection fails."""
    pass

class SMTPAuthenticationError(Exception):
    """Custom error class to raise errors when the SMTP authentication fails."""
    pass

class NoClientsEstablishedError(Exception):
    """Raised when no clients (Slack or SMTP) are established."""
    pass

class NoCommunicationMethodEstablishedError(Exception):
    """Raised when no communication method (Slack or SMTP) is established."""
    pass

class InvalidLoggerError(Exception):
    """Raised when the logger is not set up correctly."""
    pass

class InvalidEmailError(Exception):
    """Raised when the provided email address is invalid."""
    pass

class InvalidRecipientError(Exception):
    """Raised when an attempt is made to send an email to a recipient is not specified in the recipient list when creating MailHandler object."""
    pass