## 📦 Modules

### `custom_errors.py`
This module defines a collection of custom exceptions used throughout the project to handle specific error conditions in a clear and structured way.

**Classes:**

- `EnvFileNotLoadedError`: Raised when the `.env` file fails to load.
- `EnvVariableNotFoundError`: Raised when a required environment variable is missing.
- `EnvVariableEmptyError`: Raised when an environment variable exists but is empty.
- `SlackConnectionError`: Raised when there's a connection issue with Slack.
- `SlackMessageSendError`: Raised when sending a message to Slack fails.
- `SMTPConnectionError`: Raised when the SMTP connection could not be established.
- `SMTPAuthenticationError`: Raised when SMTP authentication fails.
- `NoClientsEstablishedError`: Raised when no messaging clients (Slack or SMTP) are configured.
- `NoCommunicationMethodEstablishedError`: Raised when neither Slack nor SMTP is available for communication.
- `InvalidLoggerError`: Raised when the logger setup is invalid.
- `InvalidEmailError`: Raised when an invalid email address is provided.
- `InvalidRecipientError`: Raised when an email is being sent to a recipient not in the approved list.

---

### `env_handler.py`
This module provides an `EnvHandler` class for robust management of environment variables loaded from a `.env` file. It integrates with the custom exceptions for error handling.

**Class: `EnvHandler`**

#### Methods:

- `__init__(env: str)`  
  Loads environment variables from the specified `.env` file.  
  **Raises:** `TypeError`, `EnvFileNotLoadedError`

- `load_var(var: str) -> str`  
  Fetches a specific variable from the environment.  
  **Raises:** `EnvVariableNotFoundError`, `EnvVariableEmptyError`

**Usage Example:**
```python
env_handler = EnvHandler(".env")
api_key = env_handler.load_var("API_KEY")
```

---

### `logger.py`
This module provides a custom logging utility for RINT projects. It allows writing structured log entries with controlled verbosity and thread-safe access to log files.

**Classes:**

- `LOGGING_CATEGORY`: Enum for log levels (`ERROR`, `WARNING`, `INFO`).
- `Logger`: Custom logger class supporting different verbosity levels and thread-safe logging.

**Logger Attributes:**

- `log_file (str)`: Path to the log file.
- `logging_level (int)`: Controls verbosity (`0` to `3`).

**Logger Methods:**

- `write_log(ar_name: str, category: LOGGING_CATEGORY, msg: str) -> bool`:  
  Writes a log entry to the file if it meets the logging level threshold.

**Usage Example:**
```python
logger = Logger("app.log", logging_level=2)
logger.write_log("MainModule", LOGGING_CATEGORY.ERROR, "An error occurred.")
```
---

### `slack_handler.py`

Handles integration with Slack for sending messages to a specified channel, using either direct parameters or values loaded from a `.env` file.

**Class: `SlackHandler`**

#### Attributes:
- `token (str, optional)`: Slack bot token. Can be passed directly or loaded from the `.env` file.
- `channel (str, optional)`: Slack channel name. Can be passed directly or loaded from the `.env` file.
- `env (str, optional)`: Relative path to the `.env` file. Default is `"env-files/slack.env"`.

#### Methods:
- `send_message(text: str)`: Sends the given message to the configured Slack channel.
- `get_channel() -> str`: Returns the currently set Slack channel name.

#### Exceptions Raised:
- `EnvFileNotLoadedError`: When the specified `.env` file is missing or invalid.
- `EnvVariableNotFoundError`: When required Slack environment variables are not found.
- `SlackConnectionError`: When the Slack client fails to connect or authenticate.
- `SlackMessageSendError`: When sending a message to the Slack channel fails.

#### Usage:
```python
slack = SlackHandler()
slack.send_message("Hello World.")
```

---

### `smtp_handler.py`

Provides the `MailHandler` class for sending emails via SMTP, supporting environment-based configuration and robust error handling.

---

#### **Class: `MailHandler`**

Handles SMTP configuration and message dispatch, supporting plain text, HTML, and file attachments.

##### **Constructor Parameters**:
- `env (str, optional)`: Relative path to the `.env` file (default: `"env-files/smtp.env"`).
- `smtp_server (str, optional)`: SMTP server address.
- `smtp_port (int, optional)`: SMTP server port (e.g., 465, 587).
- `user (str, optional)`: SMTP username.
- `password (str, optional)`: SMTP password.
- `sender (str, optional)`: Email address of the sender.
- `recipients (list[str], optional)`: List of recipient emails.

If any of the above are not provided, they will be loaded from the `.env` file.

---

##### **Methods**

- `send_mail(plain_msg=None, html_msg=None, subject="", recipients=None, attachments=[])`
    - Sends an email with plain text, HTML, or both.
    - **Parameters**:
        - `plain_msg (str, optional)`: Plain text content.
        - `html_msg (str, optional)`: HTML content.
        - `subject (str, optional)`: Subject line.
        - `recipients (list[str], optional)`: Override default recipient list.
        - `attachments (list[tuple[str, str, str]])`: List of attachments as `(filename, content, MIME type)`.

- `__send_mail(msg_obj, recipients)`
    - Internal helper to dispatch email using the SMTP server.

---

##### **Private Methods**
- `__check_mail(email: str)`
    - Validates the syntax of an email address.
- `__set_up_server()`
    - Establishes and authenticates a connection to the SMTP server using SSL/TLS or STARTTLS depending on port.

---

#### **Exception Handling**

- `EnvFileNotLoadedError`: `.env` file missing or invalid.
- `EnvVariableNotFoundError`: Required environment variable is missing.
- `EnvVariableEmptyError`: No email content provided.
- `InvalidEmailError`: Invalid email address format.
- `InvalidRecipientError`: Recipient not in allowed recipient list.
- `SMTPConnectionError`: SMTP connection or authentication failure.

---

#### **Usage Example**:
```python
from smtp_handler import MailHandler

mail_sender = MailHandler()
mail_sender.send_mail(
    plain_msg="Hello World.",
    subject="Test Email"
)
```

---

### `wazuh_api_handler.py`

Provides the `WazuhAPIHandler` class for interacting with the Wazuh API using authenticated HTTP GET requests.

---

#### **Class: `WazuhAPIHandler`**

A utility for authenticated communication with the Wazuh API, supporting custom headers and SSL verification.

##### **Constructor Parameters**
- `url (str)`: Base URL of the Wazuh API.
- `header (dict)`: HTTP headers to include in the request.
- `username (str)`: Username for basic authentication.
- `password (str)`: Password for basic authentication.
- `verify (str)`: Path to a CA_BUNDLE file or directory, or `False` to disable SSL verification.

Raises:
- `ValueError` if any parameter is of the wrong type.

---

##### **Methods**

- `change_header(header: dict) -> None`  
    Updates the headers used in the API requests.

    **Parameters**:
    - `header (dict)`: The new headers to set.

    **Raises**:
    - `ValueError` if `header` is not a dictionary.

- `get(query: dict) -> requests.Response`  
    Sends a GET request to the Wazuh API with the given query.

    **Parameters**:
    - `query (dict)`: Query parameters to send as JSON.

    **Returns**:
    - `requests.Response`: Response object from the API.

    **Raises**:
    - `ValueError` if `query` is not a dictionary.
    - `RuntimeError` if the request fails due to a network or HTTP error.

---

#### **Usage Example**
```python
from wazuh_api_handler import WazuhAPIHandler

handler = WazuhAPIHandler(
    url="https://wazuh.example.com:55000",
    header={"Content-Type": "application/json"},
    username="admin",
    password="secret",
    verify=False
)

# Send a GET request
response = handler.get({"pretty": "true"})
print(response.json())

# Change headers
handler.change_header({"Custom-Header": "Value"})
response = handler.get({"pretty": "false"})
print(response.json())
```

---