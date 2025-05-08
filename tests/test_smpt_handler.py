import pytest
from unittest.mock import MagicMock, patch
import os
import sys
import tempfile
import smtplib
from smtp_handler import MailHandler
from email import message_from_string
import random
import string
import threading
from unittest.mock import patch, MagicMock

# Add parent directory to path to import module
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from custom_errors import (EnvFileNotLoadedError, EnvVariableEmptyError, 
                            EnvVariableNotFoundError, InvalidEmailError, InvalidRecipientError, SMTPConnectionError)

# Test constants
TEST_SERVER = "test-smtp.example.com"
TEST_PORT = 587
TEST_USER = "test@example.com"
TEST_PASSWORD = "test-password"
TEST_SENDER = "from@example.com"
TEST_RECIPIENTS = ["to@example.com", "to2@example.com"]
TEST_SUBJECT = "Test Subject"
TEST_BODY = "Test email body"
ENV_SERVER = "env-smtp.example.com"
ENV_PORT = 465
ENV_USER = "env-user@example.com"
ENV_PASSWORD = "env-password"
ENV_SENDER = "env-from@example.com"
ENV_RECIPIENTS = "to@example.com, to2@example.com"

# General Functions

def generate_random_string(length):
    """Generate a random string of fixed length."""
    letters = string.ascii_letters + string.digits + string.punctuation
    return ''.join(random.choice(letters) for _ in range(length))

def generate_large_html(size_kb):
    """Generate large HTML content of approximately size_kb kilobytes."""
    # Basic HTML structure
    html_start = "<html><body><div>"
    html_end = "</div></body></html>"
    
    # Each paragraph is roughly 100 bytes
    paragraph = "<p>This is a test paragraph with some content to fill space.</p>"
    
    # Calculate how many paragraphs we need
    paragraphs_needed = (size_kb * 1024) // len(paragraph)
    
    return html_start + paragraph * paragraphs_needed + html_end

# Test fixtures
@pytest.fixture(autouse=True)
def clear_smpt_environment():
    """Clear all SMTP environment variables before each test."""
    env_vars = ["SMTP_SERVER", "SMTP_PORT", "USER", "PASSWORD", "SENDER", "RECIPIENTS"]
    for var in env_vars:
        os.environ.pop(var, None)

@pytest.fixture
def mock_smtp_client():
    with patch("smtp_handler.smtplib.SMTP") as mock_smtp:
        mock_client = MagicMock()
        mock_smtp.return_value = mock_client
        yield mock_smtp, mock_client

@pytest.fixture
def mock_smtp_ssl_client():
    with patch("smtp_handler.smtplib.SMTP_SSL") as mock_smtp_ssl:
        mock_client = MagicMock()
        mock_smtp_ssl.return_value = mock_client
        yield mock_smtp_ssl, mock_client

@pytest.fixture
def mock_load_dotenv():
    with patch("smtp.load_dotenv") as mock_load_dotenv:
        mock_load_dotenv.return_value = False
        yield mock_load_dotenv

@pytest.fixture
def default_env_file(request):
    """Fixture to create a default .env file for testing."""
    server = f"SMTP_SERVER={ENV_SERVER}"
    port = f"SMTP_PORT={ENV_PORT}"
    username = f"SMTP_USER={ENV_USER}"
    password = f"SMTP_PASSWORD={ENV_PASSWORD}"
    sender = f"SENDER={ENV_SENDER}"
    recipients = f"RECIPIENTS={ENV_RECIPIENTS}"

    if hasattr(request, "param"):
        # Override defaults if keys exist in the dictionary
        if "server" in request.param:
            server = f"SMTP_SERVER={request.param['server']}"
        
        if "port" in request.param:
            port = f"SMTP_PORT={request.param['port']}"
        
        if "username" in request.param:
            username = f"USER={request.param['username']}"
        
        if "password" in request.param:
            password = f"PASSWORD={request.param['password']}"

        if "sender" in request.param:
            sender = f"SENDER={request.param['sender']}"

        if "recipients" in request.param:
            recipients = f"RECIPIENTS={request.param['recipients']}"

    with tempfile.NamedTemporaryFile(delete=False, mode="w") as temp_file:
        temp_file.write(f"{server}\n")
        temp_file.write(f"{port}\n")
        temp_file.write(f"{username}\n")
        temp_file.write(f"{password}\n")
        temp_file.write(f"{sender}\n")
        temp_file.write(f"{recipients}\n")
        temp_file_path = temp_file.name
    
    yield temp_file_path

    if os.path.exists(temp_file_path):
        os.remove(temp_file_path)

@pytest.fixture
def large_binary_data():
    """Generate 5MB of random binary data."""
    return bytes(random.getrandbits(8) for _ in range(5 * 1024 * 1024))

# Test cases for __init__ when the environment file is not provided/loaded
def test_init_with_nonexistent_env_file():
    """Test initialization with non-existent env file."""
    with pytest.raises(EnvFileNotLoadedError):
        MailHandler(env="nonexistent_file.env")

def test_init_with_full_params_and_invalid_env_file(mock_smtp_client):
    """Test initialization with all params but missing env file."""
    mock_smtp, mock_client = mock_smtp_client

    smtp = MailHandler(smtp_server=TEST_SERVER, smtp_port=TEST_PORT, user=TEST_USER, 
                   password=TEST_PASSWORD, sender=TEST_SENDER, recipients=TEST_RECIPIENTS, env="nonexistent_file.env")
    
    assert smtp.smtp_server == TEST_SERVER
    assert smtp.smtp_port == TEST_PORT
    assert smtp.user == TEST_USER
    assert smtp.password == TEST_PASSWORD
    assert smtp.sender == TEST_SENDER
    assert smtp.recipients == TEST_RECIPIENTS
    
    mock_smtp.assert_called_once_with(TEST_SERVER, TEST_PORT)

@pytest.mark.parametrize(
    "init_kwargs",
    [
        {"smtp_server": TEST_SERVER, "smtp_port": TEST_PORT, "user": TEST_USER, "password": TEST_PASSWORD, "recipients": TEST_RECIPIENTS},  # Missing sender
        {"smtp_server": TEST_SERVER, "smtp_port": TEST_PORT, "user": TEST_USER, "sender": TEST_SENDER, "recipients": TEST_RECIPIENTS},    # Missing password
        {"smtp_server": TEST_SERVER, "smtp_port": TEST_PORT, "password": TEST_PASSWORD, "sender": TEST_SENDER, "recipients": TEST_RECIPIENTS},    # Missing user
        {"smtp_server": TEST_SERVER, "user": TEST_USER, "password": TEST_PASSWORD, "sender": TEST_SENDER, "recipients": TEST_RECIPIENTS},  # Missing smtp_port
        {"smtp_port": TEST_PORT, "user": TEST_USER, "password": TEST_PASSWORD, "sender": TEST_SENDER, "recipients": TEST_RECIPIENTS},  # Missing smtp_server
        {"smtp_port": TEST_PORT, "user": TEST_USER, "password": TEST_PASSWORD, "sender": TEST_SENDER},  # Missing recipients
        {},                                                                                            # All missing
    ]
)
def test_init_with_incomplete_params_and_invalid_env_file(init_kwargs):
    """Test initialization with missing params and missing env file."""
    with pytest.raises((EnvFileNotLoadedError, EnvVariableEmptyError, EnvVariableNotFoundError)):
        smtp = MailHandler(**init_kwargs, env="nonexistent_file.env")

@pytest.mark.parametrize("default_env_file", [
    {"sender": "test@example.com", "recipients": "test2@example.com,test"},
    {"sender": "testexample.com", "recipients": "valid@example.com"},  # Missing @ in sender
    {"sender": "test@", "recipients": "valid@example.com"},  # Missing domain in sender
    {"sender": "@example.com", "recipients": "valid@example.com"},  # Missing username in sender
    {"sender": "test@example", "recipients": "valid@example.com"},  # Missing TLD in sender domain
    {"sender": "test@example.com", "recipients": "testexample.com"},  # Missing @ in recipient
    {"sender": "test@example.com", "recipients": "test@,valid@example.com"},  # Missing domain in one recipient
    {"sender": "test@example.com", "recipients": "@example.com,valid@example.com"},  # Missing username in one recipient
    {"sender": "test@@example.com", "recipients": "valid@example.com"},  # Multiple @ in sender
    {"sender": "test@example.com", "recipients": "valid@@example.com"},  # Multiple @ in recipient
    {"sender": "test@example.com", "recipients": "valid@example.com,"},  # Empty recipient in list
    {"sender": "test<>@example.com", "recipients": "valid@example.com"},  # Invalid chars in sender
    {"sender": "test@example.com", "recipients": "valid+invalid@example.com, test!@example.com"}  # Invalid chars in recipients
    ], indirect=True)
def test_init_with_invalid_email_format(default_env_file):
    """Test initialization with invalid email format."""
    with pytest.raises(InvalidEmailError):
        MailHandler(env=default_env_file)

@pytest.mark.parametrize("sender,recipients", [
    ("simple@example.com", ["recipient@example.com"]),
    ("name.surname@example.com", ["first.last@example.com"]),
    ("email@subdomain.example.com", ["user@host.subdomain.example.com"]),
    ("firstname+tag@example.com", ["name+label@example.com"]),
    ("email@[123.123.123.123]", ["user@[IPv6:2001:db8::1]"]),
    ("email@example-one.com", ["user@example-domain.com"]),
    ("_______@example.com", ["user_name@example.com"]),
    ("email@example.name", ["user@example.tokyo"]),
    ("email@example.museum", ["user@example.travel"]),
    ("email@example.co.jp", ["user@example.org.uk"])
])
def test_init_with_valid_email_format(mock_smtp_client, sender, recipients):
    """Test initialization with valid email formats."""
    mock_smtp, mock_client = mock_smtp_client
    
    # Should initialize without raising exceptions
    mail = MailHandler(
        smtp_server=TEST_SERVER, 
        smtp_port=TEST_PORT, 
        user=TEST_USER, 
        password=TEST_PASSWORD, 
        sender=sender,
        recipients=recipients
    )
    
    assert mail.sender == sender
    assert mail.recipients == recipients
    mock_smtp.assert_called_once_with(TEST_SERVER, TEST_PORT)

# Test initialization with complete environment file
def test_init_with_env_file_only(mock_smtp_ssl_client, default_env_file):
    """Test initialization with only environment file."""
    mock_smtp, mock_client = mock_smtp_ssl_client
    
    smtp = MailHandler(env=default_env_file)
    
    assert smtp.smtp_server == ENV_SERVER
    assert smtp.smtp_port == ENV_PORT
    assert smtp.user == ENV_USER
    assert smtp.password == ENV_PASSWORD
    assert smtp.sender == ENV_SENDER
    assert smtp.recipients == TEST_RECIPIENTS
    mock_smtp.assert_called_once_with(ENV_SERVER, ENV_PORT)

# Test parameter overrides of environment variables
def test_init_params_override_env_vars(mock_smtp_client, default_env_file):
    """Test that provided parameters override environment variables."""
    mock_smtp, mock_client = mock_smtp_client
    
    smtp = MailHandler(
        smtp_server=TEST_SERVER, 
        smtp_port=TEST_PORT, 
        user=TEST_USER, 
        password=TEST_PASSWORD, 
        sender=TEST_SENDER,
        recipients=TEST_RECIPIENTS,
        env=default_env_file
    )
    
    assert smtp.smtp_server == TEST_SERVER
    assert smtp.smtp_port == TEST_PORT
    assert smtp.user == TEST_USER
    assert smtp.password == TEST_PASSWORD
    assert smtp.sender == TEST_SENDER
    assert smtp.recipients == TEST_RECIPIENTS
    mock_smtp.assert_called_once_with(TEST_SERVER, TEST_PORT)

# Test connection methods
@pytest.mark.parametrize("default_env_file", [{"port": "587"}], indirect=True)
def test_tls_connection(mock_smtp_client, default_env_file):
    """Test TLS connection for port 587."""
    mock_smtp, mock_client = mock_smtp_client
    
    smtp = MailHandler(env=default_env_file)
    
    mock_smtp.assert_called_once_with(ENV_SERVER, 587)
    mock_client.starttls.assert_called_once()
    mock_client.login.assert_called_once_with(ENV_USER, ENV_PASSWORD)

@pytest.mark.parametrize("default_env_file", [{"port": "465"}], indirect=True)
def test_ssl_connection(mock_smtp_ssl_client, default_env_file):
    """Test SSL connection for port 465."""
    mock_smtp_ssl, mock_client = mock_smtp_ssl_client
    
    smtp = MailHandler(env=default_env_file)
    
    mock_smtp_ssl.assert_called_once_with(ENV_SERVER, 465)
    mock_client.login.assert_called_once_with(ENV_USER, ENV_PASSWORD)

# Test connection errors
@pytest.mark.parametrize("default_env_file", [{"port": "587"}], indirect=True)
def test_connection_error(mock_smtp_client, default_env_file):
    """Test SMTPConnectionError is raised when connection fails."""
    mock_smtp, mock_client = mock_smtp_client
    mock_smtp.side_effect = smtplib.SMTPConnectError(1, "Connection error")
    
    with pytest.raises(SMTPConnectionError):
        MailHandler(env=default_env_file)

def test_authentication_error(mock_smtp_ssl_client, default_env_file):
    """Test SMTPConnectionError is raised when authentication fails."""
    mock_smtp, mock_client = mock_smtp_ssl_client
    mock_client.login.side_effect = smtplib.SMTPAuthenticationError(535, "Authentication failed")
    
    with pytest.raises(SMTPConnectionError):
        MailHandler(env=default_env_file)

# Test send_mail functionality using create_mail and individual recipient logic
def test_send_email_success(mock_smtp_ssl_client, default_env_file):
    """Test successful email sending using send_mail."""
    mock_smtp, mock_client = mock_smtp_ssl_client

    smtp = MailHandler(env=default_env_file)

    result = smtp.send_mail(plain_msg=TEST_BODY, recipients=TEST_RECIPIENTS)

    mock_client.sendmail.call_count == len(TEST_RECIPIENTS)
    assert result == TEST_RECIPIENTS

    # Get the actual message string from the first call to sendmail
    args, kwargs = mock_client.sendmail.call_args
    raw_msg = args[2]  # This is the raw string sent

    # Parse it into an email.message.EmailMessage object
    msg = message_from_string(raw_msg)

    # Ensure it's multipart and contains both plain and HTML parts
    assert msg.is_multipart()

    payloads = msg.get_payload()
    content_types = [part.get_content_type() for part in payloads]

    assert "text/plain" in content_types
    
def test_send_mail_single_recipient(mock_smtp_ssl_client, default_env_file):
    """Test the _send_mail method with a single recipient."""
    mock_smtp, mock_client = mock_smtp_ssl_client
    
    smtp = MailHandler(env=default_env_file)
    
    # Call _send_mail with a single recipient
    recipient = TEST_RECIPIENTS[0]
    result = smtp.send_mail(plain_msg=TEST_BODY, recipients=recipient)
    
    # Assert that the email was sent successfully
    assert len(result) == 1
    assert result[0] == recipient
    mock_client.sendmail.assert_called_once()

def test_send_email_error(mock_smtp_ssl_client, default_env_file):
    """Test SMTPConnectionError is raised when email sending fails."""
    mock_smtp, mock_client = mock_smtp_ssl_client
    mock_client.sendmail.side_effect = smtplib.SMTPException("Failed to send email")
    
    smtp = MailHandler(env=default_env_file)

    with pytest.raises(SMTPConnectionError):
        smtp.send_mail(plain_msg=TEST_BODY, recipients=TEST_RECIPIENTS)

def test_send_html_email(mock_smtp_ssl_client, default_env_file):
    """Test sending HTML email."""
    mock_smtp, mock_client = mock_smtp_ssl_client
    
    html_content = "<html><body><h1>Test HTML Email</h1><p>This is a test.</p></body></html>"
    
    smtp = MailHandler(env=default_env_file)

    result = smtp.send_mail(html_msg=html_content, recipients=TEST_RECIPIENTS)

    assert mock_client.sendmail.call_count == len(TEST_RECIPIENTS)
    assert result == TEST_RECIPIENTS

    # Get the actual message string from the first call to sendmail
    args, kwargs = mock_client.sendmail.call_args
    raw_msg = args[2]  # This is the raw string sent

    # Parse it into an email.message.EmailMessage object
    msg = message_from_string(raw_msg)

    # Ensure it's multipart and contains HTML parts
    assert msg.is_multipart()

    payloads = msg.get_payload()
    content_types = [part.get_content_type() for part in payloads]

    assert "text/html" in content_types

def test_email_headers_and_encoding(mock_smtp_ssl_client, default_env_file):
    mock_smtp, mock_client = mock_smtp_ssl_client
    smtp = MailHandler(env=default_env_file)
    
    result = smtp.send_mail(
        plain_msg="Test body",
        subject="Test subject",
        recipients=TEST_RECIPIENTS
    )
    
    args, kwargs = mock_client.sendmail.call_args
    raw_msg = args[2]
    msg = message_from_string(raw_msg)
    
    # Validate headers
    assert msg["Subject"] == "Test subject"
    assert msg["From"] == ENV_SENDER
    assert msg["To"] == ", ".join(TEST_RECIPIENTS)
    
    # Validate encoding
    assert "Content-Transfer-Encoding" in raw_msg

def test_multipart_email_content(mock_smtp_ssl_client, default_env_file):
    mock_smtp, mock_client = mock_smtp_ssl_client

    smtp = MailHandler(env=default_env_file)

    html_content = "<html><body><p>This is HTML</p></body></html>"
    text_content = "This is plain text"

    result = smtp.send_mail(plain_msg=text_content, html_msg=html_content, recipients=TEST_RECIPIENTS)
    assert result == TEST_RECIPIENTS
    assert mock_client.sendmail.call_count == len(TEST_RECIPIENTS)

    # Get the actual message string from the first call to sendmail
    args, kwargs = mock_client.sendmail.call_args
    raw_msg = args[2]  # This is the raw string sent

    # Parse it into an email.message.EmailMessage object
    msg = message_from_string(raw_msg)

    # Ensure it's multipart and contains both plain and HTML parts
    assert msg.is_multipart()

    payloads = msg.get_payload()
    content_types = [part.get_content_type() for part in payloads]

    assert "text/plain" in content_types
    assert "text/html" in content_types

def test_email_subject_and_body_parsing(mock_smtp_ssl_client, default_env_file):
    """Test how email subjects and bodies are parsed and processed."""
    mock_smtp, mock_client = mock_smtp_ssl_client
    
    smtp = MailHandler(env=default_env_file)
    
    # Test case 1: Basic subject and body
    subject = "Test Subject"
    body = "This is the body text"
    
    result = smtp.send_mail(
        subject=subject,
        plain_msg=body, 
        recipients=TEST_RECIPIENTS
    )
    
    args, kwargs = mock_client.sendmail.call_args
    raw_msg = args[2]
    msg = message_from_string(raw_msg)
    
    assert msg["Subject"] == subject
    assert body in raw_msg
    
    # Reset the mock
    mock_client.reset_mock()
    
    # Test case 2: Subject with special characters
    special_subject = "Special Chars: äöü €$¥"
    body = "Regular body"
    
    result = smtp.send_mail(
        subject=special_subject,
        plain_msg=body, 
        recipients=TEST_RECIPIENTS
    )
    
    args, kwargs = mock_client.sendmail.call_args
    raw_msg = args[2]
    msg = message_from_string(raw_msg)
    
    # The subject might be encoded in the raw message
    assert msg["Subject"] is not None
    assert body in raw_msg
    
    # Reset the mock
    mock_client.reset_mock()
    
    # Test case 3: Body with newlines and formatting
    subject = "Formatted Body Test"
    body = "Line 1\nLine 2\n\nParagraph 2\n    Indented line"
    
    result = smtp.send_mail(
        subject=subject,
        plain_msg=body, 
        recipients=TEST_RECIPIENTS
    )
    
    args, kwargs = mock_client.sendmail.call_args
    raw_msg = args[2]
    
    # Check if body formatting is preserved in some form
    assert "Line 1" in raw_msg
    assert "Line 2" in raw_msg
    assert "Paragraph 2" in raw_msg
    assert "Indented line" in raw_msg


@pytest.mark.parametrize("temp_env_file,expected_exception", [
    # Missing required variables
    ({"SMTP_SERVER": "test@gmail.com", "SMTP_PORT": "587"}, EnvVariableNotFoundError),

    # No values
    ({"SMTP_SERVER": "", "SMTP_PORT": ""}, EnvVariableEmptyError),

    # Completely malformed
    ({"": "!!!bad_line@@@", "": "another bad line"}, EnvFileNotLoadedError),

    # Port not a number
    ({"SMTP_SERVER": "test@gmail.com", "SMTP_PORT": "fiveeightseven"}, ValueError),
], indirect=["temp_env_file"]) 
def test_init_with_various_malformed_env_files(temp_env_file, expected_exception):
    """Test initialization with various malformed .env file contents."""
    with pytest.raises(expected_exception):
        MailHandler(env=temp_env_file)

# Tests for valid and invalid recipient subsets

def test_send_to_valid_subset_of_recipients(mock_smtp_ssl_client, default_env_file):
    """Test sending to a valid subset of the initialized recipients."""
    mock_smtp, mock_client = mock_smtp_ssl_client
    
    # Initialize with multiple recipients
    smtp = MailHandler(env=default_env_file)
    
    # Send to only the first recipient
    subset = [TEST_RECIPIENTS[0]]
    result = smtp.send_mail(plain_msg=TEST_BODY, recipients=subset)
    
    # Should succeed with just the subset
    assert result == subset
    assert mock_client.sendmail.call_count == 1
    args = mock_client.sendmail.call_args
    assert args[0][1] == subset[0]

def test_send_to_single_recipient_as_string(mock_smtp_ssl_client, default_env_file):
    """Test sending to a single recipient specified as a string."""
    mock_smtp, mock_client = mock_smtp_ssl_client
    
    smtp = MailHandler(env=default_env_file)
    
    # Send to only the first recipient as a string
    single_recipient = TEST_RECIPIENTS[0]
    result = smtp.send_mail(plain_msg=TEST_BODY, recipients=single_recipient)
    
    # Should succeed with just the one recipient
    assert result == [single_recipient]
    assert mock_client.sendmail.call_count == 1
    args = mock_client.sendmail.call_args
    assert args[0][1] == single_recipient

def test_send_to_single_recipient_as_list(mock_smtp_ssl_client, default_env_file):
    """Test sending to a single recipient specified as a list."""
    mock_smtp, mock_client = mock_smtp_ssl_client
    
    smtp = MailHandler(env=default_env_file)
    
    # Send to only the first recipient in a list
    single_recipient_list = [TEST_RECIPIENTS[0]]
    result = smtp.send_mail(plain_msg=TEST_BODY, recipients=single_recipient_list)
    
    assert result == single_recipient_list
    assert mock_client.sendmail.call_count == 1
    args = mock_client.sendmail.call_args
    assert args[0][1] == single_recipient_list[0]

def test_send_to_invalid_recipient(mock_smtp_ssl_client, default_env_file):
    """Test sending to a recipient not in the initialized list."""
    mock_smtp, mock_client = mock_smtp_ssl_client
    
    smtp = MailHandler(env=default_env_file)
    
    invalid_recipient = "invalid@example.com"
    
    # Should raise an error because recipient is not in the initialized list
    with pytest.raises(InvalidRecipientError):
        smtp.send_mail(plain_msg=TEST_BODY, recipients=invalid_recipient)

def test_send_to_mixed_valid_invalid_recipients(mock_smtp_ssl_client, default_env_file):
    """Test sending to a mix of valid and invalid recipients."""
    mock_smtp, mock_client = mock_smtp_ssl_client
    
    smtp = MailHandler(env=default_env_file)
    
    valid_recipient = TEST_RECIPIENTS[0]
    invalid_recipient = "invalid@example.com"
    
    # Should raise an error because not all recipients are valid
    with pytest.raises(InvalidRecipientError):
        smtp.send_mail(plain_msg=TEST_BODY, recipients=[valid_recipient, invalid_recipient])

def test_recipients_with_whitespace(mock_smtp_ssl_client, default_env_file):
    """Test sending to recipients with extra whitespace that should be trimmed."""
    mock_smtp, mock_client = mock_smtp_ssl_client
    
    smtp = MailHandler(env=default_env_file)
    
    # Recipients with extra whitespace
    whitespace_recipients = [f" {TEST_RECIPIENTS[0]} ", f"\t{TEST_RECIPIENTS[1]}\t"]
    
    # Should succeed as whitespace is trimmed
    result = smtp.send_mail(plain_msg=TEST_BODY, recipients=whitespace_recipients)
    
    # Check trimmed recipients are returned
    assert result == TEST_RECIPIENTS
    assert mock_client.sendmail.call_count == 2

@pytest.mark.parametrize("default_env_file", [{"recipients": "to@example.com, to@example.com"}], indirect=True)
def test_recipients_with_duplicates(mock_smtp_ssl_client, default_env_file):
    """Test initialization with duplicate recipients."""
    mock_smtp, mock_client = mock_smtp_ssl_client
    
    smtp = MailHandler(env=default_env_file)
    
    # Should work with duplicates in the list
    result = smtp.send_mail(plain_msg=TEST_BODY)
    
    # There should be just one unique recipient
    assert len(result) == 1
    assert result == ["to@example.com"]
    assert mock_client.sendmail.call_count == 1

def test_recipients_with_invalid_email_format(mock_smtp_ssl_client):
    """Test initialization with invalid email format."""
    mock_smtp, mock_client = mock_smtp_ssl_client
    
    # Try to initialize with an invalid email format
    with pytest.raises(InvalidEmailError):
        MailHandler(
            smtp_server=TEST_SERVER, 
            smtp_port=TEST_PORT, 
            user=TEST_USER, 
            password=TEST_PASSWORD, 
            sender=TEST_SENDER,
            recipients=["invalid-email-format"]
        )

def test_send_to_recipient_not_in_original_list_with_valid_email(mock_smtp_ssl_client, default_env_file):
    """Test sending to a recipient not in the original list but with valid email format."""
    mock_smtp, mock_client = mock_smtp_ssl_client
    
    smtp = MailHandler(env=default_env_file)
    
    # Try to send to a new recipient with valid email format
    new_recipient = "new.valid@example.com"
    
    with pytest.raises(InvalidRecipientError):
        smtp.send_mail(plain_msg=TEST_BODY, recipients=new_recipient)

def test_send_email_with_empty_recipient_list_valid_env(mock_smtp_ssl_client, default_env_file):
    smtp = MailHandler(env=default_env_file)

    result = smtp.send_mail(plain_msg=TEST_BODY, recipients=[])

    assert result == TEST_RECIPIENTS

@pytest.mark.parametrize("default_env_file", [{"recipients": ""}], indirect=True)
def test_send_email_with_empty_recipient_list_invalid_env(mock_smtp_ssl_client, default_env_file):
    with pytest.raises(EnvVariableEmptyError):
        smtp = MailHandler(env=default_env_file)

def test_create_mail_with_no_body(mock_smtp_ssl_client, default_env_file):
    smtp = MailHandler(env=default_env_file)

    with pytest.raises(EnvVariableEmptyError):
        result = smtp.send_mail(subject=TEST_SUBJECT, recipients=TEST_RECIPIENTS)

def test_send_email_with_subject_and_plain_msg_only(mock_smtp_ssl_client, default_env_file):
    """Test sending an email with only a subject and plain text message."""
    mock_smtp, mock_client = mock_smtp_ssl_client
    
    smtp = MailHandler(env=default_env_file)
    
    result = smtp.send_mail(subject=TEST_SUBJECT, plain_msg=TEST_BODY, recipients=TEST_RECIPIENTS)
    
    assert result == TEST_RECIPIENTS
    assert mock_client.sendmail.call_count == len(TEST_RECIPIENTS)
    
    # Get the actual message string from the first call to sendmail
    args, kwargs = mock_client.sendmail.call_args
    raw_msg = args[2]  # This is the raw string sent
    
    # Parse it into an email.message.EmailMessage object
    msg = message_from_string(raw_msg)
    
    # Check subject
    assert msg["Subject"] == TEST_SUBJECT
    
    # Ensure it contains only plain text part (no HTML)
    payloads = msg.get_payload()
    content_types = [part.get_content_type() for part in payloads]

    assert "text/plain" in content_types
    assert "Content-Type: text/html" not in content_types
    # Verify the body content
    assert TEST_BODY in raw_msg

def test_send_email_with_subject_and_html_msg_only(mock_smtp_ssl_client, default_env_file):
    """Test sending an email with only a subject and HTML message."""
    mock_smtp, mock_client = mock_smtp_ssl_client
    
    smtp = MailHandler(env=default_env_file)
    
    html_content = "<html><body><h1>Test HTML Email</h1><p>This is a test.</p></body></html>"
    
    result = smtp.send_mail(subject=TEST_SUBJECT, html_msg=html_content, recipients=TEST_RECIPIENTS)
    
    assert result == TEST_RECIPIENTS
    assert mock_client.sendmail.call_count == len(TEST_RECIPIENTS)
    
    # Get the actual message string from the first call to sendmail
    args, kwargs = mock_client.sendmail.call_args
    raw_msg = args[2]  # This is the raw string sent
    
    # Parse it into an email.message.EmailMessage object
    msg = message_from_string(raw_msg)
    
    # Check subject
    assert msg["Subject"] == TEST_SUBJECT
    
    # Ensure it contains only HTML part (no plain text)
    payloads = msg.get_payload()
    content_types = [part.get_content_type() for part in payloads]
    
    assert "text/html" in content_types
    assert "text/plain" not in content_types
    
    # Verify the body content contains HTML
    assert html_content in raw_msg

def test_send_email_with_subject_and_both_msg_types(mock_smtp_ssl_client, default_env_file):
    """Test sending an email with subject, plain text, and HTML message."""
    mock_smtp, mock_client = mock_smtp_ssl_client

    smtp = MailHandler(env=default_env_file)

    html_content = "<html><body><h1>Test HTML Email</h1><p>This is a test.</p></body></html>"
    plain_content = "This is a plain text message for testing"

    result = smtp.send_mail(
        subject=TEST_SUBJECT, 
        plain_msg=plain_content, 
        html_msg=html_content, 
        recipients=TEST_RECIPIENTS
    )

    assert result == TEST_RECIPIENTS
    assert mock_client.sendmail.call_count == len(TEST_RECIPIENTS)

    # Get the actual message string from the first call to sendmail
    args, kwargs = mock_client.sendmail.call_args
    raw_msg = args[2]  # This is the raw string sent

    # Parse it into an email.message.EmailMessage object
    msg = message_from_string(raw_msg)

    # Check subject
    assert msg["Subject"] == TEST_SUBJECT

    # Ensure it contains both plain text and HTML parts
    assert msg.is_multipart()
    payloads = msg.get_payload()
    content_types = [part.get_content_type() for part in payloads]

    assert "text/plain" in content_types
    assert "text/html" in content_types

    # Verify the body content
    assert plain_content in raw_msg
    assert html_content in raw_msg

def test_send_email_with_single_attachment(mock_smtp_ssl_client, default_env_file):
    """Test sending an email with a single attachment."""
    mock_smtp, mock_client = mock_smtp_ssl_client
    
    smtp = MailHandler(env=default_env_file)
    
    # Create a simple text attachment
    filename = "test.txt"
    content = "This is a test attachment content"
    mime_type = "text/plain"
    
    result = smtp.send_mail(
        plain_msg=TEST_BODY,
        subject=TEST_SUBJECT,
        recipients=TEST_RECIPIENTS,
        attachments=[(filename, content, mime_type)]
    )
    
    assert result == TEST_RECIPIENTS
    assert mock_client.sendmail.call_count == len(TEST_RECIPIENTS)
    
    # Get the actual message string from the first call to sendmail
    args, kwargs = mock_client.sendmail.call_args
    raw_msg = args[2]
    
    # Check the message contains attachment headers
    assert f"Content-Disposition: attachment; filename={filename}" in raw_msg
    assert "Content-Type: text/plain" in raw_msg

def test_send_email_with_multiple_attachments(mock_smtp_ssl_client, default_env_file):
    """Test sending an email with multiple attachments."""
    mock_smtp, mock_client = mock_smtp_ssl_client
    
    smtp = MailHandler(env=default_env_file)
    
    # Create multiple attachments with different types
    attachments = [
        ("doc.txt", "Text document content", "text/plain"),
        ("data.csv", "col1,col2\nval1,val2", "text/csv"),
        ("config.json", '{"setting": "value"}', "application/json")
    ]
    
    result = smtp.send_mail(
        plain_msg=TEST_BODY,
        subject=TEST_SUBJECT,
        recipients=TEST_RECIPIENTS,
        attachments=attachments
    )
    
    assert result == TEST_RECIPIENTS
    assert mock_client.sendmail.call_count == len(TEST_RECIPIENTS)
    
    # Get the actual message string
    args, kwargs = mock_client.sendmail.call_args
    raw_msg = args[2]
    
    # Check all attachments are in the message
    for filename, _, mime_type in attachments:
        assert f"Content-Disposition: attachment; filename={filename}" in raw_msg
        main_type, sub_type = mime_type.split("/")
        assert f"Content-Type: {main_type}/{sub_type}" in raw_msg

def test_send_email_with_binary_attachment(mock_smtp_ssl_client, default_env_file):
    """Test sending an email with a binary attachment."""
    mock_smtp, mock_client = mock_smtp_ssl_client
    
    smtp = MailHandler(env=default_env_file)
    
    # Create a binary attachment (simulate image data)
    filename = "image.png"
    # Some binary data for testing
    binary_content = b'\x89PNG\r\n\x1a\n\x00\x00\x00\rIHDR\x00\x00'
    mime_type = "image/png"
    
    result = smtp.send_mail(
        plain_msg=TEST_BODY,
        subject=TEST_SUBJECT,
        recipients=TEST_RECIPIENTS,
        attachments=[(filename, binary_content, mime_type)]
    )
    
    assert result == TEST_RECIPIENTS
    
    # Get the message
    args, kwargs = mock_client.sendmail.call_args
    raw_msg = args[2]
    
    # Check for attachment headers
    assert f"Content-Disposition: attachment; filename={filename}" in raw_msg
    assert "Content-Type: image/png" in raw_msg
    
    # Check for base64 encoded content (not exact binary match)
    assert "Content-Transfer-Encoding: base64" in raw_msg

def test_send_email_with_html_and_attachments(mock_smtp_ssl_client, default_env_file):
    """Test sending an HTML email with attachments."""
    mock_smtp, mock_client = mock_smtp_ssl_client
    
    smtp = MailHandler(env=default_env_file)
    
    html_content = "<html><body><h1>Test with Attachments</h1></body></html>"
    attachment = ("report.pdf", b'%PDF-1.5 fake pdf content', "application/pdf")
    
    result = smtp.send_mail(
        html_msg=html_content,
        subject=TEST_SUBJECT,
        recipients=TEST_RECIPIENTS,
        attachments=[attachment]
    )
    
    assert result == TEST_RECIPIENTS
    
    args, kwargs = mock_client.sendmail.call_args
    raw_msg = args[2]
    
    # Check both HTML content and attachment are present
    assert "Content-Type: text/html" in raw_msg
    assert html_content in raw_msg
    assert "Content-Type: application/pdf" in raw_msg
    assert f"Content-Disposition: attachment; filename={attachment[0]}" in raw_msg

def test_send_email_with_plain_html_and_attachments(mock_smtp_ssl_client, default_env_file):
    """Test sending an email with plain text, HTML content and attachments."""
    mock_smtp, mock_client = mock_smtp_ssl_client
    
    smtp = MailHandler(env=default_env_file)
    
    plain_text = "Plain text version"
    html_content = "<html><body><h1>HTML version</h1></body></html>"
    attachments = [
        ("doc1.txt", "Text content", "text/plain"),
        ("doc2.xlsx", b'binary excel data', "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet")
    ]
    
    result = smtp.send_mail(
        plain_msg=plain_text,
        html_msg=html_content,
        subject=TEST_SUBJECT,
        recipients=TEST_RECIPIENTS,
        attachments=attachments
    )
    
    assert result == TEST_RECIPIENTS
    
    args, kwargs = mock_client.sendmail.call_args
    raw_msg = args[2]
    
    # Check all content types are present
    assert "Content-Type: text/plain" in raw_msg
    assert "Content-Type: text/html" in raw_msg
    assert plain_text in raw_msg
    assert html_content in raw_msg
    
    # Check both attachments
    for filename, _, mime_type in attachments:
        assert f"Content-Disposition: attachment; filename={filename}" in raw_msg
        main_type, sub_type = mime_type.split("/")
        assert f"Content-Type: {main_type}" in raw_msg and sub_type in raw_msg
        # Stress tests for MailHandler

# Test with large text content
def test_send_email_with_large_text_content(mock_smtp_ssl_client, default_env_file):
    """Test sending an email with a very large text body (1MB)."""
    mock_smtp, mock_client = mock_smtp_ssl_client
    
    smtp = MailHandler(env=default_env_file)
    
    # Generate 1MB of text
    large_text = generate_random_string(1024 * 1024)  # 1MB
    
    result = smtp.send_mail(
        plain_msg=large_text,
        subject="Large Text Email",
        recipients=TEST_RECIPIENTS
    )
    
    assert result == TEST_RECIPIENTS
    assert mock_client.sendmail.call_count == len(TEST_RECIPIENTS)
    
    # Check that the call was made with a large payload
    args, kwargs = mock_client.sendmail.call_args
    assert len(args[2]) > 1024 * 1024  # Message should be at least 1MB

# Test with large HTML content
def test_send_email_with_large_html_content(mock_smtp_ssl_client, default_env_file):
    """Test sending an email with very large HTML content (2MB)."""
    mock_smtp, mock_client = mock_smtp_ssl_client
    
    smtp = MailHandler(env=default_env_file)
    
    # Generate 2MB of HTML
    large_html = generate_large_html(2048)  # 2MB
    
    result = smtp.send_mail(
        html_msg=large_html,
        subject="Large HTML Email",
        recipients=TEST_RECIPIENTS
    )
    
    assert result == TEST_RECIPIENTS
    assert mock_client.sendmail.call_count == len(TEST_RECIPIENTS)
    
    # Check that the call was made with a large payload
    args, kwargs = mock_client.sendmail.call_args
    assert len(args[2]) > 2 * 1024 * 1024  # Message should be at least 2MB

# Test with large attachment
def test_send_email_with_large_attachment(mock_smtp_ssl_client, default_env_file, large_binary_data):
    """Test sending an email with a very large attachment (5MB)."""
    mock_smtp, mock_client = mock_smtp_ssl_client
    
    smtp = MailHandler(env=default_env_file)
    
    result = smtp.send_mail(
        plain_msg="Email with large attachment",
        subject="Large Attachment Test",
        recipients=TEST_RECIPIENTS,
        attachments=[("large_file.bin", large_binary_data, "application/octet-stream")]
    )
    
    assert result == TEST_RECIPIENTS
    assert mock_client.sendmail.call_count == len(TEST_RECIPIENTS)
    
    # The encoded attachment will be significantly larger than the original due to base64 encoding
    args, kwargs = mock_client.sendmail.call_args
    assert len(args[2]) > 6 * 1024 * 1024  # At least 6MB (accounting for base64 overhead)

# Test with many attachments
def test_send_email_with_many_attachments(mock_smtp_ssl_client, default_env_file):
    """Test sending an email with a large number of attachments (100)."""
    mock_smtp, mock_client = mock_smtp_ssl_client
    
    smtp = MailHandler(env=default_env_file)
    
    # Create 100 small attachments
    attachments = [
        (f"file{i}.txt", f"Content for file {i}", "text/plain")
        for i in range(100)
    ]
    
    result = smtp.send_mail(
        plain_msg="Email with many attachments",
        subject="Many Attachments Test",
        recipients=TEST_RECIPIENTS,
        attachments=attachments
    )
    
    assert result == TEST_RECIPIENTS
    assert mock_client.sendmail.call_count == len(TEST_RECIPIENTS)
    
    # Check that all attachments are included
    args, kwargs = mock_client.sendmail.call_args
    raw_msg = args[2]
    
    for i in range(100):
        assert f"Content-Disposition: attachment; filename=file{i}.txt" in raw_msg

# Test with very long subject
def test_send_email_with_very_long_subject(mock_smtp_ssl_client, default_env_file):
    """Test sending an email with an extremely long subject (5000 chars)."""
    mock_smtp, mock_client = mock_smtp_ssl_client
    
    smtp = MailHandler(env=default_env_file)
    
    # Generate a 5000 character subject
    long_subject = generate_random_string(5000)
    
    result = smtp.send_mail(
        plain_msg="Email with very long subject",
        subject=long_subject,
        recipients=TEST_RECIPIENTS
    )
    
    assert result == TEST_RECIPIENTS
    assert mock_client.sendmail.call_count == len(TEST_RECIPIENTS)
    
    # The subject should be encoded in the message headers
    args, kwargs = mock_client.sendmail.call_args
    raw_msg = args[2]
    
    # Check that the subject is properly encoded and included
    assert "Subject:" in raw_msg

# Test with a large number of recipients
@pytest.mark.parametrize("default_env_file", [{
    "recipients": ",".join([f"recipient{i}@example.com" for i in range(1000)])
}], indirect=True)
def test_send_email_with_many_recipients(mock_smtp_ssl_client, default_env_file):
    """Test sending an email to a large number of recipients (1000)."""
    mock_smtp, mock_client = mock_smtp_ssl_client
    
    smtp = MailHandler(env=default_env_file)
    
    # Generate the expected recipients list for verification
    expected_recipients = [f"recipient{i}@example.com" for i in range(1000)]
    
    result = smtp.send_mail(
        plain_msg="Email to many recipients",
        subject="Many Recipients Test"
    )
    
    assert len(result) == 1000
    assert result == expected_recipients
    assert mock_client.sendmail.call_count == 1000

# Test with unicode content
def test_send_email_with_unicode_content(mock_smtp_ssl_client, default_env_file):
    """Test sending an email with various Unicode characters in all fields."""
    mock_smtp, mock_client = mock_smtp_ssl_client
    
    smtp = MailHandler(env=default_env_file)
    
    # Unicode content for different parts of the email
    unicode_subject = "Unicode Subject: こんにちは 你好 مرحبا Привет"
    unicode_body = """
    English: Hello World!
    Japanese: こんにちは世界！
    Chinese: 你好世界！
    Arabic: مرحبا بالعالم!
    Russian: Привет, мир!
    Emoji: 🌍 🚀 🎉 🤖 💻
    """
    
    result = smtp.send_mail(
        plain_msg=unicode_body,
        subject=unicode_subject,
        recipients=TEST_RECIPIENTS
    )
    
    assert result == TEST_RECIPIENTS
    assert mock_client.sendmail.call_count == len(TEST_RECIPIENTS)
    
    # Check that the unicode is properly encoded
    args, kwargs = mock_client.sendmail.call_args
    raw_msg = args[2]
    
    # The encoding might vary, but the message should contain the encoded content
    assert len(raw_msg) > len(unicode_subject) + len(unicode_body)

# Simulate rapid sending of multiple emails
def test_rapid_sending(mock_smtp_ssl_client, default_env_file):
    """Test sending 100 emails in rapid succession."""
    mock_smtp, mock_client = mock_smtp_ssl_client
    
    smtp = MailHandler(env=default_env_file)
    
    for i in range(100):
        result = smtp.send_mail(
            plain_msg=f"This is rapid test email {i}",
            subject=f"Rapid Test {i}",
            recipients=TEST_RECIPIENTS
        )
        assert result == TEST_RECIPIENTS
    
    assert mock_client.sendmail.call_count == 100 * len(TEST_RECIPIENTS)

# Test recovery after SMTP error
def test_recovery_after_smtp_error(mock_smtp_ssl_client, default_env_file):
    """Test that sending can continue after an SMTP error."""
    mock_smtp, mock_client = mock_smtp_ssl_client
    
    smtp = MailHandler(env=default_env_file)
    
    # Set up sendmail to fail on first call then succeed afterward
    side_effects = [smtplib.SMTPException("Temporary failure")] + [None] * 10
    mock_client.sendmail.side_effect = side_effects
    
    # First attempt should fail
    with pytest.raises(SMTPConnectionError):
        smtp.send_mail(
            plain_msg="First message that will fail",
            recipients=TEST_RECIPIENTS
        )
    
    # Reset the client and try again
    mock_client.sendmail.side_effect = None
    
    # Second attempt should succeed
    result = smtp.send_mail(
        plain_msg="Second message that should succeed",
        recipients=TEST_RECIPIENTS
    )
    
    assert result == TEST_RECIPIENTS
    assert mock_client.sendmail.call_count >= 2  # At least two calls were made

# Test with concurrent email sending
def test_concurrent_email_sending(mock_smtp_ssl_client, default_env_file):
    """Test sending emails from multiple threads concurrently."""
    mock_smtp_class, mock_client = mock_smtp_ssl_client
    
    # Need to patch the initialization to return a new client for each thread
    original_init = MailHandler.__init__
    
    def patched_init(self, *args, **kwargs):
        result = original_init(self, *args, **kwargs)
        # Each instance gets its own mock SMTP client
        self.server = MagicMock()
        return result
    
    with patch.object(MailHandler, '__init__', patched_init):
        def send_emails(thread_id):
            smtp = MailHandler(env=default_env_file)
            for i in range(10):
                result = smtp.send_mail(
                    plain_msg=f"Thread {thread_id}, email {i}",
                    subject=f"Concurrent Test {thread_id}-{i}",
                    recipients=TEST_RECIPIENTS
                )
                # Each thread's client is a separate mock, so we can't assert on the result
        
        # Create and start 5 threads
        threads = []
        for i in range(5):
            t = threading.Thread(target=send_emails, args=(i,))
            threads.append(t)
            t.start()
        
        # Wait for all threads to complete
        for t in threads:
            t.join()
        
        # The test passes if all threads complete without exceptions

# Test boundary conditions for attachments
def test_attachment_boundary_conditions(mock_smtp_ssl_client, default_env_file):
    """Test different boundary conditions for attachments."""
    mock_smtp, mock_client = mock_smtp_ssl_client
    
    smtp = MailHandler(env=default_env_file)
    
    # Empty attachment content
    result = smtp.send_mail(
        plain_msg="Email with empty attachment",
        recipients=TEST_RECIPIENTS,
        attachments=[("empty.txt", "", "text/plain")]
    )
    
    assert result == TEST_RECIPIENTS
    
    # Very long filename
    long_filename = "a" * 1000 + ".txt"
    result = smtp.send_mail(
        plain_msg="Email with long filename attachment",
        recipients=TEST_RECIPIENTS,
        attachments=[(long_filename, "content", "text/plain")]
    )
    
    assert result == TEST_RECIPIENTS
    
    # Unusual MIME types
    result = smtp.send_mail(
        plain_msg="Email with unusual MIME type",
        recipients=TEST_RECIPIENTS,
        attachments=[("file.xyz", "content", "application/x-custom-type")]
    )
    
    assert result == TEST_RECIPIENTS