#!/usr/bin/python3
"""
smtp_handler.py

This module provides the MailHandler class for handling sending emails using SMTP.
It supports loading configuration from a .env file and includes error handling
for various potential issues such as missing environment variables and SMTP
connection errors.

Classes:
--------
MailHandler
    A class to handle sending emails using SMTP.

Usage:
```python
mail_sender = MailHandler()
mail_sender.send_mail("Hello World.")
```
    
Exceptions:
-----------
EnvFileNotLoadedError
    Raised when the .env file is missing or incorrectly formatted.
EnvironmentVariableNotFoundError
    Raised when an environment variable is missing from the .env file.
SMTPConnectionError
    Raised when there is an issue connecting to the SMTP server or sending an email.
"""
from email import encoders
from email.mime.base import MIMEBase
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
import re
import os
import smtplib
from env_handler import EnvHandler
from custom_errors import *

class MailHandler:
    """
    A class to handle sending emails using SMTP.

    Attributes
    ----------
    user : str, optional
        The username for the SMTP server.
    password : str, optional
        The password for the SMTP server.
    smtp_server : str, optional
        The address of the SMTP server.
    smtp_port : int, optional
        The port number of the SMTP server.
    sender : str, optional
        The email address of the sender.
    recipients : list[str], optional
        A list of recipient email addresses.

    Methods
    -------
    send_mail(msg: str, sender: str | None = None, recipients: list[str] | None = None)
        Sends an email message.
    """
    def __init__(self, env: str = "env-files/smtp.env", smtp_server: str | None = None, smtp_port: int | None = None, user: str | None = None, password: str | None = None, sender: str | None = None, recipients: list[str] | None = None):
        """
        Constructs all the necessary attributes for the MailHandler object.

        Parameters
        ----------
        env : str, optional
            The path to the .env file. Must be relative (default is "env-files/smtp.env"). Script uses os.path.join on os.getcwd and the env argument to create the full path.
        user : str, optional
            The username for the SMTP server (default is None). If not provided it will be fetched from the .env file.
        password : str, optional
            The password for the SMTP server (default is None). If not provided it will be fetched from the .env file.
        smtp_server : str, optional
            The address of the SMTP server (default is None). If not provided it will be fetched from the .env file. 
        smtp_port : int, optional
            The port number of the SMTP server (default is None). If not provided it will be fetched from the .env file.
        sender : str, optional
            The email address of the sender (default is None). If not provided it will be fetched from the .env file.
        recipients : list[str], optional
            A list of recipient email addresses (default is None). If not provided it will be fetched from the .env file.
        """
        self.user = user
        self.password = password
        self.smtp_server = smtp_server
        self.smtp_port = smtp_port
        self.sender = sender
        self.recipients = recipients

        try:
            full_path = os.path.join(os.getcwd(), env)
            try:
                self.EH = EnvHandler(env=full_path)
            except Exception as e:
                if not user or not password or not smtp_server or not smtp_port or not sender or not recipients:
                    raise e

            if self.smtp_server is None:
                self.smtp_server = self.EH.load_var("SMTP_SERVER")

            if self.smtp_port is None:
                self.smtp_port = self.EH.load_var("SMTP_PORT")
                try:
                    self.smtp_port = int(self.smtp_port)
                except ValueError:
                    raise ValueError(f"SMTP_PORT must be an integer. Found: {self.smtp_port}")

            if self.user is None:
                self.user = self.EH.load_var("SMTP_USER")

            if self.password is None:
                self.password = self.EH.load_var("SMTP_PASSWORD")

            if self.sender is None:
                self.sender = self.EH.load_var("SENDER")

            if self.recipients is None:
                self.recipients = self.EH.load_var("RECIPIENTS")
                self.recipients = self.recipients.split(",")
        
        except EnvFileNotLoadedError:
            if self.smtp_server is None or self.smtp_port is None or self.user is None or self.password is None or self.sender is None or self.recipients is None:
                raise EnvFileNotLoadedError("Missing SMTP configuration in the .env file.")
        except EnvVariableNotFoundError as e:
            raise EnvVariableNotFoundError(f"Environment variable not found: {str(e)}")

        self.sender = self.sender.strip()
        self.__check_mail(self.sender)
        
        for i in range(len(self.recipients)):
            self.recipients[i] = self.recipients[i].strip()
            self.__check_mail(self.recipients[i])

        self.server = self.__set_up_server()

    def __check_mail(self, email: str):
        regex = (
            r"^[A-Za-z0-9._%+-]+@"                                # local part
            r"("                                                  # start domain group
            r"[A-Za-z0-9.-]+\.[A-Za-z]{2,24}"                     # domain.name
            r"|\[[0-9]{1,3}(\.[0-9]{1,3}){3}\]"                   # or [IPv4]
            r"|\[IPv6:[0-9a-fA-F:]+\]"                            # IPv6 literal
            r")$"
        )
        if not re.fullmatch(regex, email):
            raise InvalidEmailError(f"Invalid email address: {email}")

    def __set_up_server(self):
        """
        Set up and authenticate the SMTP server connection.
        Automatically handles STARTTLS (587), SSL (465), and fallback ports.
        
        Returns:
            smtplib.SMTP or smtplib.SMTP_SSL: An authenticated SMTP server object.
        
        Raises:
            SMTPConnectionError: If authentication fails or if connection cannot be established.
        """
        try:
            if self.smtp_port == 465:
                server = smtplib.SMTP_SSL(self.smtp_server, self.smtp_port)
            else:
                server = smtplib.SMTP(self.smtp_server, self.smtp_port)
                server.ehlo()
                if self.smtp_port == 587:
                    server.starttls()
                    server.ehlo()

            server.login(self.user, self.password)
            return server

        except smtplib.SMTPAuthenticationError as e:
            raise SMTPConnectionError(f"SMTP authentication failed: {str(e)}")
        except Exception as e:
            raise SMTPConnectionError(f"Failed to connect to SMTP server: {str(e)}")

    def send_mail(self, plain_msg: str = None, html_msg: str = None, subject: str = "", recipients: list[str] | None = None, attachments: list[tuple[str, str, str]] = []):
        """
        Sends a email [plain/html] with optional attachments.

        Parameters
        ----------
        body : str
            Content of the email.
        hasHTMLContent : bool, optional
            Specifies if the body contains HTML content. Default is False.
        subject : str, optional
            The email subject.
        recipients : list[str], optional
            Send it only to the specified recipients. If None, it will be sent to all recipients.
        attachments : list[tuple[str, str, str]]
            List of (filename, content, MIME type).
        """
        if not html_msg and not plain_msg:
            raise EnvVariableEmptyError("Email body is empty.")

        if recipients:
            if isinstance(recipients, str):
                recipients = [recipients]
            for i in range(len(recipients)):
                recipients[i] = recipients[i].strip()
                if recipients[i] not in self.recipients:
                    raise InvalidRecipientError(f"Recipient {recipients[i]} is not in the list of recipients.")
        else:
            recipients = self.recipients

        msg = MIMEMultipart("alternative")

        if plain_msg:
            msg.attach(MIMEText(plain_msg, "plain"))

        if html_msg:
            msg.attach(MIMEText(html_msg, "html"))
        
        msg["Subject"] = subject or "Mail FROM SMTP Mail Module."
        msg["From"] = self.sender
        msg["To"] = ", ".join(recipients)

        for filename, content, mime_type in attachments:
            part = MIMEBase(*mime_type.split("/"))
            part.set_payload(content)
            encoders.encode_base64(part)
            part.add_header("Content-Disposition", f"attachment; filename={filename}")
            msg.attach(part)

        return self.__send_mail(msg, recipients)

    def __send_mail(self, msg_obj, recipients: list[str] | None = None):
        """
        Internal method to send an email.

        Parameters
        ----------
        msg_obj : EmailMessage | MIMEMultipart
            The prepared message object.
        recipients : list[str]
            The envelope recipient list.
        """
        try:
            msg_str = msg_obj.as_string()

            successful = []
            for recipient in recipients:
                if recipient not in successful:
                    self.server.sendmail(self.sender, recipient, msg_str)
                    successful.append(recipient)

            return successful
        except Exception as e:
            raise SMTPConnectionError(f"Failed to send email: {str(e)}")
