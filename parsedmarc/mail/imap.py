# Standard Library
from socket import timeout
from time import sleep
from typing import Optional

# Installed
from imapclient.exceptions import IMAPClientError
from mailsuite.imap import IMAPClient

# Package
from parsedmarc.log import logger
from parsedmarc.mail.mailbox_connection import MailboxConnection


class IMAPConnection(MailboxConnection):
    """MailboxConnection for connecting to a mailbox via IMAP."""

    def __init__(
        self,
        host: Optional[str] = None,
        user: Optional[str] = None,
        password: Optional[str] = None,
        port: Optional[int] = None,
        ssl: bool = True,
        verify: bool = True,
        timeout: int = 30,
        max_retries: int = 4,
    ):
        """
        Args:
            host: Host to connect to
            user:
            password:
            port: Port to connect to
            ssl: Use SSL/TLS
            verify: Verify the SSL/TLS certification
            timeout:
            max_retries:
        """
        self._username = user
        self._password = password
        self._verify = verify
        self._client = IMAPClient(
            host,
            user,
            password,
            port=port,
            ssl=ssl,
            verify=verify,
            timeout=timeout,
            max_retries=max_retries,
        )

    def create_folder(self, folder_name: str):
        self._client.create_folder(folder_name)

    def fetch_messages(self, reports_folder: str, **kwargs):
        self._client.select_folder(reports_folder)
        return self._client.search()

    def fetch_message(self, message_id):
        return self._client.fetch_message(message_id, parse=False)

    def delete_message(self, message_id: str):
        self._client.delete_messages([message_id])

    def move_message(self, message_id: str, folder_name: str):
        self._client.move_messages([message_id], folder_name)

    def keepalive(self):
        self._client.noop()

    def watch(self, check_callback, check_timeout):
        """Use an IDLE IMAP connection to parse incoming emails, and pass the results to a callback function"""

        # IDLE callback sends IMAPClient object,
        # send back the imap connection object instead
        def idle_callback_wrapper(client: IMAPClient):
            self._client = client
            check_callback(self)

        while True:
            try:
                IMAPClient(
                    host=self._client.host,
                    username=self._username,
                    password=self._password,
                    port=self._client.port,
                    ssl=self._client.ssl,
                    verify=self._verify,
                    idle_callback=idle_callback_wrapper,
                    idle_timeout=check_timeout,
                )
            except (timeout, IMAPClientError):
                logger.warning("IMAP connection timeout. Reconnecting...")
                sleep(check_timeout)
            except Exception as e:
                logger.warning(f"IMAP connection error. {e!r}. " "Reconnecting...")
                sleep(check_timeout)
