import logging

from mailsuite.imap import IMAPClient

from parsedmarc.mail.mailbox_connection import MailboxConnection


logger = logging.getLogger("parsedmarc")


class IMAPConnection(MailboxConnection):
    def __init__(self,
                 host=None,
                 user=None,
                 password=None,
                 port=None,
                 ssl=True,
                 verify=True,
                 timeout=30,
                 max_retries=4):
        self._client = IMAPClient(host, user, password, port=port,
                                  ssl=ssl, verify=verify,
                                  timeout=timeout,
                                  max_retries=max_retries)

    def create_folder(self, folder_name: str):
        self._client.create_folder(folder_name)

    def fetch_messages(self, batch_size, reports_folder: str):
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
