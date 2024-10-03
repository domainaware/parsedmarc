from time import sleep

from parsedmarc.log import logger
from parsedmarc.mail.mailbox_connection import MailboxConnection
import mailbox
import os


class MaildirConnection(MailboxConnection):
    def __init__(
        self,
        maildir_path=None,
        maildir_create=False,
    ):
        self._maildir_path = maildir_path
        self._maildir_create = maildir_create
        maildir_owner = os.stat(maildir_path).st_uid
        if os.getuid() != maildir_owner:
            if os.getuid() == 0:
                logger.warning(
                    "Switching uid to {} to access Maildir".format(maildir_owner)
                )
                os.setuid(maildir_owner)
            else:
                ex = "runtime uid {} differ from maildir {} owner {}".format(
                    os.getuid(), maildir_path, maildir_owner
                )
                raise Exception(ex)
        self._client = mailbox.Maildir(maildir_path, create=maildir_create)
        self._subfolder_client = {}

    def create_folder(self, folder_name: str):
        self._subfolder_client[folder_name] = self._client.add_folder(folder_name)
        self._client.add_folder(folder_name)

    def fetch_messages(self, reports_folder: str, **kwargs):
        return self._client.keys()

    def fetch_message(self, message_id):
        return self._client.get(message_id).as_string()

    def delete_message(self, message_id: str):
        self._client.remove(message_id)

    def move_message(self, message_id: str, folder_name: str):
        message_data = self._client.get(message_id)
        if folder_name not in self._subfolder_client.keys():
            self._subfolder_client = mailbox.Maildir(
                os.join(self.maildir_path, folder_name), create=self.maildir_create
            )
        self._subfolder_client[folder_name].add(message_data)
        self._client.remove(message_id)

    def keepalive(self):
        return

    def watch(self, check_callback, check_timeout):
        while True:
            try:
                check_callback(self)
            except Exception as e:
                logger.warning("Maildir init error. {0}".format(e))
            sleep(check_timeout)
