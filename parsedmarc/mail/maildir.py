# -*- coding: utf-8 -*-

from __future__ import annotations

import mailbox
import os
from time import sleep
from typing import Dict

from parsedmarc.log import logger
from parsedmarc.mail.mailbox_connection import MailboxConnection


class MaildirConnection(MailboxConnection):
    def __init__(
        self,
        maildir_path: str,
        maildir_create: bool = False,
    ):
        self._maildir_path = maildir_path
        self._maildir_create = maildir_create
        try:
            maildir_owner = os.stat(maildir_path).st_uid
        except OSError:
            maildir_owner = None
        current_uid = os.getuid()
        if maildir_owner is not None and current_uid != maildir_owner:
            if current_uid == 0:
                try:
                    logger.warning(
                        "Switching uid to {} to access Maildir".format(maildir_owner)
                    )
                    os.setuid(maildir_owner)
                except OSError as e:
                    logger.warning(
                        "Failed to switch uid to {}: {}".format(maildir_owner, e)
                    )
            else:
                logger.warning(
                    "Runtime uid {} differs from maildir {} owner {}. "
                    "Access may fail if permissions are insufficient.".format(
                        current_uid, maildir_path, maildir_owner
                    )
                )
        if maildir_create:
            for subdir in ("cur", "new", "tmp"):
                os.makedirs(os.path.join(maildir_path, subdir), exist_ok=True)
        self._client = mailbox.Maildir(maildir_path, create=maildir_create)
        self._active_folder: mailbox.Maildir = self._client
        self._subfolder_client: Dict[str, mailbox.Maildir] = {}

    def _get_folder(self, folder_name: str) -> mailbox.Maildir:
        """Return a cached subfolder handle, creating it if needed."""
        if folder_name not in self._subfolder_client:
            self._subfolder_client[folder_name] = self._client.add_folder(folder_name)
        return self._subfolder_client[folder_name]

    def create_folder(self, folder_name: str):
        self._get_folder(folder_name)

    def fetch_messages(self, reports_folder: str, **kwargs):
        if reports_folder and reports_folder != "INBOX":
            self._active_folder = self._get_folder(reports_folder)
        else:
            self._active_folder = self._client
        return self._active_folder.keys()

    def fetch_message(self, message_id: str, **kwargs) -> str:
        msg = self._active_folder.get(message_id)
        if msg is None:
            return ""
        msg_str = msg.as_string()
        if kwargs.get("mark_read"):
            # Maildir spec: a message is "read" once it has been moved out of
            # new/ into cur/ with the "S" (Seen) flag set in its info field.
            msg.set_subdir("cur")
            msg.add_flag("S")
            self._active_folder[message_id] = msg
        return msg_str or ""

    def delete_message(self, message_id: str):
        self._active_folder.remove(message_id)

    def move_message(self, message_id: str, folder_name: str):
        message_data = self._active_folder.get(message_id)
        if message_data is None:
            return
        dest = self._get_folder(folder_name)
        dest.add(message_data)
        self._active_folder.remove(message_id)

    def keepalive(self):
        return

    def watch(self, check_callback, check_timeout, config_reloading=None):
        while True:
            if config_reloading and config_reloading():
                return
            try:
                check_callback(self)
            except Exception as e:
                logger.warning("Maildir init error. {0}".format(e))
            if config_reloading and config_reloading():
                return
            sleep(check_timeout)
