# -*- coding: utf-8 -*-

from __future__ import annotations

from abc import ABC


class MailboxConnection(ABC):
    """
    Interface for a mailbox connection
    """

    def create_folder(self, folder_name: str):
        raise NotImplementedError

    def fetch_messages(self, reports_folder: str, **kwargs):
        raise NotImplementedError

    def fetch_message(self, message_id) -> str:
        raise NotImplementedError

    def delete_message(self, message_id):
        raise NotImplementedError

    def move_message(self, message_id, folder_name: str):
        raise NotImplementedError

    def keepalive(self):
        raise NotImplementedError

    def watch(self, check_callback, check_timeout):
        raise NotImplementedError
