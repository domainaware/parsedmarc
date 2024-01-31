from __future__ import annotations

# Standard Library
from abc import ABC


class MailboxConnection(ABC):
    """Interface for a mailbox connection"""

    def create_folder(self, folder_name: str) -> None:
        raise NotImplementedError

    def fetch_messages(self, reports_folder: str, **kwargs) -> list[str]:
        raise NotImplementedError

    def fetch_message(self, message_id: str) -> str | bytes:
        raise NotImplementedError

    def delete_message(self, message_id: str) -> None:
        raise NotImplementedError

    def move_message(self, message_id: str, folder_name: str) -> None:
        raise NotImplementedError

    def keepalive(self) -> None:
        raise NotImplementedError

    def watch(self, check_callback, check_timeout) -> None:
        raise NotImplementedError
