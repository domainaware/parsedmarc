from abc import ABC
from typing import List


class MailboxConnection(ABC):
    """
    Interface for a mailbox connection
    """
    def create_folder(self, folder_name: str):
        raise NotImplementedError

    def fetch_messages(self, batch_size: int, reports_folder: str) -> List[str]:
        raise NotImplementedError

    def fetch_message(self, message_id) -> str:
        raise NotImplementedError

    def delete_message(self, message_id: str):
        raise NotImplementedError

    def move_message(self, message_id: str, folder_name: str):
        raise NotImplementedError

    def keepalive(self):
        raise NotImplementedError
