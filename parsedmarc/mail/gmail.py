from __future__ import annotations

# Standard Library
from base64 import urlsafe_b64decode
from functools import lru_cache
from pathlib import Path
from time import sleep
from typing import TYPE_CHECKING

# Installed
from google.auth.transport.requests import Request
from google.oauth2.credentials import Credentials
from google_auth_oauthlib.flow import InstalledAppFlow
from googleapiclient.discovery import build
from googleapiclient.errors import HttpError

if TYPE_CHECKING:
    # https://github.com/henribru/google-api-python-client-stubs?tab=readme-ov-file#explicit-annotations
    from googleapiclient._apis.gmail.v1.schemas import ModifyMessageRequest, Label

# Package
from parsedmarc.log import logger
from parsedmarc.mail.mailbox_connection import MailboxConnection


def _get_creds(token_file, credentials_file, scopes, oauth2_port):
    creds = None

    if Path(token_file).exists():
        creds = Credentials.from_authorized_user_file(token_file, scopes)

    # If there are no (valid) credentials available, let the user log in.
    if not creds or not creds.valid:
        if creds and creds.expired and creds.refresh_token:
            creds.refresh(Request())
        else:
            flow = InstalledAppFlow.from_client_secrets_file(credentials_file, scopes)
            creds = flow.run_local_server(open_browser=False, oauth2_port=oauth2_port)
        # Save the credentials for the next run
        with Path(token_file).open("w") as token:
            token.write(creds.to_json())
    return creds


class GmailConnection(MailboxConnection):
    """MailboxConnection for Google accounts using the Google API.

    This will support both Gmail and Google Workspace accounts.
    """

    def __init__(
        self,
        token_file: str,
        credentials_file: str,
        scopes: list[str],
        include_spam_trash: bool,
        reports_folder: str,
        oauth2_port: int,
    ):
        """
        Args:
            token_file:
            credentials_file:
            scopes:
            include_spam_trash:
            reports_folder:
            oauth2_port:
        """
        creds = _get_creds(token_file, credentials_file, scopes, oauth2_port)
        self.service = build("gmail", "v1", credentials=creds)
        self.include_spam_trash = include_spam_trash
        self.reports_label_id = self._find_label_id_for_label(reports_folder)

    def create_folder(self, folder_name: str) -> None:
        # Gmail doesn't support the name Archive
        if folder_name == "Archive":
            return

        logger.debug(f"Creating label {folder_name}")
        request_body: Label = {"name": folder_name, "messageListVisibility": "show"}
        try:
            self.service.users().labels().create(userId="me", body=request_body).execute()
        except HttpError as e:
            if e.status_code == 409:
                logger.debug(f"Folder {folder_name} already exists, " f"skipping creation")
            else:
                raise e
        return

    def fetch_messages(self, reports_folder: str, **kwargs) -> list[str]:
        reports_label_id = self._find_label_id_for_label(reports_folder)
        results = (
            self.service.users()
            .messages()
            .list(
                userId="me",
                includeSpamTrash=self.include_spam_trash,
                labelIds=[reports_label_id],
            )
            .execute()
        )
        messages = results.get("messages", [])
        return [message["id"] for message in messages]

    def fetch_message(self, message_id: str) -> bytes:
        msg = (
            self.service.users().messages().get(userId="me", id=message_id, format="raw").execute()
        )
        return urlsafe_b64decode(msg["raw"])

    def delete_message(self, message_id: str) -> None:
        self.service.users().messages().delete(userId="me", id=message_id)
        return

    def move_message(self, message_id: str, folder_name: str):
        label_id = self._find_label_id_for_label(folder_name)
        logger.debug(f"Moving message UID {message_id} to {folder_name}")
        request_body: ModifyMessageRequest = {
            "addLabelIds": [label_id],
            "removeLabelIds": [self.reports_label_id],
        }
        self.service.users().messages().modify(
            userId="me", id=message_id, body=request_body
        ).execute()
        return

    def keepalive(self) -> None:
        # no action needed
        return

    def watch(self, check_callback, check_timeout) -> None:
        """Checks the mailbox for new messages every n seconds"""
        while True:
            sleep(check_timeout)
            check_callback(self)
        return

    @lru_cache(maxsize=10)
    def _find_label_id_for_label(self, label_name: str) -> str:
        results = self.service.users().labels().list(userId="me").execute()
        labels = results.get("labels", [])
        for label in labels:
            if label_name == label["id"] or label_name == label["name"]:
                return label["id"]
        raise ValueError(f"Label {label_name} not found")
