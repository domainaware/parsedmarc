import logging
from base64 import urlsafe_b64decode
from pathlib import Path
from time import sleep
from typing import List

from google.auth.transport.requests import Request
from google.oauth2.credentials import Credentials
from google_auth_oauthlib.flow import InstalledAppFlow
from googleapiclient.discovery import build

from parsedmarc.mail.mailbox_connection import MailboxConnection

logger = logging.getLogger("parsedmarc")


def _get_creds(token_file, credentials_file, scopes):
    creds = None

    if Path(token_file).exists():
        creds = Credentials.from_authorized_user_file(token_file, scopes)
    # If there are no (valid) credentials available, let the user log in.
    if not creds or not creds.valid:
        if creds and creds.expired and creds.refresh_token:
            creds.refresh(Request())
        else:
            flow = InstalledAppFlow.from_client_secrets_file(
                credentials_file, scopes)
            creds = flow.run_console()
        # Save the credentials for the next run
        with open(token_file, 'w') as token:
            token.write(creds.to_json())
    return creds


class GmailConnection(MailboxConnection):
    def __init__(self,
                 token_file: str,
                 credentials_file: str,
                 scopes: List[str],
                 include_spam_trash: bool):
        creds = _get_creds(token_file, credentials_file, scopes)
        self.service = build('gmail', 'v1', credentials=creds)
        self.include_spam_trash = include_spam_trash

    def create_folder(self, folder_name: str):
        logger.debug("Creating label {0}".format(folder_name))
        request_body = {'name': folder_name, 'messageListVisibility': 'show'}
        self.service.users().labels()\
            .create(userId='me', body=request_body).execute()

    def fetch_messages(self, reports_folder: str) -> List[str]:
        reports_label_id = self._find_label_id_for_label(reports_folder)
        results = self.service.users().messages()\
            .list(userId='me',
                  includeSpamTrash=self.include_spam_trash,
                  labelIds=[reports_label_id]
                  )\
            .execute()
        messages = results.get('messages', [])
        return [message['id'] for message in messages]

    def fetch_message(self, message_id):
        msg = self.service.users().messages()\
            .get(userId='me',
                 id=message_id,
                 format="raw"
                 )\
            .execute()
        return urlsafe_b64decode(msg['raw'])

    def delete_message(self, message_id: str):
        self.service.users().messages().delete(userId='me', id=message_id)

    def move_message(self, message_id: str, folder_name: str):
        label_id = self._find_label_id_for_label(folder_name)
        logger.debug(f"Moving message UID {message_id} to {folder_name}")
        request_body = {'addLabelIds': [label_id]}
        self.service.users().messages()\
            .modify(userId='me',
                    id=message_id,
                    body=request_body)\
            .execute()

    def keepalive(self):
        # Not needed
        pass

    def watch(self, check_callback, check_timeout):
        """ Checks the mailbox for new messages every n seconds"""
        while True:
            sleep(check_timeout)
            check_callback(self)

    def _find_label_id_for_label(self, label_name: str) -> str:
        results = self.service.users().labels().list(userId='me').execute()
        labels = results.get('labels', [])
        for label in labels:
            if label_name == label['id'] or label_name == label['name']:
                return label['id']
