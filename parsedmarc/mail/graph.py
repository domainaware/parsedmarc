# -*- coding: utf-8 -*-

from __future__ import annotations

from enum import Enum
from functools import lru_cache
from pathlib import Path
from time import sleep
from typing import Any, List, Optional, Union

from azure.identity import (
    UsernamePasswordCredential,
    DeviceCodeCredential,
    ClientSecretCredential,
    CertificateCredential,
    TokenCachePersistenceOptions,
    AuthenticationRecord,
)
from msgraph.core import GraphClient
from requests.exceptions import RequestException

from parsedmarc.log import logger
from parsedmarc.mail.mailbox_connection import MailboxConnection

GRAPH_REQUEST_RETRY_ATTEMPTS = 3
GRAPH_REQUEST_RETRY_DELAY_SECONDS = 5


class AuthMethod(Enum):
    DeviceCode = 1
    UsernamePassword = 2
    ClientSecret = 3
    Certificate = 4


def _get_cache_args(token_path: Path, allow_unencrypted_storage):
    cache_args: dict[str, Any] = {
        "cache_persistence_options": TokenCachePersistenceOptions(
            name="parsedmarc", allow_unencrypted_storage=allow_unencrypted_storage
        )
    }
    auth_record = _load_token(token_path)
    if auth_record:
        cache_args["authentication_record"] = AuthenticationRecord.deserialize(
            auth_record
        )
    return cache_args


def _load_token(token_path: Path) -> Optional[str]:
    if not token_path.exists():
        return None
    with token_path.open() as token_file:
        return token_file.read()


def _cache_auth_record(record: AuthenticationRecord, token_path: Path):
    token = record.serialize()
    with token_path.open("w") as token_file:
        token_file.write(token)


def _generate_credential(auth_method: str, token_path: Path, **kwargs):
    if auth_method == AuthMethod.DeviceCode.name:
        credential = DeviceCodeCredential(
            client_id=kwargs["client_id"],
            disable_automatic_authentication=True,
            tenant_id=kwargs["tenant_id"],
            **_get_cache_args(
                token_path,
                allow_unencrypted_storage=kwargs["allow_unencrypted_storage"],
            ),
        )
    elif auth_method == AuthMethod.UsernamePassword.name:
        credential = UsernamePasswordCredential(
            client_id=kwargs["client_id"],
            client_credential=kwargs["client_secret"],
            disable_automatic_authentication=True,
            username=kwargs["username"],
            password=kwargs["password"],
            **_get_cache_args(
                token_path,
                allow_unencrypted_storage=kwargs["allow_unencrypted_storage"],
            ),
        )
    elif auth_method == AuthMethod.ClientSecret.name:
        credential = ClientSecretCredential(
            client_id=kwargs["client_id"],
            tenant_id=kwargs["tenant_id"],
            client_secret=kwargs["client_secret"],
        )
    elif auth_method == AuthMethod.Certificate.name:
        cert_path = kwargs.get("certificate_path")
        if not cert_path:
            raise ValueError(
                "certificate_path is required when auth_method is 'Certificate'"
            )
        credential = CertificateCredential(
            client_id=kwargs["client_id"],
            tenant_id=kwargs["tenant_id"],
            certificate_path=cert_path,
            password=kwargs.get("certificate_password"),
        )
    else:
        raise RuntimeError(f"Auth method {auth_method} not found")
    return credential


class MSGraphConnection(MailboxConnection):
    _WELL_KNOWN_FOLDERS = {
        "inbox": "inbox",
        "archive": "archive",
        "drafts": "drafts",
        "sentitems": "sentitems",
        "deleteditems": "deleteditems",
        "junkemail": "junkemail",
    }

    def __init__(
        self,
        auth_method: str,
        mailbox: str,
        graph_url: str,
        client_id: str,
        client_secret: Optional[str],
        username: Optional[str],
        password: Optional[str],
        tenant_id: str,
        token_file: str,
        allow_unencrypted_storage: bool,
        certificate_path: Optional[str] = None,
        certificate_password: Optional[Union[str, bytes]] = None,
    ):
        token_path = Path(token_file)
        credential = _generate_credential(
            auth_method,
            client_id=client_id,
            client_secret=client_secret,
            certificate_path=certificate_path,
            certificate_password=certificate_password,
            username=username,
            password=password,
            tenant_id=tenant_id,
            token_path=token_path,
            allow_unencrypted_storage=allow_unencrypted_storage,
        )
        client_params = {
            "credential": credential,
            "cloud": graph_url,
        }
        if not isinstance(credential, (ClientSecretCredential, CertificateCredential)):
            scopes = ["Mail.ReadWrite"]
            # Detect if mailbox is shared
            if mailbox and username != mailbox:
                scopes = ["Mail.ReadWrite.Shared"]
            auth_record = credential.authenticate(scopes=scopes)
            _cache_auth_record(auth_record, token_path)
            client_params["scopes"] = scopes

        self._client = GraphClient(**client_params)
        self.mailbox_name = mailbox

    def _request_with_retries(self, method_name: str, *args, **kwargs):
        for attempt in range(1, GRAPH_REQUEST_RETRY_ATTEMPTS + 1):
            try:
                return getattr(self._client, method_name)(*args, **kwargs)
            except RequestException as error:
                if attempt == GRAPH_REQUEST_RETRY_ATTEMPTS:
                    raise
                logger.warning(
                    "Transient MS Graph %s error on attempt %s/%s: %s",
                    method_name.upper(),
                    attempt,
                    GRAPH_REQUEST_RETRY_ATTEMPTS,
                    error,
                )
                sleep(GRAPH_REQUEST_RETRY_DELAY_SECONDS)
        raise RuntimeError("no retry attempts configured")

    def create_folder(self, folder_name: str):
        sub_url = ""
        path_parts = folder_name.split("/")
        if len(path_parts) > 1:  # Folder is a subFolder
            parent_folder_id = None
            for folder in path_parts[:-1]:
                parent_folder_id = self._find_folder_id_with_parent(
                    folder, parent_folder_id
                )
            sub_url = f"/{parent_folder_id}/childFolders"
            folder_name = path_parts[-1]

        request_body = {"displayName": folder_name}
        request_url = f"/users/{self.mailbox_name}/mailFolders{sub_url}"
        resp = self._request_with_retries("post", request_url, json=request_body)
        if resp.status_code == 409:
            logger.debug(f"Folder {folder_name} already exists, skipping creation")
        elif resp.status_code == 201:
            logger.debug(f"Created folder {folder_name}")
        else:
            logger.warning(f"Unknown response {resp.status_code} {resp.json()}")

    def fetch_messages(self, reports_folder: str, **kwargs) -> List[str]:
        """Returns a list of message UIDs in the specified folder"""
        folder_id = self._find_folder_id_from_folder_path(reports_folder)
        url = f"/users/{self.mailbox_name}/mailFolders/{folder_id}/messages"
        since = kwargs.get("since")
        if not since:
            since = None
        batch_size = kwargs.get("batch_size")
        if not batch_size:
            batch_size = 0
        emails = self._get_all_messages(url, batch_size, since)
        return [email["id"] for email in emails]

    def _get_all_messages(self, url, batch_size, since):
        messages: list
        params: dict[str, Union[str, int]] = {"$select": "id"}
        if since:
            params["$filter"] = f"receivedDateTime ge {since}"
        if batch_size and batch_size > 0:
            params["$top"] = batch_size
        else:
            params["$top"] = 100
        result = self._request_with_retries("get", url, params=params)
        if result.status_code != 200:
            raise RuntimeError(f"Failed to fetch messages {result.text}")
        messages = result.json()["value"]
        # Loop if next page is present and not obtained message limit.
        while "@odata.nextLink" in result.json() and (
            since is not None or (batch_size == 0 or batch_size - len(messages) > 0)
        ):
            result = self._request_with_retries("get", result.json()["@odata.nextLink"])
            if result.status_code != 200:
                raise RuntimeError(f"Failed to fetch messages {result.text}")
            messages.extend(result.json()["value"])
        return messages

    def mark_message_read(self, message_id: str):
        """Marks a message as read"""
        url = f"/users/{self.mailbox_name}/messages/{message_id}"
        resp = self._request_with_retries("patch", url, json={"isRead": "true"})
        if resp.status_code != 200:
            raise RuntimeWarning(
                f"Failed to mark message read{resp.status_code}: {resp.json()}"
            )

    def fetch_message(self, message_id: str, **kwargs):
        url = f"/users/{self.mailbox_name}/messages/{message_id}/$value"
        result = self._request_with_retries("get", url)
        if result.status_code != 200:
            raise RuntimeWarning(
                f"Failed to fetch message{result.status_code}: {result.json()}"
            )
        mark_read = kwargs.get("mark_read")
        if mark_read:
            self.mark_message_read(message_id)
        return result.text

    def delete_message(self, message_id: str):
        url = f"/users/{self.mailbox_name}/messages/{message_id}"
        resp = self._request_with_retries("delete", url)
        if resp.status_code != 204:
            raise RuntimeWarning(
                f"Failed to delete message {resp.status_code}: {resp.json()}"
            )

    def move_message(self, message_id: str, folder_name: str):
        folder_id = self._find_folder_id_from_folder_path(folder_name)
        request_body = {"destinationId": folder_id}
        url = f"/users/{self.mailbox_name}/messages/{message_id}/move"
        resp = self._request_with_retries("post", url, json=request_body)
        if resp.status_code != 201:
            raise RuntimeWarning(
                f"Failed to move message {resp.status_code}: {resp.json()}"
            )

    def keepalive(self):
        # Not needed
        pass

    def watch(self, check_callback, check_timeout):
        """Checks the mailbox for new messages every n seconds"""
        while True:
            sleep(check_timeout)
            check_callback(self)

    @lru_cache(maxsize=10)
    def _find_folder_id_from_folder_path(self, folder_name: str) -> str:
        path_parts = folder_name.split("/")
        parent_folder_id = None
        if len(path_parts) > 1:
            for folder in path_parts[:-1]:
                folder_id = self._find_folder_id_with_parent(folder, parent_folder_id)
                parent_folder_id = folder_id
            return self._find_folder_id_with_parent(path_parts[-1], parent_folder_id)
        else:
            # Shared mailboxes can fail root listing; try well-known folders first.
            well_known_folder_id = self._get_well_known_folder_id(folder_name)
            if well_known_folder_id:
                return well_known_folder_id
            return self._find_folder_id_with_parent(folder_name, None)

    def _get_well_known_folder_id(self, folder_name: str) -> Optional[str]:
        folder_key = folder_name.lower().replace(" ", "").replace("-", "")
        alias = self._WELL_KNOWN_FOLDERS.get(folder_key)
        if alias is None:
            return None

        url = f"/users/{self.mailbox_name}/mailFolders/{alias}?$select=id,displayName"
        folder_resp = self._client.get(url)
        if folder_resp.status_code != 200:
            return None
        payload = folder_resp.json()
        return payload.get("id")

    def _find_folder_id_with_parent(
        self, folder_name: str, parent_folder_id: Optional[str]
    ):
        sub_url = ""
        if parent_folder_id is not None:
            sub_url = f"/{parent_folder_id}/childFolders"
        url = f"/users/{self.mailbox_name}/mailFolders{sub_url}"
        filter = f"?$filter=displayName eq '{folder_name}'"
        folders_resp = self._request_with_retries("get", url + filter)
        if folders_resp.status_code != 200:
            if parent_folder_id is None:
                well_known_folder_id = self._get_well_known_folder_id(folder_name)
                if well_known_folder_id:
                    return well_known_folder_id
            raise RuntimeWarning(f"Failed to list folders.{folders_resp.json()}")
        folders: list = folders_resp.json()["value"]
        matched_folders = [
            folder for folder in folders if folder["displayName"] == folder_name
        ]
        if len(matched_folders) == 0:
            raise RuntimeError(f"folder {folder_name} not found")
        selected_folder = matched_folders[0]
        return selected_folder["id"]
