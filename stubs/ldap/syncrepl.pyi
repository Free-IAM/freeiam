from typing import Any

from _typeshed import Incomplete
from ldap.controls import RequestControl, ResponseControl
from ldap.types import LDAPEntryDict
from pyasn1.type import univ

class SyncUUID(univ.OctetString):
    subtypeSpec: Incomplete

class SyncCookie(univ.OctetString): ...

class SyncRequestMode(univ.Enumerated):
    namedValues: Incomplete
    subtypeSpec: Incomplete

class SyncRequestValue(univ.Sequence):
    componentType: Incomplete

class SyncRequestControl(RequestControl):
    controlType: str
    criticality: bool
    cookie: Incomplete
    mode: Incomplete
    reloadHint: Incomplete
    def __init__(self, criticality: int | bool = ..., cookie: str | None = ..., mode: str = ..., reloadHint: bool = ...) -> None: ...
    def encodeControlValue(self) -> bytes: ...

class SyncStateOp(univ.Enumerated):
    namedValues: Incomplete
    subtypeSpec: Incomplete

class SyncStateValue(univ.Sequence):
    componentType: Incomplete

class SyncStateControl(ResponseControl):
    controlType: str
    opnames: Incomplete
    cookie: Incomplete
    state: Incomplete
    entryUUID: Incomplete
    def decodeControlValue(self, encodedControlValue: bytes) -> None: ...

class SyncDoneValue(univ.Sequence):
    componentType: Incomplete

class SyncDoneControl(ResponseControl):
    controlType: str
    cookie: Incomplete
    refreshDeletes: Incomplete
    def decodeControlValue(self, encodedControlValue: bytes) -> None: ...

class RefreshDelete(univ.Sequence):
    componentType: Incomplete

class RefreshPresent(univ.Sequence):
    componentType: Incomplete

class SyncUUIDs(univ.SetOf):
    componentType: Incomplete

class SyncIdSet(univ.Sequence):
    componentType: Incomplete

class SyncInfoValue(univ.Choice):
    componentType: Incomplete

class SyncInfoMessage:
    responseName: str
    newcookie: Incomplete
    refreshDelete: Incomplete
    refreshPresent: Incomplete
    syncIdSet: Incomplete
    def __init__(self, encodedMessage: bytes) -> None: ...

class SyncreplConsumer:
    def syncrepl_search(self, base: str, scope: int, mode: str = ..., cookie: str | None = ..., **search_args: Any) -> int: ...
    def syncrepl_poll(self, msgid: int = ..., timeout: int | None = ..., all: int = ...) -> bool: ...
    def syncrepl_set_cookie(self, cookie: str) -> None: ...
    def syncrepl_get_cookie(self) -> str: ...
    def syncrepl_present(self, uuids: list[str] | None, refreshDeletes: bool = ...) -> None: ...
    def syncrepl_delete(self, uuids: list[str]) -> None: ...
    def syncrepl_entry(self, dn: str, attrs: LDAPEntryDict, uuid: str) -> None: ...
    def syncrepl_refreshdone(self) -> None: ...
