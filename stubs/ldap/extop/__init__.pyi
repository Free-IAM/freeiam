from typing import Any

from _typeshed import Incomplete
from ldap.extop.dds import RefreshRequest as RefreshRequest, RefreshResponse as RefreshResponse
from ldap.extop.passwd import PasswordModifyResponse as PasswordModifyResponse

class ExtendedRequest:
    requestName: Incomplete
    requestValue: Incomplete
    def __init__(self, requestName: str, requestValue: bytes | None) -> None: ...
    def encodedRequestValue(self) -> bytes: ...

class ExtendedResponse:
    responseName: Incomplete
    responseValue: Incomplete
    def __init__(self, responseName: str | None, encodedResponseValue: bytes) -> None: ...
    def decodeResponseValue(self, value: bytes) -> Any: ...
