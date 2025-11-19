from _typeshed import Incomplete
from ldap.extop import ExtendedRequest as ExtendedRequest, ExtendedResponse as ExtendedResponse
from pyasn1.type import univ

class RefreshRequest(ExtendedRequest):
    requestName: str
    defaultRequestTtl: int
    class RefreshRequestValue(univ.Sequence):
        componentType: Incomplete

    entryName: Incomplete
    requestTtl: Incomplete
    def __init__(self, requestName: str | None = ..., entryName: bytes | None = ..., requestTtl: int | None = ...) -> None: ...
    def encodedRequestValue(self) -> bytes: ...

class RefreshResponse(ExtendedResponse):
    responseName: str
    class RefreshResponseValue(univ.Sequence):
        componentType: Incomplete

    responseTtl: Incomplete
    def decodeResponseValue(self, value: bytes) -> int: ...
