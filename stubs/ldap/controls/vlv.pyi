from _typeshed import Incomplete
from ldap.controls import RequestControl, ResponseControl
from pyasn1.type import univ

class ByOffsetType(univ.Sequence):
    tagSet: Incomplete
    componentType: Incomplete

class TargetType(univ.Choice):
    componentType: Incomplete

class VirtualListViewRequestType(univ.Sequence):
    componentType: Incomplete

class VLVRequestControl(RequestControl):
    controlType: str
    before_count: Incomplete
    after_count: Incomplete
    offset: Incomplete
    content_count: Incomplete
    greater_than_or_equal: Incomplete
    context_id: Incomplete
    def __init__(
        self,
        criticality: bool = ...,
        before_count: int = ...,
        after_count: int = ...,
        offset: int | None = ...,
        content_count: int | None = ...,
        greater_than_or_equal: str | None = ...,
        context_id: str | None = ...,
    ) -> None: ...
    def encodeControlValue(self) -> bytes: ...

class VirtualListViewResultType(univ.Enumerated):
    namedValues: Incomplete

class VirtualListViewResponseType(univ.Sequence):
    componentType: Incomplete

class VLVResponseControl(ResponseControl):
    controlType: str
    def __init__(self, criticality: bool = ...) -> None: ...
    targetPosition: Incomplete
    contentCount: Incomplete
    virtualListViewResult: Incomplete
    contextID: Incomplete
    target_position: Incomplete
    content_count: Incomplete
    result: Incomplete
    context_id: Incomplete
    def decodeControlValue(self, encoded: bytes) -> None: ...
