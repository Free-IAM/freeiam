from collections.abc import Iterable, Sequence
from typing import Any, TextIO

import ldap
import ldif
from _typeshed import Incomplete
from ldap.controls import RequestControl as RequestControl
from ldap.types import LDAPEntryDict as LDAPEntryDict, LDAPSearchResult as LDAPSearchResult

SEARCH_RESULT_TYPES: Incomplete
ENTRY_RESULT_TYPES: Incomplete

class WrongResultType(Exception):
    receivedResultType: Incomplete
    expectedResultTypes: Incomplete
    def __init__(self, receivedResultType: int | None, expectedResultTypes: Iterable[int]) -> None: ...

class AsyncSearchHandler:
    def __init__(self, l: ldap.ldapobject.LDAPObject) -> None: ...
    def startSearch(
        self,
        searchRoot: str,
        searchScope: int,
        filterStr: str,
        attrList: list[str] | None = ...,
        attrsOnly: int = ...,
        timeout: int = ...,
        sizelimit: int = ...,
        serverctrls: list[RequestControl] | None = ...,
        clientctrls: list[RequestControl] | None = ...,
    ) -> None: ...
    def preProcessing(self) -> Any: ...
    def afterFirstResult(self) -> Any: ...
    def postProcessing(self) -> Any: ...
    beginResultsDropped: int
    endResultBreak: Incomplete
    def processResults(self, ignoreResultsNumber: int = ..., processResultsCount: int = ..., timeout: int = ...) -> int: ...

class List(AsyncSearchHandler):
    allResults: Incomplete
    def __init__(self, l: ldap.ldapobject.LDAPObject) -> None: ...

class Dict(AsyncSearchHandler):
    allEntries: Incomplete
    def __init__(self, l: ldap.ldapobject.LDAPObject) -> None: ...

class IndexedDict(Dict):
    indexed_attrs: Incomplete
    index: Incomplete
    def __init__(self, l: ldap.ldapobject.LDAPObject, indexed_attrs: Sequence[str] | None = ...) -> None: ...

class FileWriter(AsyncSearchHandler):
    headerStr: Incomplete
    footerStr: Incomplete
    def __init__(self, l: ldap.ldapobject.LDAPObject, f: TextIO, headerStr: str = ..., footerStr: str = ...) -> None: ...
    def preProcessing(self) -> None: ...
    def postProcessing(self) -> None: ...

class LDIFWriter(FileWriter):
    def __init__(self, l: ldap.ldapobject.LDAPObject, writer_obj: TextIO | ldif.LDIFWriter, headerStr: str = ..., footerStr: str = ...) -> None: ...
