from typing import BinaryIO, TextIO

from _typeshed import Incomplete
from ldap.types import LDAPControls, LDAPEntryDict, LDAPModList

ldif_pattern: Incomplete

class LDIFWriter:
    records_written: int
    def __init__(self, output_file: TextIO, base64_attrs: list[str] | None = ..., cols: int = ..., line_sep: str = ...) -> None: ...
    def unparse(self, dn: str, record: LDAPEntryDict | LDAPModList) -> None: ...

def CreateLDIF(dn: str, record: LDAPEntryDict | LDAPModList, base64_attrs: list[str], cols: int = ...) -> str: ...

class LDIFParser:
    version: Incomplete
    line_counter: int
    byte_counter: int
    records_read: int
    changetype_counter: Incomplete
    def __init__(
        self,
        input_file: TextIO | BinaryIO,
        ignored_attr_types: list[str] | None = ...,
        max_entries: int = ...,
        process_url_schemes: list[str] | None = ...,
        line_sep: str = ...,
    ) -> None: ...
    def handle(self, dn: str, entry: LDAPEntryDict) -> str | None: ...
    def parse_entry_records(self) -> None: ...
    def parse(self) -> None: ...
    def handle_modify(self, dn: str, modops: LDAPModList, controls: LDAPControls | None = ...) -> None: ...
    def parse_change_records(self) -> None: ...

class LDIFRecordList(LDIFParser):
    all_records: Incomplete
    all_modify_changes: Incomplete
    def __init__(
        self,
        input_file: TextIO | BinaryIO,
        ignored_attr_types: list[str] | None = ...,
        max_entries: int = ...,
        process_url_schemes: list[str] | None = ...,
    ) -> None: ...
    def handle(self, dn: str, entry: LDAPEntryDict) -> None: ...
    def handle_modify(self, dn: str, modops: LDAPModList, controls: LDAPControls | None = ...) -> None: ...

class LDIFCopy(LDIFParser):
    def __init__(
        self,
        input_file: TextIO | BinaryIO,
        output_file: TextIO,
        ignored_attr_types: list[str] | None = ...,
        max_entries: int = ...,
        process_url_schemes: list[str] | None = ...,
        base64_attrs: list[str] = ...,
        cols: int = ...,
        line_sep: str = ...,
    ) -> None: ...
    def handle(self, dn: str, entry: LDAPEntryDict) -> None: ...

def ParseLDIF(f: TextIO | BinaryIO, ignore_attrs: list[str] | None = ..., maxentries: int = ...) -> list[tuple[str, LDAPEntryDict]]: ...
