from ldap.types import (
    LDAPAddModList as LDAPAddModList,
    LDAPEntryDict as LDAPEntryDict,
    LDAPModifyModList as LDAPModifyModList,
    LDAPModListModifyEntry as LDAPModListModifyEntry,
)

def addModlist(entry: LDAPEntryDict, ignore_attr_types: list[str] | None = ...) -> LDAPAddModList: ...
def modifyModlist(
    old_entry: LDAPEntryDict,
    new_entry: LDAPEntryDict,
    ignore_attr_types: list[str] | None = ...,
    ignore_oldexistent: int = ...,
    case_ignore_attr_types: list[str] | None = ...,
) -> LDAPModifyModList: ...
