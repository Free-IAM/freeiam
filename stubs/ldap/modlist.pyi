from ldap._types import (
    LDAPAddModList,
    LDAPEntryDict,
    LDAPModifyModList,
)

def addModlist(entry: LDAPEntryDict, ignore_attr_types: list[str] | None = None) -> LDAPAddModList: ...
def modifyModlist(
    old_entry: LDAPEntryDict,
    new_entry: LDAPEntryDict,
    ignore_attr_types: list[str] | None = None,
    ignore_oldexistent: int = 0,
    case_ignore_attr_types: list[str] | None = None,
) -> LDAPModifyModList: ...
