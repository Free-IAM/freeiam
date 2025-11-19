from typing import TypeAlias

LDAPControl: TypeAlias = tuple[str, int, bytes | None]
LDAPControls: TypeAlias = list[LDAPControl]

LDAPEntryDict: TypeAlias = dict[str, list[bytes]]

LDAPModListAddEntry: TypeAlias = tuple[str, list[bytes]]
LDAPModListModifyEntry: TypeAlias = tuple[int, str, list[bytes]]
LDAPModListEntry: TypeAlias = tuple[int, str, list[str]]

LDAPAddModList: TypeAlias = list[LDAPModListAddEntry]
LDAPModifyModList: TypeAlias = list[LDAPModListModifyEntry]
LDAPModList: TypeAlias = list[LDAPModListEntry]

LDAPSearchResult: TypeAlias = tuple[(str, LDAPEntryDict)]
