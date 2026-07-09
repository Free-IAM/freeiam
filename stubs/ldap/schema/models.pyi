from collections import UserDict
from collections.abc import ItemsView, KeysView
from typing import TypeAlias

import ldap.schema.subentry
from _typeshed import Incomplete
from ldap.cidict import cidict as cidict
from ldap.schema.subentry import SCHEMA_ATTR_MAPPING as SCHEMA_ATTR_MAPPING, SCHEMA_CLASS_MAPPING as SCHEMA_CLASS_MAPPING
from ldap.schema.tokenizer import (
    LDAPTokenDict as LDAPTokenDict,
    LDAPTokenDictValue as LDAPTokenDictValue,
    parse_tokens as parse_tokens,
    split_tokens as split_tokens,
)
from ldap.types import LDAPEntryDict as LDAPEntryDict

EntryBase: TypeAlias = UserDict[(str, list[bytes])]
NOT_HUMAN_READABLE_LDAP_SYNTAXES: Incomplete

class SchemaElement:
    schema_attribute: str
    known_tokens: Incomplete
    def __init__(self, schema_element_str: str | bytes | None = None) -> None: ...
    oid: Incomplete
    def set_id(self, element_id: str) -> None: ...
    def get_id(self) -> str: ...
    def key_attr(self, key: str, value: str | None, quoted: int = 0) -> str: ...
    def key_list(self, key: str, values: tuple[str, ...], sep: str = ' ', quoted: int = 0) -> str: ...

class ObjectClass(SchemaElement):
    desc: str | None
    names: tuple[str, ...]
    schema_attribute: str
    known_tokens: Incomplete

AttributeUsage: Incomplete

class AttributeType(SchemaElement):
    desc: str | None
    names: tuple[str, ...]
    schema_attribute: str
    known_tokens: Incomplete

class LDAPSyntax(SchemaElement):
    schema_attribute: str
    known_tokens: Incomplete

class MatchingRule(SchemaElement):
    schema_attribute: str
    known_tokens: Incomplete

class MatchingRuleUse(SchemaElement):
    schema_attribute: str
    known_tokens: Incomplete

class DITContentRule(SchemaElement):
    schema_attribute: str
    known_tokens: Incomplete

class DITStructureRule(SchemaElement):
    schema_attribute: str
    known_tokens: Incomplete
    ruleid: Incomplete
    def set_id(self, element_id: str) -> None: ...
    def get_id(self) -> str: ...

class NameForm(SchemaElement):
    schema_attribute: str
    known_tokens: Incomplete

class Entry(EntryBase):
    dn: Incomplete
    def __init__(self, schema: ldap.schema.subentry.SubSchema, dn: str, entry: LDAPEntryDict) -> None: ...
    def __contains__(self, nameoroid: object) -> bool: ...
    def __getitem__(self, nameoroid: object) -> list[bytes]: ...
    def __setitem__(self, nameoroid: object, attr_values: list[bytes]) -> None: ...
    def __delitem__(self, nameoroid: object) -> None: ...
    def has_key(self, nameoroid: str) -> bool: ...
    def keys(self) -> KeysView[str]: ...
    def items(self) -> ItemsView[str, list[bytes]]: ...
    def attribute_types(
        self, attr_type_filter: list[tuple[str, list[str]]] | None = None, raise_keyerror: int = 1
    ) -> tuple[cidict[AttributeType | None], cidict[AttributeType | None]]: ...
