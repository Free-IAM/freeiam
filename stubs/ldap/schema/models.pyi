from collections.abc import ItemsView, Iterator, KeysView, MutableMapping
from typing import ClassVar, TypeAlias

import ldap.schema
from _typeshed import Incomplete
from ldap._types import LDAPEntryDict
from ldap.cidict import cidict

EntryBase: TypeAlias = MutableMapping[(str, list[bytes])]
NOT_HUMAN_READABLE_LDAP_SYNTAXES: Incomplete

class SchemaElement:
    schema_attribute: str
    known_tokens: ClassVar[list[str]]
    oid: str
    names: tuple[str, ...]
    desc: str | None

    def __init__(self, schema_element_str: str | bytes | None = None) -> None: ...
    def set_id(self, element_id: str) -> None: ...
    def get_id(self) -> str: ...
    def key_attr(self, key: str, value: str | None, quoted: int = 0) -> str: ...
    def key_list(self, key: str, values: tuple[str, ...], sep: str = ' ', quoted: int = 0) -> str: ...

class ObjectClass(SchemaElement):
    schema_attribute: str
    known_tokens: ClassVar[list[str]]
    obsolete: bool
    must: tuple[str, ...]
    may: tuple[str, ...]
    kind: int
    sup: tuple[str, ...]
    x_origin: tuple[str, ...]

AttributeUsage: Incomplete

class AttributeType(SchemaElement):
    schema_attribute: str
    known_tokens: ClassVar[list[str]]
    obsolete: bool
    single_value: bool
    collective: bool
    syntax: str | None
    no_user_mod: bool
    usage: int
    sup: tuple[str, ...]
    equality: str | None
    ordering: str | None
    substr: str | None
    x_origin: tuple[str, ...]
    x_ordered: str | None

class LDAPSyntax(SchemaElement):
    schema_attribute: str
    known_tokens: ClassVar[list[str]]
    not_human_readable: bool

class MatchingRule(SchemaElement):
    schema_attribute: str
    known_tokens: ClassVar[list[str]]
    obsolete: bool
    syntax: str | None

class MatchingRuleUse(SchemaElement):
    schema_attribute: str
    known_tokens: ClassVar[list[str]]
    obsolete: bool
    applies: tuple[str, ...]

class DITContentRule(SchemaElement):
    schema_attribute: str
    known_tokens: ClassVar[list[str]]
    obsolete: bool
    aux: tuple[str, ...]
    must: tuple[str, ...]
    may: tuple[str, ...]
    nots: tuple[str, ...]

class DITStructureRule(SchemaElement):
    schema_attribute: str
    known_tokens: ClassVar[list[str]]
    ruleid: str
    obsolete: bool
    form: str | None
    sup: tuple[str, ...]

    def set_id(self, element_id: str) -> None: ...
    def get_id(self) -> str: ...

class NameForm(SchemaElement):
    schema_attribute: str
    known_tokens: ClassVar[list[str]]
    obsolete: bool
    oc: str | None
    must: tuple[str, ...]
    may: tuple[str, ...]

class Entry(EntryBase):
    data: dict[tuple[str, ...], list[bytes]]
    dn: Incomplete

    def __init__(self, schema: ldap.schema.subentry.SubSchema, dn: str, entry: LDAPEntryDict) -> None: ...
    def __contains__(self, nameoroid: object) -> bool: ...
    def __getitem__(self, nameoroid: object) -> list[bytes]: ...
    def __setitem__(self, nameoroid: object, attr_values: list[bytes]) -> None: ...
    def __delitem__(self, nameoroid: object) -> None: ...
    def __len__(self) -> int: ...
    def has_key(self, nameoroid: str) -> bool: ...
    def keys(self) -> KeysView[str]: ...
    def items(self) -> ItemsView[str, list[bytes]]: ...
    def __iter__(self) -> Iterator[str]: ...
    def attribute_types(
        self, attr_type_filter: list[tuple[str, list[str]]] | None = None, raise_keyerror: int = 1
    ) -> tuple[cidict[AttributeType | None], cidict[AttributeType | None]]: ...
