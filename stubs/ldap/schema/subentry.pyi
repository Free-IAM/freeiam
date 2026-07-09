from collections.abc import Iterable
from typing import Any, TypeVar

from _typeshed import Incomplete
from ldap.cidict import cidict as cidict
from ldap.schema.models import (
    AttributeType as AttributeType,
    DITContentRule as DITContentRule,
    ObjectClass as ObjectClass,
    SchemaElement as SchemaElement,
)
from ldap.types import LDAPEntryDict as LDAPEntryDict

SCHEMA_CLASS_MAPPING: cidict[type[SchemaElement]]
SCHEMA_ATTR_MAPPING: dict[type[SchemaElement], str]
SchemaElementSubclass = TypeVar('SchemaElementSubclass', bound=SchemaElement)
SCHEMA_ATTRS: Incomplete

class SubschemaError(ValueError): ...

class OIDNotUnique(SubschemaError):
    desc: Incomplete
    def __init__(self, desc: str) -> None: ...

class NameNotUnique(SubschemaError):
    desc: Incomplete
    def __init__(self, desc: str) -> None: ...

class SubSchema:
    name2oid: dict[type[SchemaElement], cidict[str]]
    sed: dict[type[SchemaElement], dict[str, SchemaElement]]
    non_unique_names: dict[type[SchemaElement], cidict[None]]
    non_unique_oids: Incomplete
    def __init__(self, sub_schema_sub_entry: LDAPEntryDict, check_uniqueness: int = 1) -> None: ...
    def ldap_entry(self) -> dict[str, list[str]]: ...
    def listall(
        self, schema_element_class: type[SchemaElement], schema_element_filters: Iterable[tuple[str, Iterable[str | int]]] | None = None
    ) -> list[str]: ...
    def tree(
        self, schema_element_class: type[ObjectClass | AttributeType], schema_element_filters: Iterable[tuple[str, Iterable[str | int]]] | None = None
    ) -> cidict[list[str]]: ...
    def getoid(self, se_class: type[SchemaElementSubclass], nameoroid: str, raise_keyerror: int = 0) -> str: ...
    def get_inheritedattr(self, se_class: type[SchemaElementSubclass], nameoroid: str, name: str) -> Any: ...
    def get_obj(
        self, se_class: type[SchemaElementSubclass], nameoroid: str, default: SchemaElementSubclass | None = None, raise_keyerror: int = 0
    ) -> SchemaElementSubclass | None: ...
    def get_inheritedobj(
        self, se_class: type[SchemaElementSubclass], nameoroid: str, inherited: list[str] | None = None
    ) -> SchemaElementSubclass | None: ...
    def get_syntax(self, nameoroid: str) -> str | None: ...
    def get_structural_oc(self, oc_list: Iterable[str]) -> str | None: ...
    def get_applicable_aux_classes(self, nameoroid: str) -> list[str]: ...
    def attribute_types(
        self,
        object_class_list: Iterable[str],
        attr_type_filter: Iterable[tuple[str, Iterable[str | int]]] | None = None,
        raise_keyerror: int = 1,
        ignore_dit_content_rule: int = 0,
    ) -> tuple[cidict[AttributeType | None], cidict[AttributeType | None]]: ...

def urlfetch(uri: str, trace_level: int = 0) -> tuple[str | None, SubSchema | None]: ...
