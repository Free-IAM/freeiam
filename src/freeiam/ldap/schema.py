# SPDX-FileCopyrightText: 2025 Florian Best
# SPDX-License-Identifier: MIT OR Apache-2.0
"""LDAP Schemata."""

from ldap.schema import AttributeType, ObjectClass


class Schema:
    """LDAP Schemata."""

    __slots__ = ('_schema',)

    def __init__(self, schema):
        self._schema = schema

    def get_object_class(self, name):
        """Get object class by name."""
        for oc in self.get_object_classes():
            if name in oc.names:
                return oc
        return None

    def get_object_class_by_oid(self, oid):
        """Get object class by OID."""
        return self._schema.get_obj(ObjectClass, oid)

    def get_object_classes(self):
        """Get all object classes."""
        for oid in self._schema.listall(ObjectClass):
            yield self.get_object_class_by_oid(oid)

    def get_attribute(self, name):
        """Get attribute by name."""
        for attr in self.get_attributes():
            if name in attr.names:
                return attr
        return None

    def get_attributes(self):
        """Get all attributes."""
        for oid in self._schema.listall(AttributeType):
            yield self._schema.get_obj(AttributeType, oid)

    def get_attribute_aliases(self) -> dict:
        """Get aliases of attribute names."""
        return {
            alias: attr.names[0]
            for attr in self.get_attributes()
            for alias in attr.names[1:]
            if len(attr.names) > 1
        }  # fmt: skip
