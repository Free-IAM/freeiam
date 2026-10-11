# SPDX-FileCopyrightText: 2025 Florian Best
# SPDX-License-Identifier: MIT OR Apache-2.0
"""LDAP attributes."""

import contextlib
import typing

from freeiam.ldap.schema import Schema


class Attributes(dict[str, list[bytes]]):  # noqa: FURB189
    """A mapping of LDAP attribute names to values."""

    ALIASES: typing.ClassVar[dict[str, str]] = {}
    SCHEMA: Schema | None = None

    def __getitem__(self, key: str) -> list[bytes]:
        with contextlib.suppress(KeyError):
            return super().__getitem__(key)
        return self.__missing__(key)

    def __missing__(self, key: str) -> list[bytes]:
        key = self.ALIASES.get(key, key)
        return {k.lower(): v for k, v in self.items()}[key.lower()]

    @classmethod
    def set_schema(cls, subschema: Schema) -> None:
        """Set attribute aliases from the schema."""
        cls.SCHEMA = subschema
        cls.ALIASES.update(subschema.get_attribute_aliases())
