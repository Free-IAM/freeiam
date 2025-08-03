# SPDX-FileCopyrightText: 2025 Florian Best
# SPDX-License-Identifier: MIT OR Apache-2.0
"""LDAP Distinguished Name (DN) utilities."""

from __future__ import annotations

import functools
from typing import Self

import ldap.dn

from freeiam.errors import InvalidDN
from freeiam.ldap.constants import AVA, DNFormat


__all__ = ('DN',)


@functools.lru_cache
def _to_dn(dn):
    return ldap.dn.str2dn(dn)


class DN:
    """A LDAP Distinguished Name."""

    _CASE_INSENSITIVE_ATTRIBUTES = ('c', 'cn', 'dc', 'l', 'o', 'ou', 'uid')

    __slots__ = ('_cached_hash', '_cached_normalized', '_dn', '_format', 'dn')

    @classmethod
    def get(cls, dn: Self | str) -> Self:
        """Get a DN from string or existing DN."""
        return cls(dn) if isinstance(dn, str) else dn

    @classmethod
    def escape(cls, value: str):
        """Escape LDAP DN value."""
        return ldap.dn.escape_dn_chars(value)

    @classmethod
    def compose(cls, *parts):
        """
        Compose a DN from different segments.

        >>> base = DN('dc=freeiam,dc=org')
        >>> str(DN.compose(('cn', 'admin'), 'ou=foo,ou=bar', base))
        "cn=admin,ou=foo,ou=bar,dc=freeiam,dc=org"
        """
        rdns = []
        for part in parts:
            if isinstance(part, DN):
                rdns.extend(part.rdns)
            elif isinstance(part, str):
                rdns.extend(cls(part).rdns)
            elif isinstance(part, tuple):
                rdns.append([[*part[:3], AVA.String][:3]])
        return cls(*parts)

    @classmethod
    def normalize(cls, dn: Self | str) -> str:
        """Normalize DN."""
        return str(cls.get(dn))

    @classmethod
    def get_unique(cls, dns: list[str]) -> set[Self]:
        """
        Return a unique set of DNs.

        >>> len(DN.unique(['CN=users,dc=freeiam,dc=org', 'cn=users,dc=freeiam,dc=org', 'cn = users,dc=freeiam,dc=org', 'CN=Users,dc=freeiam,dc=org']))
        1
        """
        return {cls(dn) for dn in dns}

    @classmethod
    def get_unique_str(cls, dns: list[Self]) -> set[str]:
        """
        Return a unique set of DN strings from DNs.

        >>> DN.get_unique_str(DN.unique(['cn=foo', 'cn=bar']) - DN.unique(['cn = foo'])) == {'cn=bar'}
        True
        """
        return {str(dn) for dn in dns}

    @property
    def rdn(self) -> Self:
        """
        Get attr and value of the first RDN component.

        >>> DN('cn=foo,cn=bar').rdn
        ('cn', 'foo')
        """
        return self.multi_rdn[0]

    @property
    def multi_rdn(self) -> Self:
        """
        Get all attrs and values of the RDN.

        >>> DN('uid=1+cn=2,dc=3').rdn
        (('uid', '1'), ('cn', '2'))
        """
        return tuple(tuple(rdn[:2]) for rdn in self._dn[0])

    @property
    def rdns(self) -> list[list[tuple[str, str, int]]]:
        """Get the single RDN items."""
        return self._dn

    @property
    def parent(self) -> Self | None:
        """
        Get the parent DN.

        >>> DN('cn=item,cn=parent').parent == DN('cn=parent')
        True
        """
        if len(self._dn) > 1:
            return self[1:]
        return None

    def __init__(self, dn: str, format: DNFormat = None) -> None:  # noqa: A002
        self.dn = dn
        self._format = format
        self._cached_hash = None
        self._cached_normalized = None
        try:
            self._dn = _to_dn(self.dn)
        except ldap.DECODING_ERROR:
            try:
                self._dn = _to_dn(self.dn.replace(r'\?', '?'))  # Samba LDAP returns broken DN
            except ldap.DECODING_ERROR as exc:
                err = InvalidDN(exc)
                err._description = 'Malformed DN syntax'
                err._info = f'{self.dn!r}: {exc}'.removesuffix(': ')
                raise err from exc

    def get_parent(self, end: Self | str) -> Self | None:
        """
        Get the parent DN until a certain base.

        >>> base = DN('dc=freeiam,dc=org')
        >>> DN('cn=foo,dc=freeiam,dc=org').get_parent(base) == base
        True
        >>> DN('dc=freeiam,dc=org').get_parent(base)
        None
        """
        if not self.endswith(end) or self == end:
            return None
        return self.parent

    def endswith(self, other: Self | str) -> bool:
        """
        Check if DN ends with another base DN.

        >>> DN('cn=foo,cn=bar').endswith('cn=bar')
        True
        >>> DN('cn=foo,cn=bar').endswith('cn=foo')
        False
        >>> DN('cn=foo').endswith('cn=foo,cn=bar')
        False
        >>> DN('cn=foo,cn=bar').endswith('')
        True
        """
        other = self.get(other)
        return self[-len(other) or len(self) :] == other

    def startswith(self, other: Self | str):
        """
        Check if DN starts with another DN.

        >>> DN('cn=foo,cn=bar').startswith('cn=foo')
        True
        >>> DN('cn=foo,cn=bar').startswith('cn=bar')
        False
        >>> DN('cn=foo,cn=bar').startswith('')
        True
        """
        other = self.get(other)
        return self[: len(other)] == other

    def walk(self, base: Self | str | None = None):
        """
        Walk the reversed DN components from the given base.

        >>> [str(x) for x in DN('cn=foo,cn=bar,cn=baz,cn=blub').walk('cn=baz,cn=blub')]
        ['cn=baz,cn=blub', 'cn=bar,cn=baz,cn=blub', 'cn=foo,cn=bar,cn=baz,cn=blub']
        >>> [str(x) for x in DN('cn=foo,cn=bar,cn=baz,cn=blub').walk()]
        ['cn=blub', 'cn=baz,cn=blub', 'cn=bar,cn=baz,cn=blub', 'cn=foo,cn=bar,cn=baz,cn=blub']
        """
        base = self.get(base or '')
        if not self.endswith(base):
            msg = 'DN does not end with given base'
            raise ValueError(msg)

        for i in reversed(range(len(self) - (len(base) or 1) + 1)):
            yield self[i:]

    def __str__(self) -> str:
        """
        Get a normalized string representation of the DN.

        >>> str(DN('cn = foo , cn = bar')) == "cn=foo,cn=bar"
        True
        """
        if self._cached_normalized is None:
            self._cached_normalized = ldap.dn.dn2str(self._dn)
        return self._cached_normalized

    def __repr__(self) -> str:
        """
        Get a representation.

        >>> repr(DN('cn=foo,cn=bar')) == "<DN 'cn=foo,cn=bar'>"
        True
        """
        return f'<{type(self).__name__} {self}>'

    def __len__(self) -> int:
        """Return number of components of the DN."""
        return len(self._dn)

    def __getitem__(self, key: str | slice) -> Self:
        """Get slice or item of the DN components."""
        if isinstance(key, slice):
            return self.__class__(ldap.dn.dn2str(self._dn[key]))
        return self.__class__(ldap.dn.dn2str([self._dn[key]]))

    def __eq__(self, other: Self | str) -> bool:
        """
        Check normalized DNs for equality.

        >>> DN('cn=foo') == DN('cn=foo')
        True
        >>> DN('cn=foo') == DN('cn=bar')
        False
        >>> DN('Cn=Foo') == DN('cn=foo')
        True
        >>> DN('Cn=foo') == DN('cn=bar')
        False
        >>> DN('uid=Administrator') == DN('uid=administrator')
        True
        >>> DN('foo=Foo') == DN('foo=foo')
        False
        >>> DN('cn=foo,cn=bar') == DN('cn=foo,cn=bar')
        True
        >>> DN('cn=bar,cn=foo') == DN('cn=foo,cn=bar')
        False
        >>> DN('cn=foo+cn=bar') == DN('cn=foo+cn=bar')
        True
        >>> DN('cn=bar+cn=foo') == DN('cn=foo+cn=bar')
        True
        >>> DN('cn=bar+Cn=foo') == DN('cn=foo+Cn=bar')
        True
        >>> DN(r'cn=%s31foo' % chr(92)) == DN(r'cn=1foo')
        True
        """
        return hash(self) == hash(DN(other) if isinstance(other, str) else other)

    def __ne__(self, other: Self | str) -> bool:
        return not self == other

    def __hash__(self) -> str:
        if self._cached_hash is None:
            self._cached_hash = hash(tuple(
                tuple(sorted(
                    (attr.lower(), val.lower() if attr.lower() in self._CASE_INSENSITIVE_ATTRIBUTES else val, ava)
                    for attr, val, ava in rdn
                )) for rdn in self._dn
            ))  # fmt: skip
        return self._cached_hash

    def __add__(self, other):
        return self.__class__(f'{self},{other}')
