# SPDX-FileCopyrightText: 2025 Florian Best
# SPDX-License-Identifier: MIT OR Apache-2.0
"""LDAP filter expressions."""

import enum
import operator
import re
import string
from collections import deque
from collections.abc import Callable, Sequence
from typing import Any, Self, TypeVar

import lark
import ldap.filter
from lark import Lark, Transformer, v_args

from freeiam import errors


__all__ = (
    'AND',
    'NOT',
    'OR',
    'ApproximateMatch',
    'Assertion',
    'EqualityMatch',
    'ExtensibleMatch',
    'Filter',
    'GreaterOrEqual',
    'LessOrEqual',
    'Operator',
    'PresenceMatch',
    'SubstringMatch',
)


LDAP_FILTER_GRAMMAR = r"""
start: _group | bare
bare: comparison
_group: ws? (operator | expression) ws?

STAR: "*"

?operator: and_operator | or_operator | not_operator

expression: "(" ows comparison ")"
and_operator: "(" ows "&" ows groups ows ")"
or_operator:  "(" ows "|" ows groups ows ")"
not_operator: "(" ows "!" ows _group  ows ")"
?groups: _group* -> groups

?comparison: attr "=" STAR                      -> presence
     | attr "="  value                          -> equality
     | attr "="  substrings                     -> substring
     | attr ">=" value                          -> ge
     | attr "<=" value                          -> le
     | attr "~=" value                          -> approx
     |      ":"  dn ":" matchingrule ":=" value -> extmatch_noattr_dn_match
     | attr ":"  dn ":" matchingrule ":=" value -> extmatch_attr_dn_match
     | attr ":"  dn                  ":=" value -> extmatch_attr_dn_nomatch
     |      ":"         matchingrule ":=" value -> extmatch_noattr_nodn_match
     | attr ":"         matchingrule ":=" value -> extmatch_attr_nodn_match
     | attr                          ":=" value -> extmatch_attr_nodn_nomatch

substrings: _value STAR (_value STAR)* _value?
          | STAR _value (STAR _value)* STAR?

attr: /[a-zA-Z][a-zA-Z0-9-;]*/ | oid
?oid: /\d+[\.\d]*/
!dn: "dn"i
matchingrule: attr

_value: /([^\x00()*\\]|\\\\[0-9a-fA-F]{2}|\\[0-9a-fA-F]{2})+/
value: _value?

ows: ws?
ws: WS
%import common.WS
%import common.HEXDIGIT
"""

_ASCII_LIMIT = 128


class EscapeMode(enum.IntEnum):
    """Escape mode."""

    SPECIAL = 0
    r"""Escapes only the special characters defined in RFC 4515 (\, *, (, ), \x00)."""

    RESTRICTED = 1
    """
    Escapes all characters except for safe ASCII alphanumerics (0-9, A-Z, a-z)
    and a limited set of punctuation. Intended to allow only a small, controlled character set in filter values.
    """

    ALL = 2
    """Escapes every character, including all ASCII characters. Produces a fully hexadecimal-escaped filter value."""


class WalkStrategy(enum.IntEnum):
    """Traversal strategy."""

    BOTH = 0
    POST = 1
    PRE = 2


class Token(str):  # noqa: FURB189
    __slots__ = ()

    def copy(self) -> Self:
        return self  # pragma: no cover


class Attribute:
    """An LDAP attribute."""

    __slots__ = ('attribute', 'dn', 'eq', 'matchingrule')

    ALLOWED_CHARS = string.ascii_letters + string.digits + ';-.'
    ALLOWED_OID = string.digits + '.'

    @property
    def approx(self) -> Self:
        return type(self)(self.attribute, self.dn, self.matchingrule, _equality_method=Filter.get_approx)

    def extensible(self, dn: bool = False, matchingrule: str | None = None) -> Self:
        return type(self)(self.attribute, dn, matchingrule)

    def __init__(
        self,
        attribute: str,
        dn: bool = False,
        matchingrule: str | None = None,
        *,
        _equality_method: Callable[[str, str], 'SubstringMatch | EqualityMatch | ExtensibleMatch | ApproximateMatch'] | None = None,
    ) -> None:
        self.attribute = attribute
        self.dn = dn
        self.matchingrule = matchingrule
        if _equality_method:
            self.eq = _equality_method
        elif dn or matchingrule:
            self.eq = self.eq_ext
        else:
            self.eq = Filter.get_eq
        if attribute.strip(self.ALLOWED_CHARS) or (attribute[0].isdigit() and attribute.strip(self.ALLOWED_OID)):
            raise ValueError(attribute)
        if matchingrule and (matchingrule.strip(self.ALLOWED_CHARS) or (matchingrule[0].isdigit() and matchingrule.strip(self.ALLOWED_OID))):
            raise ValueError(matchingrule)

    def eq_ext(self, attr: str, value: str) -> 'ExtensibleMatch':
        return Filter.get_extensible(attr, self.dn, self.matchingrule, value)

    def __eq__(self, other: str) -> 'SubstringMatch | EqualityMatch | ExtensibleMatch | ApproximateMatch':  # type: ignore[override]  # ty: ignore[invalid-method-override]
        if isinstance(other, (list, tuple)):
            return Filter.get_substring(self.attribute, *other)
        return self.eq(self.attribute, other)

    def __ne__(self, other: Sequence[str] | None) -> 'NOT | PresenceMatch':  # type: ignore[override]  # ty: ignore[invalid-method-override]
        if other is None:
            return Filter.get_pres(self.attribute)
        return Filter.get_not(self == other)  # type: ignore[arg-type]  # ty: ignore[invalid-argument-type]

    def __gt__(self, other: str | int) -> 'NOT | GreaterOrEqual':
        return Filter.get_gt(self.attribute, other)

    def __ge__(self, other: str | int) -> 'GreaterOrEqual':
        return Filter.get_gt_eq(self.attribute, other)

    def __lt__(self, other: str | int) -> 'NOT | LessOrEqual':
        return Filter.get_lt(self.attribute, other)

    def __le__(self, other: str | int) -> 'LessOrEqual':
        return Filter.get_lt_eq(self.attribute, other)

    def __hash__(self) -> int:
        return hash((type(self), self.attribute, self.dn, self.matchingrule))


class Expression:
    """Base class for any expression."""

    __slots__ = ()

    def __or__(self, other: Sequence['Expression']) -> 'OR':
        expr = other
        if not isinstance(other, Sequence):
            expr = [expr]
        return Filter.get_or(self, *expr)

    def __and__(self, other: Sequence['Expression']) -> 'AND':
        expr = other
        if not isinstance(other, Sequence):
            expr = [expr]

        return Filter.get_and(self, *expr)

    def negate(self) -> 'NOT':
        return Filter.get_not(self)

    def copy(self) -> Self:
        raise NotImplementedError()  # pragma: no cover


class Assertion(Expression):
    """Base class for comparison operators."""

    __slots__ = ('_lead', '_raw_escaped_value', 'attr')
    expression = ''
    operator: Callable[..., bool] | None = None

    _raw_escaped_value: bytes | None
    """The original raw escaped(!) value - not suitable for comparison."""

    def __init__(self, attr: str) -> None:
        self.attr = attr
        self._raw_escaped_value = None
        self._lead = ''

    @property
    def _assertion_value(self) -> bytes | None:
        return self._raw_escaped_value

    @property
    def _extensible_suffix(self) -> str:
        return ''

    @property
    def escaped(self) -> str:
        """Get the value in an encoded or escaped representation."""
        if self._raw_escaped_value is not None:
            return self._raw_escaped_value.decode('UTF-8')
        return self.escape_bytes(self._assertion_value or b'')

    def copy(self) -> Self:
        """Copy the object (without preserving optional whitespace)."""
        raise NotImplementedError()  # pragma: no cover

    def __str__(self) -> str:
        return f'{self._lead}{self.attr}{self._extensible_suffix}{self.expression}{self.escaped}'

    def __repr__(self) -> str:
        val = self._assertion_value
        value = f'escape({val!r})' if val else ''
        return f'{type(self).__name__}({self.attr}{self._extensible_suffix}{self.expression}{value})'

    def __hash__(self) -> int:
        return hash((type(self), self.attr.casefold(), self._assertion_value))

    def __eq__(self, other: object) -> bool:
        if not isinstance(other, Assertion):
            return NotImplemented

        return (
            type(self),
            self.attr.casefold(),
            self._assertion_value,
        ) == (
            type(other),
            other.attr.casefold(),
            other._assertion_value,
        )

    # @classmethod
    # def escape(cls, value: str) -> str:
    #     """Escaped value for use in filter."""
    #     if value != value.strip():
    #         return Filter.escape(value, EscapeMode.RESTRICTED)
    #     return Filter.escape(value, EscapeMode.SPECIAL)

    @classmethod
    def escape_bytes(cls, value: bytes) -> str:
        """Escaped value for use in filter."""
        if value != value.strip():
            return Filter.escape_bytes(value, EscapeMode.RESTRICTED)
        return Filter.escape_bytes(value, EscapeMode.SPECIAL)


class ValueAssertion(Assertion):
    """Abstaract base class for value based assertions."""

    __slots__ = ('_value',)

    @classmethod
    def from_escaped(cls, attr: str, value: bytes) -> Self:
        """Create an assertion from an RFC 4515 escaped value."""
        obj = cls(attr, Filter.unescape(value))
        obj._raw_escaped_value = value
        return obj

    def __init__(self, attr: str, value: bytes) -> None:
        super().__init__(attr)
        self._value = value

    def decode(self, encoding: str = 'utf-8', errors: str = 'strict') -> str:
        """
        Decode the assertion bytes using the specified character encoding.

        The caller is responsible for choosing an encoding appropriate
        for the LDAP attribute syntax.
        """
        return self.value.decode(encoding, errors)

    def copy(self) -> Self:
        """Copy the object (without preserving optional whitespace)."""
        return type(self)(self.attr, self._value)

    @property
    def _assertion_value(self) -> bytes:
        return self._value

    @property
    def value(self) -> bytes:
        """Get the value in a unescaped representation."""
        return self._value

    @value.setter
    def value(self, _value: bytes) -> None:
        """Set the value in a unescaped representation."""
        self._value = _value
        self._raw_escaped_value = None


class EqualityMatch(ValueAssertion):
    """Compare for equality (attr=value)."""

    expression = '='
    operator = operator.eq


class GreaterOrEqual(ValueAssertion):
    """Compare for greater than or equal to a value (attr>=value)."""

    expression = '>='
    operator = operator.ge


class LessOrEqual(ValueAssertion):
    """Compare for less than or equal to a value (attr<=value)."""

    expression = '<='
    operator = operator.le


class ApproximateMatch(ValueAssertion):
    """Compare approximately (attr~=value)."""

    expression = '~='


class SubstringMatch(Assertion):
    """Compare a substring match (attr=*val*ue*)."""

    __slots__ = ('_any', '_final', '_initial')

    expression = '='
    operator = operator.contains

    @property
    def initial(self) -> bytes | None:
        """Return the initial substring component."""
        return self._initial

    @initial.setter
    def initial(self, value: bytes | None) -> None:
        self._initial = value
        self._raw_escaped_value = None

    @property
    def any(self) -> tuple[bytes, ...]:
        """Return the intermediate substring components."""
        return self._any

    @any.setter  # noqa: A003
    def any(self, values: Sequence[bytes]) -> None:
        self._any = tuple(values)
        self._raw_escaped_value = None

    @property
    def final(self) -> bytes | None:
        """Return the final substring component."""
        return self._final

    @final.setter
    def final(self, value: bytes | None) -> None:
        self._final = value
        self._raw_escaped_value = None

    def __init__(self, attr: str, *, initial: bytes | None = None, any: Sequence[bytes] = (), final: bytes | None = None) -> None:  # noqa: A002
        super().__init__(attr)

        self._initial = initial
        self._any = tuple(any)
        self._final = final

        if self._initial is None and not self._any and self._final is None:
            raise ValueError('SubstringMatch requires at least one component')  # noqa: TRY003

    @classmethod
    def from_escaped(cls, attr: str, value: bytes, *, initial: bytes | None = None, any: Sequence[bytes] = (), final: bytes | None = None) -> Self:  # noqa: A002
        """Create an assertion from an RFC 4515 escaped value."""
        obj = cls(
            attr,
            initial=Filter.unescape(initial) if initial is not None else initial,
            any=tuple(Filter.unescape(val) for val in any),
            final=Filter.unescape(final) if final is not None else final,
        )
        obj._raw_escaped_value = value
        return obj

    def decode(self, encoding: str = 'utf-8', errors: str = 'strict') -> tuple[str, ...]:
        """Get decoded values."""
        return tuple(val.decode(encoding, errors) for val in self.values)

    @property
    def values(self) -> tuple[bytes, ...]:
        """Return substring assertion values."""
        return (self.initial or b'', *self.any, self.final or b'')

    @property
    def escaped(self) -> str:
        """Get the value in an encoded or escaped representation."""
        if self._raw_escaped_value is not None:
            # we already have the original escaped representation
            return self._raw_escaped_value.decode('UTF-8')
        return '*'.join([
            self.escape_bytes(self.initial or b''),
            *(Filter.escape_bytes(part) for part in self.any),
            self.escape_bytes(self.final or b''),
        ])

    def __repr__(self) -> str:
        val = f'initial={self.initial!r}, any={self.any!r}, final={self.final!r}'
        return f'{type(self).__name__}({self.attr}{self._extensible_suffix}{self.expression}escape({val}))'

    def __eq__(self, other: object) -> bool:
        if not isinstance(other, SubstringMatch):
            return NotImplemented

        return (
            type(self),
            self.attr.casefold(),
            self.initial,
            self.any,
            self.final,
        ) == (
            type(other),
            other.attr.casefold(),
            other.initial,
            other.any,
            other.final,
        )

    def __hash__(self) -> int:
        return hash((type(self), self.attr.casefold(), self.initial, self.any, self.final))

    def copy(self) -> Self:
        """Copy the object (without preserving optional whitespace)."""
        return type(self)(self.attr, initial=self.initial, any=self.any, final=self.final)


class PresenceMatch(Assertion):
    """Compare for presence (attr=*)."""

    expression = '=*'

    @classmethod
    def from_escaped(cls, attr: str) -> Self:
        """Create an assertion from an RFC 4515 escaped value."""
        return cls(attr)

    @property
    def escaped(self) -> str:
        """Get the value in an encoded or escaped representation."""
        return ''

    def copy(self) -> Self:
        """Copy the object (without preserving optional whitespace)."""
        return type(self)(self.attr)

    @property
    def _assertion_value(self) -> None:
        return None


class ExtensibleMatch(ValueAssertion):
    """Comparison with an extensible match (attr:dn:rule:=value)."""

    expression = ':='
    __slots__ = ('dn', 'matchingrule')

    @classmethod
    def from_escaped(cls, attr: str, value: bytes, dn: bool | str = False, matchingrule: str | None = None) -> Self:
        """Create an assertion from an RFC 4515 escaped value."""
        obj = cls(attr, Filter.unescape(value), dn, matchingrule)
        obj._raw_escaped_value = value
        return obj

    def __init__(self, attr: str, value: bytes, dn: bool | str, matchingrule: str | None) -> None:
        super().__init__(attr, value)
        self.dn = dn if isinstance(dn, str) else ('dn' if dn else False)
        self.matchingrule = matchingrule
        if not self.attr and not self.matchingrule:
            raise ValueError()

    @property
    def _extensible_suffix(self) -> str:
        suffix = f':{self.dn}' if self.dn else ''
        if self.matchingrule:
            suffix += f':{self.matchingrule}'
        return suffix

    def copy(self) -> Self:
        """Copy the object (without preserving optional whitespace)."""
        return type(self)(self.attr, self.value, self.dn, self.matchingrule)

    def __eq__(self, other: object) -> bool:
        if not isinstance(other, ExtensibleMatch):
            return False
        matchingrule = self.matchingrule.casefold() if self.matchingrule is not None else None
        other_rule = other.matchingrule.casefold() if other.matchingrule is not None else None
        return (self.attr.casefold(), self.value, bool(self.dn), matchingrule) == (other.attr.casefold(), other.value, bool(other.dn), other_rule)

    def __hash__(self) -> int:
        matchingrule = self.matchingrule.casefold() if self.matchingrule is not None else None
        return hash((type(self), self.attr.casefold(), self.value, bool(self.dn), matchingrule))


class Container(Expression):
    """A group of one expression without brackets."""

    __slots__ = ('_expressions', '_sep')
    operator: Callable[..., bool] | None = None
    expression = ''

    @property
    def operators(self) -> tuple['AND | OR | NOT', ...]:
        """Get all operator expressions."""
        return tuple(op for op in self._expressions if isinstance(op, (AND, OR, NOT)))

    @property
    def comparisons(self) -> tuple[Assertion, ...]:
        """Get all comparison expressions."""
        return tuple(op for op in self._expressions if isinstance(op, Assertion))

    @property
    def expressions(self) -> tuple['Assertion | AND | OR | NOT', ...]:
        """Get all comparison or operator expressions."""
        return tuple(op for op in self._expressions if isinstance(op, (Assertion, AND, OR, NOT)))

    def __init__(self, /, expressions: list[Expression | Token], *, sep: Token | None = None):
        self._expressions = expressions
        self._sep = sep

    def copy(self) -> Self:
        """Copy the object (without preserving optional whitespace)."""
        return type(self)([e.copy() for e in self._expressions])

    def append(self, expression: Expression) -> None:
        """Append to the operator list."""
        self._expressions.append(expression)

    def insert(self, expression: Expression, index: int = 0) -> None:
        """Insert an expression into the operator list."""
        self._expressions.insert(index, expression)

    def replace(self, expression: Expression, replacement: Expression) -> None:
        """Replace an expression in the operator list."""
        index = next((i for i, e in enumerate(self._expressions) if e is expression), None)
        if index is None:  # pragma: no cover
            raise ValueError('Not in expressions', expression)  # noqa: TRY003
        self._expressions[index] = replacement

    def remove(self, expression: Expression) -> None:
        """Remove an expression from the operator list."""
        index = next((i for i, e in enumerate(self._expressions) if e is expression), None)
        if index is None:  # pragma: no cover
            raise ValueError('Not in expressions', expression)  # noqa: TRY003
        self._expressions.pop(index)

    def __str__(self) -> str:
        return ''.join(str(expr) for expr in self._expressions)

    def __repr__(self) -> str:
        exprs = f' {self.expression} '.join(repr(x) for x in self._expressions)
        return f'{type(self).__name__}( {exprs} )'


class Group(Container):
    """A group of one expression within brackets."""

    def __str__(self) -> str:
        sep = self._sep or ''
        groups = ''.join(f'({expr})' if isinstance(expr, Assertion) else str(expr) for expr in self._expressions)
        return f'({self.expression}{sep}{groups})' if self.expression else groups


class Operator(Group):
    """A logical operator."""


class AND(Operator):
    """A group of AND conjunction expressions ``(&(...)(...))``."""

    operator = operator.and_
    expression = '&'


class OR(Operator):
    """A group of OR disjunction expressions ``(|(...)(...))``."""

    operator = operator.or_
    expression = '|'


class NOT(Operator):
    """A group of NOT negation expressions ``(!( ... ))``."""

    operator = operator.not_
    expression = '!'


class Filter:
    """An LDAP filter according to RFC 4515."""

    __slots__ = ('_debug', '_tree', 'ast', 'filter_expr')

    parser = Lark(LDAP_FILTER_GRAMMAR)
    RE_HEXESCAPE = re.compile(rb'\\([0-9A-Fa-f]{2})')

    def __init__(self, /, filter_expr: str | None, *, strict: bool = False, _debug: bool = False) -> None:
        # TODO: security: restrict length
        # TODO: security: restrict depth
        # TODO: security: restrict number of escape sequences
        self.filter_expr = filter_expr
        self.ast: Container
        self._tree: lark.Tree[lark.Token] | None = None
        self._debug = _debug
        self.parse(strict)

    @property
    def root(self) -> Expression | None:
        """The first object in the filter."""
        if self._tree is None:  # pragma: no cover
            return None
        for expr in self.ast._expressions:
            if isinstance(expr, Token):
                continue  # pragma: no cover
            return expr
        return None  # pragma: no cover

    def parse(self, strict: bool = False) -> None:
        """Parse."""
        if not self.filter_expr or self.filter_expr == ' ':
            self.ast = Container([])
            return
        transformer = _FilterTransformer(strict)
        try:
            self._tree = self.parser.parse(self.filter_expr)
            root = transformer.transform(self._tree)
            self.ast = Container([root])
        except lark.exceptions.LarkError:
            if self._debug:  # pragma: no cover
                raise
            raise self.error() from None
        if strict:
            self.walk(self._disallow_whitespace, self._disallow_whitespace)

    def _disallow_whitespace(self, fil: Self, parent: Expression, expr: Expression) -> None:  # noqa: ARG002
        if isinstance(expr, Assertion):
            if expr._lead:
                raise self.error()
        elif isinstance(expr, Operator) and expr._sep:  # pragma: no cover
            raise self.error()  # currently impossible, broken OWS

    def error(self) -> errors.FilterError:
        """Create a filter parsing error."""
        return errors.FilterError({'result': -7, 'desc': 'Bad search filter', 'info': str(self.filter_expr), 'ctrls': []})

    def pretty(self, indent: int = 0) -> str:
        """Transform the filter into a pretty-formatted representation."""

        def render(expr: Expression, level: int) -> str:
            pad = '  ' * level
            if isinstance(expr, Assertion):
                return f'{pad}({expr})'
            if isinstance(expr, (AND, OR)):
                head = f'{pad}({expr.expression}'
                children = '\n'.join(render(e, level + 1) for e in expr._expressions if not isinstance(e, Token))
                return f'{head}\n{children}\n{pad})'
            if isinstance(expr, NOT):
                head = f'{pad}({expr.expression}'
                children = ''.join(render(e, 0) for e in expr._expressions if not isinstance(e, Token))
                return f'{head}{children})'
            if isinstance(expr, (Group, Container)):
                return '\n'.join(render(e, level) for e in expr._expressions if not isinstance(e, Token))
            raise TypeError(f'Unexpected expression: {type(expr)}')  # noqa: TRY003,EM102  # pragma: no cover

        if self.root is None:
            return ''
        return render(self.root, indent)

    @classmethod
    def attr(cls, attr: str, dn: bool = False, matchingrule: str | None = None) -> Attribute:
        """Get attribute for comparison."""
        return Attribute(attr, dn, matchingrule)

    @classmethod
    def get_eq(cls, attr: str, value: str) -> EqualityMatch:
        """Get EqualityMatch."""
        return EqualityMatch(attr, value.encode('UTF-8'))

    @classmethod
    def get_approx(cls, attr: str, value: str) -> ApproximateMatch:
        """Get ApproximateMatch."""
        return ApproximateMatch(attr, value.encode('UTF-8'))

    @classmethod
    def get_pres(cls, attr: str) -> PresenceMatch:
        """Get PresenceMatch."""
        return PresenceMatch(attr)

    @classmethod
    def get_substring(cls, attr: str, *values: str) -> SubstringMatch:
        """Get SubstringMatch."""
        if len(values) < 2:  # noqa: PLR2004
            raise ValueError('Substring filter requires at least two parts')  # noqa: TRY003

        return SubstringMatch(
            attr,
            initial=values[0].encode('UTF-8') or None,
            any=tuple(av.encode('UTF-8') for av in values[1:-1]),
            final=values[-1].encode('UTF-8') or None,
        )

    @classmethod
    def get_gt_eq(cls, attr: str, value: str | int) -> GreaterOrEqual:
        """Get GreaterOrEqual."""
        return GreaterOrEqual(attr, str(value).encode('UTF-8'))

    @classmethod
    def get_gt(cls, attr: str, value: str | int) -> NOT | GreaterOrEqual:
        """Create an expression greater than the given value."""
        if isinstance(value, str):
            return cls.get_not(cls.get_lt_eq(attr, value))
        return cls.get_gt_eq(attr, value + 1)

    @classmethod
    def get_lt_eq(cls, attr: str, value: str | int) -> LessOrEqual:
        """Get LessOrEqual."""
        return LessOrEqual(attr, str(value).encode('UTF-8'))

    @classmethod
    def get_lt(cls, attr: str, value: str | int) -> NOT | LessOrEqual:
        """Create an expression less than the given value."""
        if isinstance(value, str):
            return cls.get_not(cls.get_gt_eq(attr, value))
        return cls.get_lt_eq(attr, value - 1)

    @classmethod
    def get_extensible(cls, attr: str, dn: bool, matchingrule: str | None, value: str) -> ExtensibleMatch:
        """Get ExtensibleMatch."""
        return ExtensibleMatch(attr, value.encode('UTF-8'), dn, matchingrule)

    @classmethod
    def get_not(cls, expression: Expression) -> NOT:
        """Get negation."""
        return NOT([expression])

    @classmethod
    def get_and(cls, *expressions: Expression) -> AND:
        """Get conjunction."""
        return AND(list(expressions))

    @classmethod
    def get_or(cls, *expressions: Expression) -> OR:
        """Get disjunction."""
        return OR(list(expressions))

    @classmethod
    def from_format(cls, format_string: str, values: list[str]) -> Self:
        """Get a Filter from a filter format string."""
        return cls(cls.escape_formatted(format_string, values))

    @classmethod
    def escape(cls, value: str, escape_mode: EscapeMode = EscapeMode.RESTRICTED) -> str:
        """Escape LDAP filter characters."""
        return ldap.filter.escape_filter_chars(value, escape_mode)

    @classmethod
    def escape_bytes(
        cls,
        value: bytes,
        escape_mode: EscapeMode = EscapeMode.SPECIAL,
    ) -> str:
        """
        Escape assertion bytes according to RFC 4515.

        :param value: Unescaped LDAP assertion bytes.
        :param escape_mode: Controls which bytes are escaped.
        :return: An RFC 4515 filter assertion value.
        """
        special = b'\x00\\*()'

        if escape_mode == EscapeMode.SPECIAL:
            return ''.join(f'\\{byte:02x}' if byte in special or byte >= _ASCII_LIMIT else chr(byte) for byte in value)

        if escape_mode == EscapeMode.RESTRICTED:
            return ''.join(chr(byte) if ord('0') <= byte <= ord('z') and byte not in special else f'\\{byte:02x}' for byte in value)

        if escape_mode == EscapeMode.ALL:
            return ''.join(f'\\{byte:02x}' for byte in value)

        msg = f'Invalid escape mode: {escape_mode!r}'
        raise ValueError(msg)

    @classmethod
    def unescape(cls, value: bytes) -> bytes:
        """Reverse the escaping of filter characters."""
        return cls.RE_HEXESCAPE.sub(
            lambda m: bytes([int(m.group(1), 16)]),
            value,
        )

    @classmethod
    def escape_formatted(cls, format_string: str, values: Sequence[str]) -> str:
        """Escape LDAP filter characters in format string."""
        return ldap.filter.filter_format(format_string, values)

    @classmethod
    def time_span_filter(cls, from_timestamp: int = 0, until_timestamp: int | None = None, delta_attr: str = 'modifyTimestamp') -> Self:
        """Get timespan filter e.g. '(&(modifyTimestamp>=19700101000000Z)(!(modifyTimestamp>=19700101000001Z)))'."""
        return cls(ldap.filter.time_span_filter('', from_timestamp, until_timestamp, delta_attr))

    def walk(
        self,
        comparison_callback: Callable[[Self, Container, Assertion], None] | None,
        operator_callback: Callable[[Self, Container, AND | OR | NOT | Container], None] | None,
        strategy: WalkStrategy = WalkStrategy.POST,
    ) -> None:
        """Walk the filter expressions and operator conjunctions iteratively."""
        stack = deque([(self.ast, self.root, True)])

        while stack:
            parent, expression, is_pre_visit = stack.pop()

            if isinstance(expression, Assertion):
                if comparison_callback:
                    comparison_callback(self, parent, expression)
            elif isinstance(expression, (Operator, Group, Container)):
                if is_pre_visit:
                    if operator_callback and strategy in {WalkStrategy.PRE, WalkStrategy.BOTH} and isinstance(expression, (AND, OR, NOT)):
                        operator_callback(self, parent, expression)

                    if operator_callback and strategy in {WalkStrategy.POST, WalkStrategy.BOTH} and isinstance(expression, (AND, OR, NOT)):
                        stack.append((parent, expression, False))

                    for child_expression in expression.expressions[::-1]:
                        stack.append((expression, child_expression, True))
                else:
                    assert operator_callback is not None  # noqa: S101
                    operator_callback(self, parent, expression)
            elif isinstance(expression, Token):  # pragma: no cover
                pass  # not possible in the root!?
            else:  # pragma: no cover
                raise TypeError(expression)

    def __repr__(self) -> str:
        return f'{type(self).__name__}({self.root!r})'

    def __str__(self) -> str:
        if self._tree is None:
            return self.filter_expr or ''
        return str(self.ast)

    # def _pretty(self):
    #     return self._tree.pretty()


T = TypeVar('T', bound='Assertion | EqualityMatch | GreaterOrEqual | LessOrEqual | ExtensibleMatch')
Z = TypeVar('Z', bound='Any')


@v_args(inline=True)
class _FilterTransformer(Transformer[lark.Token, Expression]):
    """Filter tree Transformer."""

    def __init__(self, strict: bool) -> None:
        self.__strict = strict
        super().__init__()

    def start(self, value: Expression) -> Expression:  # noqa: PLR6301
        if isinstance(value, Assertion):
            return Group([value])
        if isinstance(value, Container):
            return value
        raise TypeError(type(value))  # pragma: no cover

    def bare(self, cmp: Expression) -> Container:  # noqa: PLR6301
        return Container([cmp])

    def groups(self, *groups: Expression) -> list[Expression]:  # noqa: PLR6301
        return list(groups)

    def expression(self, ld: str, cmp: Assertion) -> Assertion:  # noqa: PLR6301
        cmp._lead = ld or ''
        return cmp

    def and_operator(self, sep: None, ld: Token, exprs: list[Expression], tr: Token) -> AND:
        return AND(self._filter([ld, *exprs, tr]), sep=sep)

    def or_operator(self, sep: None, ld: Token, exprs: list[Expression], tr: Token) -> OR:
        return OR(self._filter([ld, *exprs, tr]), sep=sep)

    def not_operator(self, sep: None, ld: Token, expr: Expression, tr: Token) -> NOT:
        return NOT(self._filter([ld, expr, tr]), sep=sep)

    def _filter(self, items: list[Z | None]) -> list[Z]:  # noqa: PLR6301
        return [item for item in items if item is not None]

    def attr(self, attr: lark.Token) -> str:  # noqa: PLR6301
        return str(attr)

    def value(self, value: lark.Token | str | None = None) -> str:  # noqa: PLR6301
        return str(value or '')

    @classmethod
    def equality(cls, attr: str, value: str) -> EqualityMatch:
        return EqualityMatch.from_escaped(attr, value.encode('UTF-8'))

    @classmethod
    def presence(cls, attr: str, _star: Token) -> PresenceMatch:
        return PresenceMatch.from_escaped(attr)

    @classmethod
    def substring(cls, attr: str, value: tuple[str | None, tuple[str, ...], str | None]) -> SubstringMatch:
        initial, any_values, final = value
        val = '*'.join([initial or '', *any_values, final or ''])
        return SubstringMatch.from_escaped(
            attr,
            val.encode('UTF-8'),
            initial=initial.encode('UTF-8') if initial is not None else initial,
            any=tuple(av.encode('UTF-8') for av in any_values),
            final=final.encode('UTF-8') if final is not None else final,
        )

    @classmethod
    def substrings(cls, *tokens: lark.Token) -> tuple[str | None, tuple[str, ...], str | None]:
        parts: list[str | None] = [None]

        for token in tokens:
            if token.type == 'STAR':
                parts.append(None)
            else:
                parts[-1] = str(token)

        return (
            parts[0],
            tuple(part for part in parts[1:-1] if part is not None),
            parts[-1],
        )

    @classmethod
    def ge(cls, attr: str, value: str) -> GreaterOrEqual:
        return GreaterOrEqual.from_escaped(attr, value.encode('UTF-8'))

    @classmethod
    def le(cls, attr: str, value: str) -> LessOrEqual:
        return LessOrEqual.from_escaped(attr, value.encode('UTF-8'))

    @classmethod
    def extmatch_attr_nodn_match(cls, attr: str, matchingrule: str, value: str) -> ExtensibleMatch:
        return ExtensibleMatch.from_escaped(attr, value.encode('UTF-8'), dn=False, matchingrule=matchingrule)

    @classmethod
    def extmatch_attr_dn_nomatch(cls, attr: str, dn: str, value: str) -> ExtensibleMatch:
        return ExtensibleMatch.from_escaped(attr, value.encode('UTF-8'), dn, '')

    @classmethod
    def extmatch_noattr_nodn_match(cls, matchingrule: str, value: str) -> ExtensibleMatch:
        if matchingrule.lower() == 'dn':
            raise RuntimeError()
        return ExtensibleMatch.from_escaped('', value.encode('UTF-8'), dn=False, matchingrule=matchingrule)

    @classmethod
    def extmatch_attr_nodn_nomatch(cls, attr: str, value: str) -> ExtensibleMatch:
        return ExtensibleMatch.from_escaped(attr, value.encode('UTF-8'), dn=False, matchingrule='')

    @classmethod
    def extmatch_attr_dn_match(cls, attr: str, dn: str, matchingrule: str, value: str) -> ExtensibleMatch:
        return ExtensibleMatch.from_escaped(attr, value.encode('UTF-8'), dn, matchingrule)

    @classmethod
    def extmatch_noattr_dn_match(cls, dn: str, matchingrule: str, value: str) -> ExtensibleMatch:
        return ExtensibleMatch.from_escaped('', value.encode('UTF-8'), dn, matchingrule)

    @classmethod
    def approx(cls, attr: str, value: str) -> ApproximateMatch:
        return ApproximateMatch.from_escaped(str(attr), value.encode('UTF-8'))

    @classmethod
    def dn(cls, value: str = 'dn') -> str:
        return value

    @classmethod
    def matchingrule(cls, value: str) -> str:
        return value

    @classmethod
    def ws(cls, value: str) -> Token:
        return Token(value)

    def ows(self, value: str | None = None) -> Token | None:  # noqa: PLR6301
        if value is None:
            return None
        return Token(value)
