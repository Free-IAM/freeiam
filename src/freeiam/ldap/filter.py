# SPDX-FileCopyrightText: 2025 Florian Best
# SPDX-License-Identifier: MIT OR Apache-2.0
"""LDAP filter expressions."""

import enum
import operator
import re
from collections import deque
from collections.abc import Callable
from typing import Self

import lark
import ldap.filter
from lark import Lark, Transformer, v_args

from freeiam import errors


__all__ = (
    'AND',
    'NOT',
    'OR',
    'ApproximateMatch',
    'Comparision',
    'EqualityMatch',
    'ExtensibleMatch',
    'Filter',
    'GreaterOrEqual',
    'LessOrEqual',
    'Operator',
    'PresenceMatch',
    'SubstringMatch',
)


ldap_filter_grammar = r"""
start: _group | bare
bare: comparision
_group: ws? (operator | expression) ws?

?operator: and | or | not

expression: "(" ows comparision ows ")"
and: "(" ows "&" ows groups ows ")"
or:  "(" ows "|" ows groups ows ")"
not: "(" ows "!" ows _group  ows ")"
?groups: _group* -> groups

?comparision: attr "=*"                         -> presence
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

substrings: substr_part+
substr_part: _value | "*"

attr: /[a-zA-Z][a-zA-Z0-9-;]*/ | oid
?oid: /\d+[\.\d]*/
!dn: "dn"i
matchingrule: attr

_value: /([^\x00()*\\]|\\\\[0-9a-fA-F]{2}|\\[0-9a-fA-F]{2})+/
value: ows _value? ows

ows: ws?
ws: WS
%import common.WS
%import common.HEXDIGIT
"""


class EscapeMode(enum.IntEnum):
    """Escape mode."""

    SPECIAL = 0
    NON_ASCII = 1
    ALL = 2


class WalkStrategy(enum.IntEnum):
    """Walk stategy."""

    BOTH = 0
    POST = 1
    PRE = 2


class Token(str):  # noqa: FURB189
    __slots__ = ()


class _Value(str):  # noqa: FURB189
    __slots__ = ('prefix', 'suffix')


class Expression:
    __slots__ = ()


class Operator(Expression):
    """A logical operator."""

    __slots__ = ('_sep', 'expressions')
    operator = None
    expression = ''

    def __init__(self, expressions, *, sep: Token | None = None):
        self.expressions = expressions
        self._sep = sep

    def copy(self):
        """Copy the object."""
        return type(self)([e.copy() for e in self.expressions])

    def append(self, expression: Expression):
        """Append to the operator list."""
        self.expressions.append(expression)

    def insert(self, expression: Expression, index: int = 0):
        """Insert into the operator list."""
        self.expressions.insert(index, expression)

    def replace(self, expression: Expression, replacement: Expression):
        """Insert into the operator list."""
        index = next((i for i, e in enumerate(self.expressions) if e is expression), None)
        if index is None:  # pragma: no cover
            raise ValueError('Not in expressions', expression)  # noqa: TRY003
        self.expressions[index] = replacement

    def remove(self, expression: Expression):
        """Insert from the operator list."""
        index = next((i for i, e in enumerate(self.expressions) if e is expression), None)
        if index is None:  # pragma: no cover
            raise ValueError('Not in expressions', expression)  # noqa: TRY003
        self.expressions.pop(index)

    def __str__(self):
        sep = self._sep or ''
        groups = ''.join(f'({expr})' if isinstance(expr, Comparision) else str(expr) for expr in self.expressions)
        return f'({self.expression}{sep}{groups})' if self.expression else groups

    def __repr__(self):
        exprs = f' {self.expression} '.join(repr(x) for x in self.expressions)
        return f'{type(self).__name__}( {exprs} )'


class Container(Operator):
    """A group of one expression without brackets."""

    expression = ''

    def __str__(self):
        return ''.join(str(expr) for expr in self.expressions)


class Group(Operator):
    """A group of one expression in brackets."""

    expression = ''


class AND(Operator):
    """A group of AND conjunction expressions (&(...)(...))."""

    operator = operator.and_
    expression = '&'


class OR(Operator):
    """A group of OR disjunction expressions (|(...)(...))."""

    operator = operator.or_
    expression = '|'


class NOT(Operator):
    """A group of NOT negation expressions (!( ... ))."""

    operator = operator.not_
    expression = '!'


class Comparision(Expression):
    """Base class for comparision operators."""

    __slots__ = ('_end', '_extra', '_lead', '_mid', '_trail', 'attr', 'is_escaped', 'raw_value')
    operator = None
    expression = ''

    @property
    def value(self):
        """Get the value in a decoded form."""
        if self.is_escaped:
            return Filter.unescape(self.raw_value)
        return self.raw_value

    @value.setter
    def value(self, raw_value):
        self.raw_value = raw_value

    @property
    def escaped(self):
        """Get the value in a encoded/escaped form."""
        if self.is_escaped:
            return self.raw_value
        value = self.raw_value
        if value != value.strip():
            return Filter.escape(value, EscapeMode.NON_ASCII)
        return Filter.escape(value, EscapeMode.SPECIAL)

    def __init__(self, attr, value, is_escaped=False):
        self.attr = attr
        self.raw_value = value
        self.is_escaped = is_escaped
        self._extra = ''
        self._lead = ''
        self._mid = ''
        self._trail = ''
        self._end = ''

    def copy(self):
        """Copy the object."""
        # TODO: copy whitespace?
        return type(self)(self.attr, self.raw_value, is_escaped=self.is_escaped)

    def __str__(self):
        return f'{self._lead}{self.attr}{self._extra}{self.expression}{self._mid}{self.escaped}{self._end}{self._trail}'

    def __repr__(self):
        val = repr(self.raw_value) if self.is_escaped else f'escape({self.raw_value!r})'
        return f'{type(self).__name__}({self.attr}{self._extra}{self.expression}{val})'


class EqualityMatch(Comparision):
    """Compare for equality (attr=value)."""

    operator = operator.eq
    expression = '='


class GreaterOrEqual(Comparision):
    """Compare for greater or equals (attr>=value)."""

    operator = operator.ge
    expression = '>='


class LessOrEqual(Comparision):
    """Compare for less than or equals (attr<=value)."""

    operator = operator.le
    expression = '<='


class ApproximateMatch(Comparision):
    """Compare approximately (attr~=value)."""

    expression = '~='


class SubstringMatch(Comparision):
    """Compare substring match (attr=val*)."""

    operator = operator.contains
    expression = '='


class PresenceMatch(Comparision):
    """Compare for presence (attr=*)."""

    expression = '=*'


class ExtensibleMatch(Comparision):
    """Compare with extensible match (attr:dn:rule:=value, optional: dn / Matching Rule OID)."""

    expression = ':='
    __slots__ = (*Comparision.__slots__, 'dn', 'matchingrule')

    def copy(self):
        """Copy the object."""
        return type(self)(self.attr, self.value, self.dn, self.matchingrule, is_escaped=self.is_escaped)

    def __init__(self, attr, value, dn, matchingrule, is_escaped=True):
        super().__init__(attr, value, is_escaped=is_escaped)
        extra = ''
        if dn:
            extra = f':{dn}'
        if matchingrule:
            extra = f'{extra}:{matchingrule}'
        self._extra = extra
        self.dn = dn
        self.matchingrule = matchingrule


class Filter:
    """A LDAP Filter according to RFC 4515."""

    __slots__ = ('_debug', '_tree', 'ast', 'filter_expr')

    parser = Lark(ldap_filter_grammar)
    RE_HEXESCAPE = re.compile(r'\\([0-9A-Fa-f]{2})')

    def __init__(self, /, filter_expr: str | None, *, strict=False, _debug=False):
        # TODO: security: restrict length
        # TODO: security: restrict depth
        # TODO: security: restrict number of escape sequences
        self.filter_expr = filter_expr
        self.ast: Container
        self._tree = None
        self._debug = _debug
        self.parse(strict)

    @property
    def root(self):
        """The first object in the filter."""
        if self._tree is None:  # pragma: no cover
            return None
        return self.ast.expressions[0]

    def parse(self, strict=False):
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

    def _disallow_whitespace(self, fil, parent, expr):  # noqa: ARG002
        if isinstance(expr, Comparision):
            if expr._mid or expr._lead or expr._trail or expr._end:
                raise self.error()
        elif isinstance(expr, Operator) and expr._sep:  # pragma: no cover
            raise self.error()  # currently impossible, broken OWS

    def error(self):
        """Get FilterError."""
        return errors.FilterError(ldap.FILTER_ERROR({'result': -7, 'desc': 'Bad search filter', 'info': str(self.filter_expr), 'ctrls': []}))

    def pretty(self, indent=0):
        """Transform into a pretty presentation."""

        def _pretty(expr, level):
            pad = '  ' * level
            if isinstance(expr, Comparision):
                return f'{pad}({expr})'
            if isinstance(expr, (AND, OR)):
                head = f'{pad}({expr.expression}'
                children = '\n'.join(_pretty(e, level + 1) for e in expr.expressions if not isinstance(e, Token))
                return f'{head}\n{children}\n{pad})'
            if isinstance(expr, NOT):
                head = f'{pad}({expr.expression}'
                children = ''.join(_pretty(e, 0) for e in expr.expressions if not isinstance(e, Token))
                return f'{head}{children})'
            if isinstance(expr, Operator):
                return '\n'.join(_pretty(e, level) for e in expr.expressions if not isinstance(e, Token))
            raise TypeError(f'Unexpected expression: {type(expr)}')  # noqa: TRY003,EM102  # pragma: no cover

        if self.root is None:
            return ''
        return _pretty(self.root, indent)

    @classmethod
    def get_eq(cls, attr, value):
        return EqualityMatch(attr, value, is_escaped=False)

    @classmethod
    def get_approx(cls, attr, value):
        return ApproximateMatch(attr, is_escaped=False)

    @classmethod
    def get_pres(cls, attr):
        return PresenceMatch(attr, is_escaped=False)

    @classmethod
    def get_substring(cls, attr, *values):
        return SubstringMatch(attr, ''.join(values), is_escaped=False)

    @classmethod
    def get_gt_eq(cls, attr, value):
        return GreaterOrEqual(attr, str(value), is_escaped=False)

    @classmethod
    def get_gt(cls, attr, value: int):
        return cls.get_gt_eq(attr, value - 1)

    @classmethod
    def get_lt_eq(cls, attr, value):
        return LessOrEqual(attr, str(value), is_escaped=False)

    @classmethod
    def get_lt(cls, attr, value: int):
        return cls.get_lt_eq(attr, value + 1)

    @classmethod
    def get_extensible(cls, attr, dn, matchingrule, value):
        return ExtensibleMatch(attr, dn, matchingrule, value)

    @classmethod
    def get_and(cls, *expressions):
        return AND(expressions)

    @classmethod
    def get_or(cls, *expressions):
        return OR(expressions)

    @classmethod
    def get_not(cls, expression):
        return NOT([expression])

    @classmethod
    def from_format(cls, format_string, values) -> Self:
        """Get a Filter from a filter format string."""
        return cls(cls.escape_formatted(format_string, values))

    @classmethod
    def escape(cls, value, escape_mode: EscapeMode = EscapeMode.SPECIAL):
        """Escape LDAP filter characters."""
        return ldap.filter.escape_filter_chars(value, escape_mode)

    @classmethod
    def unescape(cls, value: str) -> str:
        """Reverse the escaping of filter characters."""
        return cls.RE_HEXESCAPE.sub(
            lambda m: bytes([int(m.group(1), 16)]).decode('utf-8', errors='replace'),
            value,
        )

    @classmethod
    def escape_formatted(cls, format_string, values):
        """Escape LDAP filter characters in format string."""
        return ldap.filter.filter_format(format_string, values)

    @classmethod
    def time_span_filter(cls, from_timestamp=0, until_timestamp=None, delta_attr='modifyTimestamp'):
        """Get timespan filter e.g. '(&(modifyTimestamp>=19700101000000Z)(!(modifyTimestamp>=19700101000001Z)))'."""
        return cls(ldap.filter.time_span_filter('', from_timestamp, until_timestamp, delta_attr))

    def walk(self, comparison_callback: Callable | None, operator_callback: Callable | None, strategy: WalkStrategy = WalkStrategy.POST):
        """Walk the filter expressions and operator conjunctions iteratively."""
        stack = deque([(self.ast, self.root, True)])

        while stack:
            parent, expression, is_pre_visit = stack.pop()

            if isinstance(expression, Comparision):
                if comparison_callback:
                    comparison_callback(self, parent, expression)
            elif isinstance(expression, Operator):
                if is_pre_visit:
                    if operator_callback and strategy in {WalkStrategy.PRE, WalkStrategy.BOTH} and isinstance(expression, (AND, OR, NOT)):
                        operator_callback(self, parent, expression)

                    if operator_callback and strategy in {WalkStrategy.POST, WalkStrategy.BOTH} and isinstance(expression, (AND, OR, NOT)):
                        stack.append((parent, expression, False))

                    for child_expression in expression.expressions[::-1]:
                        stack.append((expression, child_expression, True))
                else:
                    operator_callback(self, parent, expression)
            elif isinstance(expression, Token):  # pragma: no cover
                pass  # not possible in the root!?
            else:  # pragma: no cover
                raise TypeError(expression)

    def __repr__(self):
        return f'{type(self).__name__}({self.root!r})'

    def __str__(self):
        if self._tree is None:
            return self.filter_expr
        return str(self.ast)

    # def _pretty(self):
    #     return self._tree.pretty()


@v_args(inline=True)
class _FilterTransformer(Transformer):
    """Filter tree Transformer."""

    def __init__(self, strict):
        self.__strict = strict
        super().__init__()

    def start(self, value):  # noqa: PLR6301
        if isinstance(value, Comparision):
            value = Group([value])
        if isinstance(value, (Operator, Comparision)):
            return value
        raise TypeError(type(value))  # pragma: no cover

    def bare(self, cmp):  # noqa: PLR6301
        return Container([cmp])

    def groups(self, *groups):  # noqa: PLR6301
        return list(groups)

    def expression(self, ld, cmp, tr):  # noqa: PLR6301
        cmp._lead = ld or ''
        cmp._trail = tr or ''
        return cmp

    def and_(self, sep, ld, exprs, tr):
        return AND(self._filter([ld, *list(exprs), tr]), sep=sep)

    def or_(self, sep, ld, exprs, tr):
        return OR(self._filter([ld, *list(exprs), tr]), sep=sep)

    def not_(self, sep, ld, expr, tr):
        return NOT(self._filter([ld, expr, tr]), sep=sep)

    def _filter(self, items):  # noqa: PLR6301
        return [item for item in items if item is not None]

    def attr(self, attr):  # noqa: PLR6301
        return str(attr)

    def value(self, ld, *value) -> _Value:  # noqa: PLR6301
        if len(value) > 1:
            val, tr = value
        else:
            val, tr = '', value[0]

        if val != val.strip():
            ld_, val, tr_ = val.partition(val.strip())
            ld = ld or ld_
            tr = tr or tr_
        val = _Value(val)
        val.prefix = ld
        val.suffix = tr
        return val

    def _prefix(self, data: _Value, value):  # noqa: PLR6301
        value._mid = data.prefix or ''
        value._end = data.suffix or ''
        return value

    def equality(self, attr, value):
        return self._prefix(value, EqualityMatch(str(attr), str(value), is_escaped=True))

    def presence(self, attr, value=''):
        return self._prefix(self.value(None, value, None), PresenceMatch(str(attr), '', is_escaped=True))

    def substring(self, attr, value):
        value = self.value(None, value, None)
        if value == '*':
            return self.presence(attr, value)
        return self._prefix(value, SubstringMatch(attr, value, is_escaped=True))

    def substr_part(self, value='*'):  # noqa: PLR6301
        return value

    def substrings(self, *values):  # noqa: PLR6301
        value = ''.join(values)
        if '**' in value:
            raise ValueError()
        return value

    def ge(self, attr, value):
        return self._prefix(value, GreaterOrEqual(attr, str(value), is_escaped=True))

    def le(self, attr, value):
        return self._prefix(value, LessOrEqual(attr, str(value), is_escaped=True))

    def extmatch_attr_nodn_match(self, attr, matchingrule, value):
        return self._prefix(value, ExtensibleMatch(attr, str(value), '', matchingrule, is_escaped=True))

    def extmatch_attr_dn_nomatch(self, attr, dn, value):
        return self._prefix(value, ExtensibleMatch(attr, str(value), dn, '', is_escaped=True))

    def extmatch_noattr_nodn_match(self, matchingrule, value):
        if matchingrule.lower() == 'dn':
            raise ValueError()
        return self._prefix(value, ExtensibleMatch('', str(value), '', matchingrule, is_escaped=True))

    def extmatch_attr_nodn_nomatch(self, attr, value):
        return self._prefix(value, ExtensibleMatch(attr, str(value), '', '', is_escaped=True))

    def extmatch_attr_dn_match(self, attr, dn, matchingrule, value):
        return self._prefix(value, ExtensibleMatch(attr, str(value), dn, matchingrule, is_escaped=True))

    def extmatch_noattr_dn_match(self, dn, matchingrule, value):
        return self._prefix(value, ExtensibleMatch('', str(value), dn, matchingrule, is_escaped=True))

    def approx(self, attr, value):
        return self._prefix(value, ApproximateMatch(str(attr), str(value), is_escaped=True))

    def dn(self, value='dn'):  # noqa: PLR6301
        return str(value)

    def matchingrule(self, value):  # noqa: PLR6301
        return str(value)

    def ws(self, value):  # noqa: PLR6301
        return Token(value)

    def ows(self, value=None):  # noqa: PLR6301
        if value is None:
            return None
        return Token(value)

    def __default__(self, data, children, meta):  # noqa: PLW3201
        if data == 'and':
            return self.and_(*children)
        if data == 'or':
            return self.or_(*children)
        if data == 'not':
            return self.not_(*children)
        return super().__default__(data, children, meta)  # pragma: no cover
