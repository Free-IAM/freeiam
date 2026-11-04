# SPDX-FileCopyrightText: 2025 Florian Best
# SPDX-License-Identifier: MIT OR Apache-2.0
"""LARK based filter implementation."""

from typing import Any, TypeVar, cast

import lark
from lark import Lark, Transformer, v_args

from freeiam import errors
from freeiam.ldap.filter import (
    AND,
    NOT,
    OR,
    ApproximateMatch,
    Assertion,
    Container,
    EqualityMatch,
    Expression,
    ExtensibleMatch,
    Filter,
    GreaterOrEqual,
    Group,
    LessOrEqual,
    Operator,
    PresenceMatch,
    SubstringMatch,
    Token,
)


FILTER_GRAMMAR = r"""
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


T = TypeVar('T', bound='Assertion | EqualityMatch | GreaterOrEqual | LessOrEqual | ExtensibleMatch')
Z = TypeVar('Z', bound='Any')


class _AdditionalWhitespaceError(lark.exceptions.LarkError):
    """Unexpected whitespace in a parsed filter."""


@v_args(inline=True)
class _FilterTransformer(Transformer[lark.Token, Expression]):
    """Filter tree Transformer."""

    def __init__(self, strict: bool) -> None:
        self.__strict = strict
        super().__init__()

    def start(self, value: Expression, *args: object) -> Expression:  # noqa: PLR6301
        if args:
            raise _AdditionalWhitespaceError
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
    def presence(cls, attr: str, _star: lark.Token) -> PresenceMatch:
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
        return ExtensibleMatch.from_escaped(attr, value.encode('UTF-8'), matchingrule=matchingrule, dn=False)

    @classmethod
    def extmatch_attr_dn_nomatch(cls, attr: str, dn: lark.Token, value: str) -> ExtensibleMatch:
        return ExtensibleMatch.from_escaped(attr, value.encode('UTF-8'), None, dn=str(dn))

    @classmethod
    def extmatch_noattr_nodn_match(cls, matchingrule: str, value: str) -> ExtensibleMatch:
        if matchingrule.lower() == 'dn':
            raise RuntimeError()
        return ExtensibleMatch.from_escaped('', value.encode('UTF-8'), matchingrule=matchingrule, dn=False)

    @classmethod
    def extmatch_attr_nodn_nomatch(cls, attr: str, value: str) -> ExtensibleMatch:
        return ExtensibleMatch.from_escaped(attr, value.encode('UTF-8'), matchingrule='', dn=False)

    @classmethod
    def extmatch_attr_dn_match(cls, attr: str, dn: str, matchingrule: str, value: str) -> ExtensibleMatch:
        return ExtensibleMatch.from_escaped(attr, value.encode('UTF-8'), matchingrule, dn=dn)

    @classmethod
    def extmatch_noattr_dn_match(cls, dn: str, matchingrule: str, value: str) -> ExtensibleMatch:
        return ExtensibleMatch.from_escaped('', value.encode('UTF-8'), matchingrule, dn=dn)

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


class LarkParser:
    """Parser."""

    _parser_strict = Lark(
        FILTER_GRAMMAR,
        parser='lalr',
        maybe_placeholders=False,
        transformer=_FilterTransformer(strict=True),
    )

    _parser_unstrict = Lark(
        FILTER_GRAMMAR,
        parser='lalr',
        maybe_placeholders=False,
        transformer=_FilterTransformer(strict=False),
    )

    __slots__ = ('_filter', '_parser', '_strict')

    def __init__(self, filter: Filter, strict: bool = False) -> None:  # noqa: A002
        self._parser = self._parser_strict if strict else self._parser_unstrict
        self._filter = filter
        self._strict = strict

    def parse(self, expression: str, _debug: bool = False) -> Container:
        """Parse."""
        try:
            root = cast('Expression', self._parser.parse(expression))
            ast = Container([root])
        except lark.exceptions.LarkError:
            if _debug:  # pragma: no cover
                raise
            raise self.error(expression) from None

        if self._strict:
            self._validate_strict(root, expression)

        return ast

    @classmethod
    def _validate_strict(cls, root: Expression, expression: str) -> None:
        """Validate whitespace on the newly parsed AST."""
        stack = [root]
        while stack:
            node = stack.pop()
            if isinstance(node, Assertion) and node._lead:
                raise cls.error(expression)
            if isinstance(node, Operator) and node._sep:
                raise cls.error(expression)
            if isinstance(node, Container):
                stack.extend(child for child in node.expressions)

    @classmethod
    def error(cls, expression: str) -> errors.FilterError:
        """Create a filter parsing error."""
        return errors.FilterError({'result': -7, 'desc': 'Bad search filter', 'info': str(expression), 'ctrls': []})
