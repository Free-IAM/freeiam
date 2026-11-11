# SPDX-FileCopyrightText: 2026 Florian Best
# SPDX-License-Identifier: MIT OR Apache-2.0
"""BER based filter implementation."""

# ruff: noqa: N815, PLR2004

from importlib import import_module

from pyasn1.codec.ber import decoder as ber_decoder, encoder as ber_encoder
from pyasn1.type import namedtype, tag, univ  # type: ignore[attr-defined]

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
    GreaterOrEqual,
    Group,
    LessOrEqual,
    Operator,
    PresenceMatch,
    SubstringMatch,
    Token,
    ValueAssertion,
)


# RFC 4511 section 4.5.1. Explicit IMPLICIT tagging is important:
# the contents of each CHOICE alternative use context-specific tags
class _Assertion(univ.Sequence):
    componentType = namedtype.NamedTypes(
        namedtype.NamedType('attributeDesc', univ.OctetString()),
        namedtype.NamedType('assertionValue', univ.OctetString()),
    )


class _Substring(univ.Choice):
    componentType = namedtype.NamedTypes(
        namedtype.NamedType('initial', univ.OctetString().subtype(implicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatSimple, 0))),  # type: ignore[no-untyped-call]
        namedtype.NamedType('any', univ.OctetString().subtype(implicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatSimple, 1))),  # type: ignore[no-untyped-call]
        namedtype.NamedType('final', univ.OctetString().subtype(implicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatSimple, 2))),  # type: ignore[no-untyped-call]
    )


class _Substrings(univ.Sequence):
    componentType = namedtype.NamedTypes(
        namedtype.NamedType('type', univ.OctetString()),
        namedtype.NamedType('substrings', univ.SequenceOf(componentType=_Substring())),
    )


class _Extensible(univ.Sequence):
    componentType = namedtype.NamedTypes(
        namedtype.OptionalNamedType('matchingRule', univ.OctetString().subtype(implicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatSimple, 1))),  # type: ignore[no-untyped-call]
        namedtype.OptionalNamedType('type', univ.OctetString().subtype(implicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatSimple, 2))),  # type: ignore[no-untyped-call]
        namedtype.NamedType('matchValue', univ.OctetString().subtype(implicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatSimple, 3))),  # type: ignore[no-untyped-call]
        namedtype.DefaultedNamedType(
            'dnAttributes',
            univ.Boolean(value=False).subtype(implicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatSimple, 4)),  # type: ignore[no-untyped-call]
        ),
    )


class _FilterASN1(univ.Choice):
    pass


# recursive definitions need a forward declaration and a delayed componentType
_FilterASN1.componentType = namedtype.NamedTypes(
    namedtype.NamedType(
        'and',
        univ.SetOf(componentType=_FilterASN1()).subtype(implicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatConstructed, 0)),  # type: ignore[no-untyped-call]
    ),
    namedtype.NamedType('or', univ.SetOf(componentType=_FilterASN1()).subtype(implicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatConstructed, 1))),  # type: ignore[no-untyped-call]
    namedtype.NamedType('not', _FilterASN1().subtype(implicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatConstructed, 2))),  # type: ignore[no-untyped-call]
    namedtype.NamedType('equalityMatch', _Assertion().subtype(implicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatConstructed, 3))),  # type: ignore[no-untyped-call]
    namedtype.NamedType('substrings', _Substrings().subtype(implicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatConstructed, 4))),  # type: ignore[no-untyped-call]
    namedtype.NamedType('greaterOrEqual', _Assertion().subtype(implicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatConstructed, 5))),  # type: ignore[no-untyped-call]
    namedtype.NamedType('lessOrEqual', _Assertion().subtype(implicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatConstructed, 6))),  # type: ignore[no-untyped-call]
    namedtype.NamedType('present', univ.OctetString().subtype(implicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatSimple, 7))),  # type: ignore[no-untyped-call]
    namedtype.NamedType('approxMatch', _Assertion().subtype(implicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatConstructed, 8))),  # type: ignore[no-untyped-call]
    namedtype.NamedType('extensibleMatch', _Extensible().subtype(implicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatConstructed, 9))),  # type: ignore[no-untyped-call]
)


def expression_to_ber(expression: Expression) -> bytes:
    """Encode the filter as an LDAP BER filter."""
    if isinstance(expression, (Group, Container)) and not isinstance(expression, Operator):
        if len(expression.expressions) != 1:
            raise ValueError('Filter requires exactly one root expression')

        expression = expression.expressions[0]
    return _expression_to_ber(expression)


def _expression_to_ber(expr: Expression) -> bytes:
    if isinstance(expr, (AND, OR)):
        return _tlv(0xA0 if isinstance(expr, AND) else 0xA1, b''.join(_expression_to_ber(child) for child in expr.expressions))
    if isinstance(expr, NOT):
        return _tlv(0xA2, _expression_to_ber(expr.expressions[0]))
    return ber_encoder.encode(_asn1_from_expression(expr))


def _tlv(tag_byte: int, content: bytes) -> bytes:
    """Encode a BER tag and definite length."""
    length = len(content)
    if length < 128:
        prefix = bytes((length,))
    else:
        value = length.to_bytes((length.bit_length() + 7) // 8, 'big')
        prefix = bytes((0x80 | len(value),)) + value
    return bytes((tag_byte,)) + prefix + content


class LibldapParser:
    """Parser."""

    __slots__ = ('_strict',)

    def __init__(self, strict: bool = False) -> None:
        self._strict = strict

    def parse(self, expression: str, _debug: bool = False) -> Container:
        """Parse."""
        if self._strict and expression != expression.strip():
            raise self.error(expression)

        try:
            libldap = import_module('freeiam._libldap')
            data = libldap.ldap_pvt_put_filter(expression)
        except ValueError:
            if _debug:  # pragma: no cover
                raise
            # if str(exc) in ('Bad LDAP filter', 'embedded null character'):
            raise self.error(expression) from None

        expr = _expression_from_ber(bytes(data))
        if isinstance(expr, Assertion):
            expr = Group([expr]) if expression.startswith('(') else Container([expr])
        return Container([expr])

    @classmethod
    def error(cls, expression: str) -> errors.FilterError:
        """Create a filter parsing error."""
        return errors.FilterError({'result': -7, 'desc': 'Bad search filter', 'info': str(expression), 'ctrls': []})


def _expression_from_ber(data: bytes) -> Expression:
    """
    Decode recursive filter branches before invoking pyasn1 for leaf types.

    pyasn1's recursively self-referencing CHOICE cannot be constructed from a
    forward-declared instance which has not yet received its componentType.
    """
    identifier, content, rest = _read_tlv(data)
    if rest:
        raise ValueError('Trailing BER filter data')

    if identifier in {0xA0, 0xA1}:
        expressions: list[Expression | Token] = []
        while content:
            _, _, tail = _read_tlv(content)
            consumed = len(content) - len(tail)
            expressions.append(_expression_from_ber(content[:consumed]))
            content = tail
        return (AND if identifier == 0xA0 else OR)(expressions)

    if identifier == 0xA2:
        return NOT([_expression_from_ber(content)])

    item, remaining = ber_decoder.decode(data, asn1Spec=_FilterASN1())
    if remaining:
        raise ValueError('Trailing BER filter data')

    return _expression_from_asn1(item)


def _read_tlv(data: bytes) -> tuple[int, bytes, bytes]:
    """Return (tag, content, remaining) for a definite-length BER TLV."""
    if len(data) < 2:
        raise ValueError('Truncated BER filter')

    identifier = data[0]
    length_byte = data[1]
    offset = 2
    if length_byte == 0x80:
        raise ValueError('Indefinite BER lengths are not supported')

    if length_byte & 0x80:
        count = length_byte & 0x7F
        if not count or count > 8 or len(data) < offset + count:
            raise ValueError('Invalid BER length')

        length = int.from_bytes(data[offset : offset + count], 'big')
        offset += count
    else:
        length = length_byte

    end = offset + length
    if end > len(data):
        raise ValueError('Truncated BER filter content')

    return identifier, data[offset:end], data[end:]


def _expression_from_asn1(value: _FilterASN1) -> Expression:
    name = value.getName()
    item = value.getComponent()
    if name in {'and', 'or'}:
        return (AND if name == 'and' else OR)([_expression_from_asn1(x) for x in item])
    if name == 'not':
        return NOT([_expression_from_asn1(item)])
    if name == 'present':
        return PresenceMatch(bytes(item).decode('ASCII'))
    if name in {'equalityMatch', 'greaterOrEqual', 'lessOrEqual', 'approxMatch'}:
        cls = {'equalityMatch': EqualityMatch, 'greaterOrEqual': GreaterOrEqual, 'lessOrEqual': LessOrEqual, 'approxMatch': ApproximateMatch}[name]
        return cls(bytes(item['attributeDesc']).decode('ASCII'), bytes(item['assertionValue']))
    if name == 'substrings':
        initial = final = None
        middles = []
        for part in item['substrings']:
            part_name = part.getName()
            part_value = bytes(part.getComponent())
            if part_name == 'initial':
                initial = part_value
            elif part_name == 'final':
                final = part_value
            else:
                middles.append(part_value)
        return SubstringMatch(bytes(item['type']).decode('ASCII'), initial=initial, any=middles, final=final)
    if name == 'extensibleMatch':
        rule = item['matchingRule']
        attr = item['type']
        return ExtensibleMatch(
            bytes(attr).decode('ASCII') if attr.isValue else '',
            bytes(item['matchValue']),
            bytes(rule).decode('ASCII') if rule.isValue else None,
            dn=bool(item['dnAttributes']),
        )
    msg = f'Unknown ASN.1 filter alternative: {name}'
    raise ValueError(msg)


def _asn1_from_expression(expr: Expression) -> _FilterASN1:
    result = _FilterASN1()
    if isinstance(expr, (AND, OR)):
        name = 'and' if isinstance(expr, AND) else 'or'
        values = result.getComponentByName(name)
        for index, child in enumerate(expr.expressions):
            values.setComponentByPosition(index, _asn1_from_expression(child))
        result.setComponentByName(name, values)
    elif isinstance(expr, NOT):
        result.setComponentByName('not', _asn1_from_expression(expr.expressions[0]))
    elif isinstance(expr, PresenceMatch):
        result.setComponentByName('present', expr.attr.encode('ASCII'))
    elif isinstance(expr, SubstringMatch):
        item = result.getComponentByName('substrings')
        item.setComponentByName('type', expr.attr.encode('ASCII'))
        parts = item.getComponentByName('substrings')
        entries = [('initial', expr.initial)] if expr.initial is not None else []
        entries += [('any', x) for x in expr.any]
        entries += [('final', expr.final)] if expr.final is not None else []
        for idx, (name, payload) in enumerate(entries):
            entry = _Substring()
            entry.setComponentByName(name, payload)
            parts.setComponentByPosition(idx, entry)
        item.setComponentByName('substrings', parts)
        result.setComponentByName('substrings', item)
    elif isinstance(expr, ExtensibleMatch):
        item = result.getComponentByName('extensibleMatch')
        if expr.matchingrule:
            item.setComponentByName('matchingRule', expr.matchingrule.encode('ASCII'))
        if expr.attr:
            item.setComponentByName('type', expr.attr.encode('ASCII'))
        item.setComponentByName('matchValue', expr.value)
        item.setComponentByName('dnAttributes', bool(expr.dn))
        result.setComponentByName('extensibleMatch', item)
    elif isinstance(expr, ValueAssertion):
        asn1_name = {
            EqualityMatch: 'equalityMatch',
            GreaterOrEqual: 'greaterOrEqual',
            LessOrEqual: 'lessOrEqual',
            ApproximateMatch: 'approxMatch',
        }.get(type(expr))
        item = result.getComponentByName(asn1_name)
        item.setComponentByName('attributeDesc', expr.attr.encode('ASCII'))
        item.setComponentByName('assertionValue', expr.value)
        result.setComponentByName(asn1_name, item)
    else:
        raise TypeError(type(expr))
    return result
