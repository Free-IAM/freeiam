# SPDX-FileCopyrightText: 2026 Florian Best
# SPDX-License-Identifier: MIT OR Apache-2.0
"""Coverage tests for LDAP filter backends and error branches."""

# ruff: noqa: N802,N803,PLR6301,TRY003

from types import SimpleNamespace

import lark
import pytest

from freeiam.errors import FilterError
from freeiam.ldap._filter import ber as ber_module, lark as lark_module  # noqa: PLC2701
from freeiam.ldap.filter import (
    AND,
    NOT,
    OR,
    ApproximateMatch,
    Container,
    EqualityMatch,
    Expression,
    ExtensibleMatch,
    Filter,
    GreaterOrEqual,
    Group,
    LessOrEqual,
    PresenceMatch,
    SubstringMatch,
    Token,
)


class _SequenceValue:
    """Record the children written into an ASN.1 SET OF-like object."""

    def __init__(self) -> None:
        self.children = {}

    def setComponentByPosition(self, index, value):
        self.children[index] = value


class _ASN1Choice:
    """Record writes without depending on pyasn1's recursive CHOICE support."""

    def __init__(self) -> None:
        self.components = {}

    def getComponentByName(self, name):
        if name in {'and', 'or'}:
            return _SequenceValue()
        return _ASN1Choice()

    def setComponentByName(self, name, value):
        self.components[name] = value


@pytest.fixture
def recorded_asn1(monkeypatch):
    monkeypatch.setattr(ber_module, '_FilterASN1', _ASN1Choice)


@pytest.mark.parametrize(
    'data, message',
    [
        (b'', 'Truncated BER filter'),
        (b'\xa0', 'Truncated BER filter'),
        (b'\xa0\x80', 'Indefinite BER lengths'),
        (b'\xa0\x81', 'Invalid BER length'),
        (b'\xa0\x80\x00\x00', 'Indefinite BER lengths'),
        (b'\xa0\x89' + b'\x00' * 9, 'Invalid BER length'),
        (b'\xa0\x81\x03\x00', 'Truncated BER filter content'),
        (b'\xa0\x04\x00', 'Truncated BER filter content'),
    ],
)
def test_ber_tlv_rejects_invalid_lengths(data, message):
    with pytest.raises(ValueError, match=message):
        ber_module._read_tlv(data)


@pytest.mark.parametrize('size', [0, 1, 127, 128, 255, 256, 65536])
def test_ber_tlv_roundtrip_at_length_boundaries(size):
    payload = b'x' * size
    encoded = ber_module._tlv(0x87, payload)
    tag, decoded, remainder = ber_module._read_tlv(encoded + b'tail')
    assert tag == 0x87
    assert decoded == payload
    assert remainder == b'tail'
    assert encoded == ber_module._tlv(tag, decoded)


def test_ber_tlv_nonminimal_but_definite_long_length():
    tag, contents, remainder = ber_module._read_tlv(b'\x87\x81\x01x!')
    assert (tag, contents, remainder) == (0x87, b'x', b'!')


@pytest.mark.parametrize('content', [b'\x87\x01a', b'\xa0\x00', b'\xa1\x00'])
def test_ber_rejects_trailing_filter_bytes(content):
    with pytest.raises(ValueError, match='Trailing BER filter data'):
        ber_module._expression_from_ber(content + b'\x00')


@pytest.mark.parametrize('tag,kind', [(0xA0, AND), (0xA1, OR)])
def test_ber_recursively_decodes_boolean_filters(tag, kind):
    leaf = ber_module._expression_to_ber(EqualityMatch('cn', b'John'))
    encoded = ber_module._tlv(tag, leaf + leaf)
    actual = ber_module._expression_from_ber(encoded)
    assert isinstance(actual, kind)
    assert len(actual.expressions) == 2
    assert [x.value for x in actual.expressions] == [b'John', b'John']
    assert ber_module._expression_to_ber(actual) == encoded


def test_ber_recursively_decodes_not_filter():
    leaf = ber_module._expression_to_ber(PresenceMatch('uid'))
    encoded = ber_module._tlv(0xA2, leaf)
    actual = ber_module._expression_from_ber(encoded)
    assert isinstance(actual, NOT)
    assert len(actual.expressions) == 1
    assert isinstance(actual.expressions[0], PresenceMatch)
    assert ber_module._expression_to_ber(actual) == encoded


@pytest.mark.parametrize('kind,tag', [(AND, 0xA0), (OR, 0xA1)])
def test_ber_encodes_empty_boolean_filter(kind, tag):
    assert ber_module._expression_to_ber(kind([])) == bytes((tag, 0))
    restored = ber_module._expression_from_ber(bytes((tag, 0)))
    assert isinstance(restored, kind)
    assert restored.expressions == ()


@pytest.mark.parametrize('children', [[], [PresenceMatch('cn'), PresenceMatch('sn')]])
def test_ber_not_requires_exactly_one_child(children):
    with pytest.raises(ValueError, match=r'NOT requires between 1 and 1 expressions, got \d'):
        ber_module._expression_to_ber(NOT(children))


def test_from_ber_operator():
    original = Filter('(&(cn=John)(sn=Doe))')
    restored = Filter.from_ber(original.to_ber())

    assert isinstance(restored.root, AND)
    assert str(restored) == '(&(cn=John)(sn=Doe))'
    assert restored.to_ber() == original.to_ber()


def test_ber_rejects_trailing_bytes_from_pyasn1(monkeypatch):
    monkeypatch.setattr(
        ber_module.ber_decoder,
        'decode',
        lambda data, asn1Spec: (object(), b'extra'),  # noqa: ARG005
    )
    with pytest.raises(ValueError, match='Trailing BER filter data'):
        ber_module._expression_from_ber(b'\x87\x00')


def test_ber_rejects_unsupported_ast_type():
    with pytest.raises(TypeError):
        ber_module._asn1_from_expression(Container([]))


@pytest.mark.parametrize(
    'assertion',
    [
        PresenceMatch('cn'),
        EqualityMatch('cn', b'hello'),
        GreaterOrEqual('uidNumber', b'1000'),
        LessOrEqual('uidNumber', b'2000'),
        ApproximateMatch('cn', b'hello'),
        SubstringMatch('cn', initial=b'foo'),
        SubstringMatch('cn', final=b'bar'),
        SubstringMatch('cn', initial=b'foo', any=(b'bar', b'baz'), final=b'qux'),
        ExtensibleMatch('cn', b'John', 'caseIgnoreMatch'),
        ExtensibleMatch('', b'John', 'caseIgnoreMatch', dn=True),
        ExtensibleMatch('cn', b'John', None, dn=True),
    ],
    ids=repr,
)
def test_ber_leaf_roundtrip_all_assertion_variants(assertion):
    original = ber_module._expression_to_ber(assertion)
    restored = ber_module._expression_from_ber(original)
    assert type(restored) is type(assertion)
    assert ber_module._expression_to_ber(restored) == original


class _ASN1Value:
    def __init__(self, name, component):
        self.name = name
        self.component = component

    def getName(self):
        return self.name

    def getComponent(self):
        return self.component


@pytest.mark.parametrize('name,kind', [('and', AND), ('or', OR)])
def test_ber_asn1_recursive_and_or_dispatch(name, kind):
    value = _ASN1Value(name, [_ASN1Value('present', b'cn')])
    actual = ber_module._expression_from_asn1(value)
    assert isinstance(actual, kind)
    assert isinstance(actual.expressions[0], PresenceMatch)


def test_ber_asn1_recursive_not_dispatch():
    value = _ASN1Value('not', _ASN1Value('present', b'cn'))
    actual = ber_module._expression_from_asn1(value)
    assert isinstance(actual, NOT)
    assert isinstance(actual.expressions[0], PresenceMatch)


def test_ber_asn1_unknown_choice_is_rejected():
    with pytest.raises(ValueError, match=r'Unknown ASN.1 filter alternative'):
        ber_module._expression_from_asn1(_ASN1Value('unexpected', object()))


def test_ber_asn1_substring_with_initial_any_and_final():
    parts = [
        _ASN1Value('initial', b'a'),
        _ASN1Value('any', b'b'),
        _ASN1Value('final', b'c'),
    ]
    value = _ASN1Value('substrings', {'type': b'cn', 'substrings': parts})
    result = ber_module._expression_from_asn1(value)
    assert isinstance(result, SubstringMatch)
    assert (result.initial, result.any, result.final) == (b'a', (b'b',), b'c')


class _OptionalASN1Value:
    def __init__(self, value=None):
        self.isValue = value is not None
        self.value = value

    def __bytes__(self):
        if self.value is None:
            raise AssertionError('Absent optional field must not be decoded')
        return self.value


@pytest.mark.parametrize(
    'attr,rule,dn',
    [
        (b'cn', b'caseIgnoreMatch', True),
        (b'cn', None, False),
        (None, b'caseIgnoreMatch', False),
    ],
)
def test_ber_asn1_extensible_optional_fields(attr, rule, dn):
    value = _ASN1Value(
        'extensibleMatch',
        {
            'type': _OptionalASN1Value(attr),
            'matchingRule': _OptionalASN1Value(rule),
            'matchValue': b'John',
            'dnAttributes': dn,
        },
    )
    actual = ber_module._expression_from_asn1(value)
    assert isinstance(actual, ExtensibleMatch)
    assert actual.attr == (attr.decode() if attr else '')
    assert actual.matchingrule == (rule.decode() if rule else None)
    assert bool(actual.dn) is dn
    assert actual.value == b'John'


def test_libldap_parser_rejects_outer_whitespace_in_strict_mode():
    with pytest.raises(FilterError):
        ber_module.LibldapParser(strict=True).parse(' (cn=John) ')


def test_libldap_parser_normalizes_native_valueerror(monkeypatch):
    def fail(_expression):
        raise ValueError('Some arbitrary native error message')

    monkeypatch.setattr(
        ber_module,
        'import_module',
        lambda _name: SimpleNamespace(ldap_pvt_put_filter=fail),
    )
    with pytest.raises(FilterError):
        ber_module.LibldapParser().parse('(cn=bad)')
    with pytest.raises(ValueError, match='arbitrary native'):
        ber_module.LibldapParser().parse('(cn=bad)', _debug=True)


def test_libldap_parser_wraps_parenthesized_and_bare_assertions(monkeypatch):

    def encode(expression):
        assert expression in {'cn=John', '(cn=John)'}
        return ber_module._expression_to_ber(EqualityMatch('cn', b'John'))

    monkeypatch.setattr(
        ber_module,
        'import_module',
        lambda _name: SimpleNamespace(ldap_pvt_put_filter=encode),
    )
    enclosed = ber_module.LibldapParser().parse('(cn=John)')
    bare = ber_module.LibldapParser().parse('cn=John')
    # assert isinstance(enclosed.expressions[0], Group)
    # assert type(bare.expressions[0]) is Container
    assert str(enclosed) == '(cn=John)'
    assert str(bare) == 'cn=John'


def test_lark_transformer_rejects_additional_whitespace():
    transformer = lark_module._FilterTransformer(strict=False)
    with pytest.raises(lark_module._WhitespaceError):
        transformer.start(EqualityMatch('cn', b'John'), object())


def test_lark_strict_validation_rejects_operator_separator():
    operator = AND([EqualityMatch('cn', b'John')], sep=Token(' '))
    with pytest.raises(FilterError):
        lark_module.LarkParser._validate_strict(operator, '(&(cn=John))')


def test_lark_transformer_optional_whitespace():
    transformer = lark_module._FilterTransformer(strict=False)
    assert transformer.ows() is None
    assert transformer.ows('  ') == Token('  ')
    assert transformer.ws('\t') == Token('\t')


def test_lark_debug_exposes_underlying_exception():
    parser = lark_module.LarkParser(Filter('(cn=John)', parser='lark'))
    with pytest.raises(lark.exceptions.LarkError):
        parser.parse('(cn=', _debug=True)
    with pytest.raises(FilterError):
        parser.parse('(cn=', _debug=False)


def test_filter_parser_rejects_unknown_backend():
    with pytest.raises(ValueError, match='Unknown parser'):
        Filter('(cn=John)', parser='nonexistent')


def test_filter_from_ber_does_not_need_native_parser():
    original = ber_module._expression_to_ber(EqualityMatch('cn', b'John'))
    restored = Filter.from_ber(original)
    assert str(restored) == '(cn=John)'
    assert restored.to_ber() == original


def test_filter_to_ber_rejects_empty_and_multiple_roots():
    assert Filter('', parser='lark').to_ber() == b''
    fil = Filter('(cn=John)', parser='lark')
    fil.ast = Container([Group([EqualityMatch('a', b'1'), EqualityMatch('b', b'2')])])
    with pytest.raises(ValueError, match='exactly one root expression'):
        fil.to_ber()


@pytest.mark.parametrize('operator, tag', [(AND, 'and'), (OR, 'or')])
def test_ber_asn1_direct_boolean_encoding(recorded_asn1, operator, tag):
    """Exercise the internal ASN.1 encoder's otherwise bypassed AND/OR path."""
    result = ber_module._asn1_from_expression(operator([PresenceMatch('cn'), PresenceMatch('sn')]))
    assert set(result.components) == {tag}
    children = result.components[tag].children
    assert set(children) == {0, 1}
    assert children[0].components == {'present': b'cn'}
    assert children[1].components == {'present': b'sn'}


def test_ber_asn1_direct_not_encoding(recorded_asn1):
    result = ber_module._asn1_from_expression(NOT([PresenceMatch('cn')]))
    assert result.components['not'].components == {'present': b'cn'}


@pytest.mark.parametrize('children', [[], [PresenceMatch('cn'), PresenceMatch('sn')]])
def test_ber_asn1_direct_not_rejects_invalid_arity(recorded_asn1, children):
    with pytest.raises(ValueError, match=r'NOT requires between 1 and 1 expressions, got \d'):
        ber_module._asn1_from_expression(NOT(children))


def test_ber_asn1_direct_substring_encoding(recorded_asn1):
    """Check the remaining substring dispatch and its structural components."""
    expr = SubstringMatch('cn', initial=b'foo', any=(b'bar',), final=b'baz')

    # The real ASN.1 path is already tested by roundtrips in the main coverage suite.
    # Here we need a recording object able to model SequenceOf components.
    class _SubstringComponent(_ASN1Choice):
        pass

    class _SubstringSequence(_ASN1Choice):
        def getComponentByName(self, name):
            if name == 'substrings':
                return _SequenceValue()
            return super().getComponentByName(name)

    class _Root(_ASN1Choice):
        def getComponentByName(self, name):
            if name == 'substrings':
                return _SubstringSequence()
            return super().getComponentByName(name)

    # The real _Substring constructor uses pyasn1. Replacing just its class
    # keeps this direct-branch test independent of recursive ASN.1 internals.
    with pytest.MonkeyPatch.context() as mp:
        mp.setattr(ber_module, '_FilterASN1', _Root)
        mp.setattr(ber_module, '_Substring', _SubstringComponent)
        result = ber_module._asn1_from_expression(expr)
    record = result.components['substrings']
    assert record.components['type'] == b'cn'
    parts = record.components['substrings'].children
    assert [list(parts[i].components) for i in range(3)] == [
        ['initial'],
        ['any'],
        ['final'],
    ]
    assert [next(iter(parts[i].components.values())) for i in range(3)] == [
        b'foo',
        b'bar',
        b'baz',
    ]


def test_lark_rejects_dn_without_attribute_or_matchingrule():
    """The special invalid matching rule 'dn' is rejected by its transformer."""
    with pytest.raises(RuntimeError):
        lark_module._FilterTransformer.extmatch_noattr_nodn_match('dn', 'value')


class _UnsupportedExpression(Expression):
    def copy(self):
        return type(self)()


def test_filter_pretty_rejects_unknown_expression():
    fil = Filter('')
    fil.ast = Container([_UnsupportedExpression()])
    with pytest.raises(TypeError, match='_UnsupportedExpression'):
        fil.pretty()


def test_filter_walk_skips_unknown_expression():
    fil = Filter('')
    fil.ast = Container([OR([_UnsupportedExpression(), EqualityMatch('cn', b'John')])])
    visited = []

    def visit(_filter, _parent, assertion):
        visited.append(assertion.attr)

    fil.walk(visit, None)
    assert visited == ['cn']


def test_walk_unknown_expression():
    fil = Filter('')
    fil.ast = Container([Expression()])

    fil.walk(None, None)
