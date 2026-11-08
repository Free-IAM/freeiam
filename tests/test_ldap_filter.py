import ldap
import pytest

from freeiam.errors import FilterError
from freeiam.ldap.filter import (
    AND,
    NOT,
    OR,
    ApproximateMatch,
    Assertion,
    Attribute,
    Container,
    EqualityMatch,
    EscapeMode,
    ExtensibleMatch,
    Filter,
    GreaterOrEqual,
    Group,
    LessOrEqual,
    PresenceMatch,
    SubstringMatch,
    WalkStrategy,
)


complex_filter_expr = r"""
(&
  (|
    (cn=John Doe)
    (sn=*)
    (givenName=Jo*n*Do*)
    (uid>=1000)
    (uid<=2000)
    (mail~=j.doe@freeiam.org)
    (!(objectClass=inetOrgPerson))
  )
  (description=contains\28parentheses,spaces\20\29\5cand\2astars\2a)
  (objectClass:caseIgnoreMatch:=inetOrgPerson)
  (cn:dn:2.4.6.8.10:=John\20Doe)
)
""".strip()

VALID_FILTERS = [
    '',
    ' ',
    # equality match
    'cn=John',
    '(cn=John)',
    '(cn;lang-de;lang-en=John)',
    '(cn=*)',
    '(uid=1000)',
    '(sn=Smith)',
    '(member=cn=John Doe,ou=People,dc=freeiam,dc=org)',
    r'(filename=C:\5cMyFile)',
    r'(bin=\00\00\00\04)',
    r'(sn=Lu\c4\8di\c4\87)',
    # presence
    '(objectClass=*)',
    '(mail=*)',
    # substring
    '(cn=Jo*)',
    '(cn=*hn)',
    '(cn=*oh*)',
    '(cn=Jo*hn*Do*)',
    r'(cn=*\2A*)',
    # greater-or-equal
    '(uid>=1000)',
    '(age>=18)',
    r'(age>=\32)',
    r'(age>=\28)',
    r'(age>=\29)',
    r'(age>=18\20)',
    '(age>= 18)',
    '(cn>=John)',
    r'(cn>=J\6fhn)',
    r'(cn>=Jo\5c)',
    r'(cn>=Jo\2a)',
    # less-or-equal
    '(uid<=2000)',
    '(age<=65)',
    '(cn<=Smith)',
    r'(cn<=Sm\69th)',
    r'(cn<=\2aSmith\2a)',
    r'(uid<=\31\32\33)',
    r'(uid<=abc\5c)',
    # approx match
    '(mail~=j.doe@example.org)',
    '(cn~=John)',
    '(cn~=Jhn)',  # missing letter (approx)
    r'(cn~=J\6fhn)',  # escaped 'o'
    r'(cn~=Smith\20Jr\2e)',  # with escaped space and '.'
    r'(title~=Senior\20Engineer)',  # space escape
    r'(description~=multi\20word\20text)',
    r'(info~=\2a)',  # only escaped asterisk
    r'(uid~=abc\5c)',  # trailing backslash
    # extensible match
    '(cn:caseIgnoreMatch:=John)',
    '(cn:dn:caseIgnoreMatch:=John)',
    '(cn:DN:caseIgnoreMatch:=John)',
    '(cn:2.5.13.2:=John)',
    '(cn:dn:2.5.13.2:=John)',
    '(cn:DN:2.5.13.2:=John)',
    '(uniqueMember:1.2.840.113556.1.4.1941:=uid=john,ou=users,dc=freeiam,dc=org)',
    '(uniqueMember:inchainMatch:=uid=john,ou=users,dc=freeiam,dc=org)',
    '(cn:dn:=foo)',
    '(cn:=foo)',
    '(:dn:caseIgnoreMatch:=value)',
    '(:DN:caseIgnoreMatch:=value)',
    '(:dN:caseIgnoreMatch:=value)',
    '(:Dn:caseIgnoreMatch:=value)',
    '(:caseIgnoreMatch:=value)',
    '(:1.2.3:=Foo Bar)',
    '(cn:dn:Case-Ignore-Match:=John)',
    # NOT
    '(!(cn=John))',
    '(!(objectClass=*))',
    '(!(key>=42))',
    # AND
    '(&(cn=John)(sn=Doe))',
    '(&(objectClass=person)(uid>=1000)(uid<=2000))',
    '(&(cn=Alice)(mail=alice@freeiam.org))',
    '(&(objectClass=person)(|(sn=Foo)(cn=Bar *)))',
    # OR
    '(|(cn=John)(cn=Johnny))',
    '(|(objectClass=person)(objectClass=organizationalPerson))',
    # nested logical operators
    '(&(|(cn=John)(sn=Doe))(!(uid=123)))',
    '(!(|(&(a=b)(c=d))(!(e=f))))',
    # escape sequences
    r'(cn=John\20Doe)',
    r'(cn=\00)',
    r'(description=with\5cbackslash)',
    r'(cn=\2a)',  # literal '*'
    r'(cn=with\28paren\29)',  # '(' and ')'
    '(cn=%s)' % ('\\42' * 42),
    # minimal valid structure
    '(!(|(cn=a)))',
    '(&(!(a=b)))',
    # unicode/UTF-8-compatbile
    '(cn=Jörg)',
    '(ou=München)',
    # missing values
    '(seeAlso=)',
    '(uid>=)',
    '(uid<=)',
    '(mail~=)',
    '(cn:caseIgnoreMatch:=)',
    '(cn:dn:caseIgnoreMatch:=)',
    '(:caseIgnoreMatch:=)',
    # IPv4
    '(aRecord=192.0.2.1)',
    '(aRecord=10.0.*)',
    '(ipHostNumber=192.168.0.1)',
    '(ipHostNumber>=192.168.0.0)',
    '(ipHostNumber<=192.168.255.255)',
    # IPv6
    '(aAAARecord=2001:db8::1)',
    '(aAAARecord=fe80::%eth0)',
    '(aAAARecord=*2001:db8:*)',
    # MAC
    '(macAddress=00:11:22:33:44:55)',
    '(macAddress=00-11-22-33-44-55)',
    '(macAddress=0011.2233.4455)',
    '(macAddress~=00:11)',
    '(ieee802Device=00:11:22:33:44:55)',
    '(dhcpHWAddress=ethernet 00:11:22:33:44:55)',
    # whitespace
    '(cn= John)',
    '( cn=John )',
    '(& (cn=John))',
    '(&   (cn=John))',
    '(&( cn=John))',
    '(cn=Two  Whitespaces)',
    '(cn=  Two  Whitespaces  )',
    '(cn=* )',
    '(cn= *)',
    '(cn=Two  White*spaces)',
    '(cn=  Two  White*spaces  )',
    '(cn:dn:caseIgnoreMatch:= John)',
    # tricky cases
    '(cn==John)',
    '(cn===John)',
    '(mail=~=abc)',
    '(&)',
    '(|)',
    r'(cn=abc\\20)',
    r'(&(key=va\\28!\\29ue))',
    r'(&(key=va\\\\28!\\\\29ue))',
    r'(1.3.6.1.4.1.1466.0=\04\02\48\69)',
    '(cn::=John)',
    '(cn:dn::=John)',
    # rest
    '(0=foo)',
    '(1=foo)',
    '(11=foo)',
    '(x-z=foo)',
    '(cn;extra=foo)',
    '(1.2.3.4.5;x-tag=)',
    '(1.2.3.4.5;lang-de=John)',
    '(1.2.3.4.5;x-tag;lang-de=John)',
    '(cn;lang-de=John)',
    '(cn;lang-de;lang-en=John)',
    '(cn;lang=de=value)',
    # options
    '(cn;1=value)',
    '(cn;-=value)',
    '(cn;1-2=value)',
    '(cn;lang-de=value)',
    '(cn;lang-de;lang-en=value)',
    '(cn;LANG-DE=value)',
    '(cn;x-tag=value)',
    '(cn;x-tag;123=value)',
    '(1.2=value)',
    '(1.2.3.4.5=value)',
    '(1.2.3.4.5;x-tag=value)',
    '(1.2.3.4.5;1=value)',
    '(1.2.3.4.5;-=value)',
    '(1.2.3.4.5;x-tag;lang-de=value)',
    # everything
    complex_filter_expr,
] + [
    template.format(rule=rule)
    for rule in [
        'caseIgnoreMatch',
        'CASEIGNOREMATCH',
        'caseIgnoreMatch-',
        'caseIgnoreMatch--test',
        'x',
        'x-',
        'x--test',
        'x123',
        '1.2',
        '2.5.13.2',
        '0.0',
        '1.0.3',
        '1.2.840.113556.1.4.1941',
        'unknownMatchingRule',
        '01.2.3',  # meh: libldap allows :-(
        '1.02.3',  # meh: libldap allows :-(
        '1.2.03',  # meh: libldap allows :-(
        '1',  # meh: libldap allows :-(
        '123',  # meh: libldap allows :-(
    ]
    for template in (
        '(cn:{rule}:=John)',
        '(:{rule}:=John)',
        '(cn:dn:{rule}:=John)',
        '(:dn:{rule}:=John)',
    )
]

# also contains RFC 4515 violations accepted by libldap
STRICT_INVALID_FILTERS = [
    # non-standard escape sequences
    r'(attr=\*)',
    r'(attr=\()',
    r'(attr=\))',
    r'(attr=\\)',
    r'(attr=foo\*bar)',
    r'(attr=foo\\bar)',
    r'(attr=\\20)',
    # non-standard extensible match syntax
    '(cn::=John)',
    '(cn:dn::=John)',
    # insignificant whitespace outside assertion values
    '( cn=John)',
    '(&( cn=John))',
    '(& (cn=John))',
    # leading/trailing whitespace
    ' (cn=foo) ',
]

INVALID_FILTERS = [
    # empty
    '()',
    '(!)',
    '(()',
    '(())',
    # unbalanced
    '(',
    ')',
    '(cn=John Doe',
    '(&(cn=John)(sn=Smith)',
    '(|(a=b)(c=d)',
    '(!(a=b) extra )',
    # text
    'hello',
    # multiple NOT
    '(!(a=b)(b=c))',
    # invalid operators
    '(cn===John)(uid><1000)',
    # invalid attribute names
    '(=value)',
    '(123name=value)',
    '(.cn=value)',
    # invalid escaping
    r'(cn=abc\)',
    r'(cn=abc\ZZ)',
    r'(cn=comma\,separated)',  # ',' is not special, but this is common
    # invalid substring / presence
    '(cn=**)',
    '(cn=**test)',
    '(cn=test**)',
    '(cn=te**st)',
    '(cn=***test)',
    # invalid extensible
    '(cn:2.5.13.2=foo)',
    '(cn:dn:2.5-13.2:=John)',
    '(:=value)',
    '(:dn:=value)',
    '(:DN:=value)',
    '(:Dn:=value)',
    '(:dN:=value)',
    '(cn: dn :caseIgnoreMatch:=John)',
    '(cn:dn:caseIgnoreMatch:=*)',
    '(cn:dn:caseIgnoreMatch:=J*n)',
    # null byte in value
    '(cn=foo\x00bar)',
    # trash
    '(cn=John) extra',
    'some text (cn=John)(&(cn=John)(sn=Smith)) trailing )',
    # invalid combinations
    '(|(a=b)(c=*))(uid=1)',
    # whitespace
    pytest.param('(!\n  (|(cn=a))\n)', marks=pytest.mark.xfail(reason='test_invalid_filter: libldap denies, we allow')),
    '(cn =John)',
    '(cn\t=John)',
    '(cn\t=\tJohn)',
    '(cn=John) ',
    ' (cn=John) ',
    ' (cn=John)',
    '( & ( a = b ) )',
    '(cn:dn :caseIgnoreMatch:=John)',
    '(cn:dn: caseIgnoreMatch:=John)',
    '(cn:dn:caseIgnoreMatch :=John)',
    '(cn:dn:caseIgnoreMatch := John)',
    '(cn:dn : caseIgnoreMatch:=John)',
    '(cn:dn :caseIgnoreMatch :=John)',
    '(cn:dn :caseIgnoreMatch:= John)',
    '(cn:dn: caseIgnoreMatch :=John)',
    '(cn:dn: caseIgnoreMatch:= John)',
    '(cn:dn: caseIgnoreMatch := John)',
    '(::=John)',
    '(:dn::=John)',
    # misc
    r'(cn=\)',
    r'(cn=abc\2g)',
    '((o={*)(dc=*))',
    '(_=foo)',
    '(_x=foo)',
    '(x_z=foo)',
    '(;=foo)',
    '(;x=foo)',
    '(-x=foo)',
    '(-=f)',
    '  ',
    '((((((((((((((((((((((((((((((((((((((((((((((((((cn=John))))))))))))))))))))))))))))))))))))))))))))))))))',
    '(!(!(!(!(&(&(&(|(|(|(cn=John))))))))))))',
    # empty options
    '(cn;=value)',
    '(cn;;=value)',
    '(cn;;;=value)',
    '(cn;;lang-de=value)',
    '(cn;lang-de;=value)',
    '(cn;lang-de;;lang-en=value)',
    '(1.2.3.4.5;=value)',
    '(1.2.3.4.5;;=value)',
    '(1.2.3.4.5;;x-tag=value)',
    '(1.2.3.4.5;x-tag;=value)',
    '(1.2.3.4.5;x-tag;;lang-de=value)',
    # invalid characters
    '(cn;lang_de=value)',
    '(cn;lang.de=value)',
    '(cn;lang de=value)',
    '(cn;lang\tde=value)',
    '(cn;lang/de=value)',
    '(cn;lang:de=value)',
    '(cn;lang+de=value)',
    '(cn;lang@de=value)',
    '(cn;lang*de=value)',
    '(cn;lang(de)=value)',
    '(cn;lang\\2dde=value)',
    '(1.2.3.4.5;x_tag=value)',
    '(1.2.3.4.5;x.tag=value)',
    '(1.2.3.4.5;x tag=value)',
    # whitespace around separators
    '(cn ;lang-de=value)',
    '(cn; lang-de=value)',
    '(cn;lang-de =value)',
    '(cn ; lang-de=value)',
    '(1.2.3.4.5 ;x-tag=value)',
    '(1.2.3.4.5; x-tag=value)',
    '(1.2.3.4.5;x-tag =value)',
    # backslash in non-values
    r'(cn\2dtest=John)',
    r'(cn\5ctest=John)',
    r'(cn;lang\2dde=John)',
    r'(1.2.3\2e4=John)',
    r'(cn:case\49gnoreMatch:=John)',
] + [
    template.format(rule=rule)
    for rule in [
        # empty or incomplete descriptors
        '-',
        '--',
        '-caseIgnoreMatch',
        '1caseIgnoreMatch',
        # attribute options are not allowed
        'caseIgnoreMatch;',
        'caseIgnoreMatch;x-tag',
        'caseIgnoreMatch;lang-de',
        'caseIgnoreMatch;;lang-de',
        '2.5.13.2;x-tag',
        '2.5.13.2;1',
        # invalid numeric OIDs
        '1.',
        '.1',
        '1..2',
        '1.2.',
        '1.2..3',
        # invalid characters
        '_caseIgnoreMatch',
        'case_IgnoreMatch',
        'case.IgnoreMatch',
        'case/IgnoreMatch',
        'case+IgnoreMatch',
        'case@IgnoreMatch',
        'case*IgnoreMatch',
        'case\\2dIgnoreMatch',
        # whitespace
        ' caseIgnoreMatch',
        'caseIgnoreMatch ',
        'case IgnoreMatch',
        'case\tIgnoreMatch',
        'case\nIgnoreMatch',
        '2.5.13.2 ',
        '2.5.13. 2',
    ]
    for template in (
        '(cn:{rule}:=John)',
        '(:{rule}:=John)',
        '(cn:dn:{rule}:=John)',
        '(:dn:{rule}:=John)',
    )
]


# Additional cases from https://www.openldap.org/ietf/ldapbis/filters.txt
OPENLDAP_VALID_FILTERS = [
    '(attr=*)',
    '(attr;x-tag=*)',
    '(attr=)',
    '(1.2.3.4.5=)',
    '(1.2.3.4.5;x-tag=)',
    '(space= )',
    '(attr=value)',
    r'(null=\00)',
    r'(bell=\07)',
    '(bell=\x07)',
    r'(attr;x-star=\2a)',
    r'(attr;x-escape=\5C)',
    '(attr=initial*)',
    '(attr=*any*)',
    '(attr=*final)',
    '(attr=initial*final)',
    '(attr=initial*any*any*final)',
    '(attr=initial*any*)',
    '(attr=*any*final)',
    '(attr=*any*any*)',
    '(attr~=)',
    '(attr~=fubar)',
    '(attr>=fubar)',
    '(attr<=fubar)',
    '(attr:1.2.3:=fubar)',
    '(attr:dn:=fubar)',
    '(attr:DN:=fubar)',
    '(attr:dn:1.2.3:=fubar)',
    '(:1.2.3:=fubar)',
    '(:caseExactMatch:=fubar)',
    '(:dn:1.2.3:=fubar)',
    '(:dn:caseIgnoreMatch:=fubar)',
    '(!(objectClass=*))',
    '(&(objectClass=*))',
    '(&(objectClass=*)(name~=))',
    '(|(objectClass=*))',
    '(|(objectClass=*)(name~=))',
]

OPENLDAP_VALID_FILTERS_BUT_OPENLDAP_ITSELF_DOES_NOT_RESPECT_THAT = [
    '(attr=**)',
    '(attr=initial**)',
    '(attr=**final)',
    '(attr=initial**final)',
    '(attr=initial***final)',
    '(!(|(&(!(objectClass=*))))',
]

OPENLDAP_INVALID_FILTERS = [
    '(attr=*',
    'attr=*)',
    '(attr~=*)',
    '(attr=\x00)',
    '(attr=()',
    '(attr=))',
    r'(attr=\)',
    r'(attr=\GG)',
    r'(attr=\F)',
    r'(attr=\x)',
    '(attr>0)',
    '(attr<0)',
    '(attr?=value)',
    '  ',
    '()',
    '(=)',
    '(;option=*)',
    '(attr;=*)',
    '(at_tr=*)',
    '(attr;opt_=*)',
    r'(attr\3Boption=*)',
    '(:=)',
    '(::=)',
    '(:::=)',
    '(!)',
    '(!(attr=TRUE)(attr=FALSE))',
    '(attr?=)',
]

OPENLDAP_INVALID_FILTERS_BUT_OPENLDAP_ITSELF_DOES_NOT_RESPECT_THAT = [
    'attr=*',
    '(|)',
    '(|(uid=cn)(cn=cn))',  # invalid tag
    # the following are moved to STRICT_INVALID_FILTERS
    # r'(attr=\*)',
    # r'(attr=\()',
    # r'(attr=\))',
    # r'(attr=\\)',
]

ALL_VALID_FILTERS = VALID_FILTERS + OPENLDAP_VALID_FILTERS + OPENLDAP_INVALID_FILTERS_BUT_OPENLDAP_ITSELF_DOES_NOT_RESPECT_THAT
ALL_INVALID_FILTERS = INVALID_FILTERS + OPENLDAP_INVALID_FILTERS + OPENLDAP_VALID_FILTERS_BUT_OPENLDAP_ITSELF_DOES_NOT_RESPECT_THAT


@pytest.mark.parametrize('expr', ALL_VALID_FILTERS)
def test_valid_filter(expr, parser):
    try:
        Filter(expr, parser=parser, strict=expr not in STRICT_INVALID_FILTERS)
    except FilterError:
        Filter(expr, parser=parser, _debug=True)

    Filter(Filter(expr, parser=parser).pretty(), parser=parser)


@pytest.mark.parametrize('expr', ALL_VALID_FILTERS)
def test_filter_parse_compose(expr, parser):
    """BER discards spelling, escaped-byte case, and optional whitespace."""
    fil = Filter(expr, parser=parser)
    if not fil.root:
        assert str(fil) == expr
        return
    canonical = str(fil)
    reparsed = Filter(canonical, parser=parser)
    assert reparsed.to_ber() == fil.to_ber()
    assert str(reparsed) == canonical


@pytest.fixture(params=['libldap', 'lark'])
def parser(request):
    return request.param


@pytest.mark.parametrize(
    'expression',
    [*ALL_VALID_FILTERS, '(cn=John)', '(cn=*)', '(cn=* )', '(cn= *)', r'(cn=foo\2abar*)', r'(cn=J\6fhn)', '(&(cn=John)(sn=Doe))', '(!(uid>=1000))'],
)
def test_parser_equivalence(expression, parser):
    result = Filter(expression, parser=parser)
    reference = Filter(expression, parser='libldap')

    assert result.to_ber() == reference.to_ber()


@pytest.mark.parametrize('expr', ALL_VALID_FILTERS)
def test_libldap_valid_filter(expr):
    try:
        _validate_filter(expr)
    except FilterError:
        pytest.fail(expr)


@pytest.mark.parametrize('expr', ALL_INVALID_FILTERS)
def test_invalid_filter(expr, parser):
    with pytest.raises(FilterError):
        Filter(expr, parser=parser, strict=expr in STRICT_INVALID_FILTERS)


@pytest.mark.parametrize('expr', ALL_INVALID_FILTERS)
def test_libldap_invalid_filter(expr):
    with pytest.raises(FilterError):
        _validate_filter(expr)


def _validate_filter(expr):
    lo = ldap.initialize('')
    try:
        lo.search_ext_s('', ldap.SCOPE_BASE, expr)
    except ldap.FILTER_ERROR as exc:
        raise FilterError.from_ldap_exception(exc) from None
    except ValueError as exc:
        if str(exc) != 'embedded null character':
            raise
        raise FilterError({}) from None
    except ldap.SERVER_DOWN:
        pass
    finally:
        lo.unbind()


def validate_filter(expr):
    try:
        _validate_filter(expr)
    except FilterError:
        return False
    return True


def get_filter_root(filter_expr, parser='lark', **kwargs):
    """Return the actual comparison/operator, unwrapping the textual Group."""
    for expr in Filter(filter_expr, parser=parser, _debug=True, **kwargs).root.expressions:
        if isinstance(expr, (AND, OR, NOT, Assertion)):
            return expr
    return None
    root = Filter(filter_expr, parser=parser, _debug=True).root
    if isinstance(root, Group) and not isinstance(root, (AND, OR, NOT)):
        return root.expressions[0]
    return root


@pytest.mark.parametrize('expr', [' cn=foo ', *STRICT_INVALID_FILTERS])
def test_strict_parsing(expr):
    with pytest.raises(FilterError):
        Filter(expr, parser='lark', strict=True)


def test_equality_match(parser):
    fil = get_filter_root('(cn=foo)', parser)
    assert isinstance(fil, EqualityMatch)


def test_approximate_match(parser):
    fil = get_filter_root('(cn~=foo)', parser)
    assert isinstance(fil, ApproximateMatch)


@pytest.mark.parametrize(
    'expr, expected',
    [
        ('(cn:caseIgnoreMatch:=john)', (ExtensibleMatch, 'cn', False, 'caseIgnoreMatch', b'john')),
        ('(cn:dn:=John Doe)', (ExtensibleMatch, 'cn', 'dn', None, b'John Doe')),
        ('(cn:dn:caseIgnoreMatch:=John Doe)', (ExtensibleMatch, 'cn', 'dn', 'caseIgnoreMatch', b'John Doe')),
        ('(:dn:caseIgnoreMatch:=John Doe)', (ExtensibleMatch, '', 'dn', 'caseIgnoreMatch', b'John Doe')),
        ('(sn:2.5.13.3:=DOE)', (ExtensibleMatch, 'sn', False, '2.5.13.3', b'DOE')),
    ],
)
def test_extensible_match(expr, expected, parser):
    fil = get_filter_root(expr, parser)
    assert (type(fil), fil.attr, fil.dn, fil.matchingrule, fil.value) == expected


def test_ge_match(parser):
    fil = get_filter_root('(cn>=1)', parser)
    assert isinstance(fil, GreaterOrEqual)


def test_le_match(parser):
    fil = get_filter_root('(cn<=1)', parser)
    assert isinstance(fil, LessOrEqual)


def test_presence_match(parser):
    fil = get_filter_root('(cn=*)', parser)
    assert isinstance(fil, PresenceMatch)
    assert not isinstance(get_filter_root('(cn= *)', parser), PresenceMatch)
    assert not isinstance(get_filter_root('(cn=* )', parser), PresenceMatch)


def test_substring_match(parser):
    fil = get_filter_root('(cn=*foo*)', parser)
    assert isinstance(fil, SubstringMatch)
    assert fil.decode() == (None, 'foo', None)
    assert get_filter_root(r'(cn=*foo*b\2Ar*baz)', parser).decode() == (None, 'foo', 'b*r', 'baz')


@pytest.mark.parametrize(
    'expr,attrs',
    [
        ('(cn= John)', {'attr': 'cn', 'value': b' John'}),
        ('( cn=John )', {'attr': 'cn', 'value': b'John '}),
        ('(cn=John )', {'attr': 'cn', 'value': b'John '}),
        ('(cn= John )', {'attr': 'cn', 'value': b' John '}),
        ('(& (cn=John))', {'attr': 'cn', 'value': b'John'}),
        ('(&(cn=John) )', {'attr': 'cn', 'value': b'John'}),
        ('(&   (cn=John))', {'attr': 'cn', 'value': b'John'}),
        ('(&( cn=John))', {'attr': 'cn', 'value': b'John'}),
        ('(& (  cn=John  ) )', {'attr': 'cn', 'value': b'John  '}),
        ('(&  ( cn=John )  )', {'attr': 'cn', 'value': b'John '}),
        ('(&  ( cn= John )  )', {'attr': 'cn', 'value': b' John '}),
        ('(cn=Two  Whitespaces)', {'attr': 'cn', 'value': b'Two  Whitespaces'}),
        ('(cn=* )', {'attr': 'cn', 'initial': None, 'final': b' ', 'any': (), '__class__': SubstringMatch}),
        ('(cn= *)', {'attr': 'cn', 'initial': b' ', 'final': None, 'any': (), '__class__': SubstringMatch}),
        ('(cn=Two  White*spaces)', {'attr': 'cn', 'initial': b'Two  White', 'final': b'spaces', 'any': (), '__class__': SubstringMatch}),
        ('(cn=  Two  White*spaces  )', {'attr': 'cn', 'initial': b'  Two  White', 'final': b'spaces  ', 'any': (), '__class__': SubstringMatch}),
    ],
)
def test_whitespace_preserve(expr, attrs, parser):
    root = get_filter_root(expr, parser, strict=False)
    # the original AND structure must survive BER decoding. Inspect its
    # comparison child, rather than treating the operator as a comparison.
    if isinstance(root, AND):
        assert len(root.expressions) == 1
        fil = root.expressions[0]
    else:
        fil = root
    assert isinstance(fil, Assertion)
    assert fil.attr == attrs['attr']
    if 'initial' in attrs:
        assert isinstance(fil, SubstringMatch)
        assert fil.initial == attrs['initial']
        assert fil.final == attrs['final']
        assert fil.any == attrs['any']
    else:
        assert fil.value == attrs['value']
    if '__class__' in attrs:
        assert type(fil) is attrs['__class__']
    # assert the semantic structure survives formatting and re-parsing.
    assert Filter(str(Filter(expr)), parser=parser).to_ber() == Filter(expr).to_ber()


def test_extensible_match_whitespace_combinations(parser):
    # test all 128 possible combinations
    parts = ['cn', ':', 'dn', ':', 'caseIgnoreMatch', ':=', 'John']

    combos = []
    for mask in range(1 << (len(parts) - 1)):
        s = ''
        for i, part in enumerate(parts):
            s += part
            if i < len(parts) - 1 and mask & (1 << i):
                s += ' '
        combos.append(f'({s})')

    errors = []
    for c in combos:
        try:
            Filter(c, parser=parser)
        except FilterError:
            if validate_filter(c):
                errors.append(c)
    assert not errors


@pytest.mark.parametrize(
    'expr,value,unescape',
    [
        (
            r'(description=contains\28parentheses,spaces\20\29\5cand\2astars\2a)',
            rb'contains\28parentheses,spaces\20\29\5cand\2astars\2a',
            rb'contains(parentheses,spaces )\and*stars*',
        ),
        (r'(cn:dn:2.4.6.8.10:=John\20Doe)', rb'John\20Doe', rb'John Doe'),
        (r'(filename=C:\5cMyFile)', rb'C:\5cMyFile', rb'C:\MyFile'),
        (r'(bin=\00\00\00\04)', rb'\00\00\00\04', b'\00\00\00\04'),
        (r'(sn=Lu\c4\8di\c4\87)', rb'Lu\c4\8di\c4\87', b'Lu\xc4\x8di\xc4\x87'),
        (r'(cn=*\2A*)', rb'*\2A*', (None, '*', None)),
        (r'(cn=John\20Doe)', rb'John\20Doe', rb'John Doe'),
        (r'(cn=\00)', rb'\00', b'\x00'),
        (r'(description=with\5cbackslash)', rb'with\5cbackslash', rb'with\backslash'),
        (r'(cn=\2a)', rb'\2a', rb'*'),
        (r'(cn=with\28paren\29)', rb'with\28paren\29', rb'with(paren)'),
        ('(cn=abc\\20)', b'abc\\20', rb'abc '),
        (r'(cn=cde\\20)', rb'cde\\20', b'cde\\20'),  # b'cde\\ '
        ('(&(key=va\\\\28!\\\\29ue))', b'va\\\\28!\\\\29ue', b'va\\28!\\29ue'),  # rb'va\(!\)ue'
        (r'(1.3.6.1.4.1.1466.0=\04\02\48\69)', rb'\04\02\48\69', b'\x04\x02Hi'),
    ],
)
def test_unescape(expr, value, unescape, parser):
    fil = get_filter_root(expr, parser)
    if parser == 'lark':
        assert fil._raw_escaped_value == value
    if not isinstance(fil, SubstringMatch):
        assert fil.value == unescape
    else:
        assert fil.decode() == unescape


def test_comparison_unescape():
    assert EqualityMatch.from_escaped('cn', rb'foo\20bar').value == b'foo bar'
    assert EqualityMatch('cn', rb' foobar ').escaped == r'\20foobar\20'
    assert EqualityMatch('cn', rb' foobar ').value == b' foobar '


def test_escape():
    ascii_chars = ''.join(chr(i) for i in range(128))
    assert (
        Filter.escape(ascii_chars, EscapeMode.SPECIAL)
        == '\\00\x01\x02\x03\x04\x05\x06\x07\x08\t\n\x0b\x0c\r\x0e\x0f\x10\x11\x12\x13\x14\x15\x16\x17\x18\x19\x1a\x1b\x1c\x1d\x1e\x1f !"#$%&\'\\28\\29\\2a+,-./0123456789:;<=>?@ABCDEFGHIJKLMNOPQRSTUVWXYZ[\\5c]^_`abcdefghijklmnopqrstuvwxyz{|}~\x7f'  # noqa: E501
    )
    assert (
        Filter.escape(ascii_chars, EscapeMode.RESTRICTED)
        == '\\00\\01\\02\\03\\04\\05\\06\\07\\08\\09\\0a\\0b\\0c\\0d\\0e\\0f\\10\\11\\12\\13\\14\\15\\16\\17\\18\\19\\1a\\1b\\1c\\1d\\1e\\1f\\20\\21\\22\\23\\24\\25\\26\\27\\28\\29\\2a\\2b\\2c\\2d\\2e\\2f0123456789:;<=>?@ABCDEFGHIJKLMNOPQRSTUVWXYZ[\\5c]^_`abcdefghijklmnopqrstuvwxyz\\7b\\7c\\7d\\7e\\7f'  # noqa: E501
    )
    assert (
        Filter.escape(ascii_chars, EscapeMode.ALL)
        == '\\00\\01\\02\\03\\04\\05\\06\\07\\08\\09\\0a\\0b\\0c\\0d\\0e\\0f\\10\\11\\12\\13\\14\\15\\16\\17\\18\\19\\1a\\1b\\1c\\1d\\1e\\1f\\20\\21\\22\\23\\24\\25\\26\\27\\28\\29\\2a\\2b\\2c\\2d\\2e\\2f\\30\\31\\32\\33\\34\\35\\36\\37\\38\\39\\3a\\3b\\3c\\3d\\3e\\3f\\40\\41\\42\\43\\44\\45\\46\\47\\48\\49\\4a\\4b\\4c\\4d\\4e\\4f\\50\\51\\52\\53\\54\\55\\56\\57\\58\\59\\5a\\5b\\5c\\5d\\5e\\5f\\60\\61\\62\\63\\64\\65\\66\\67\\68\\69\\6a\\6b\\6c\\6d\\6e\\6f\\70\\71\\72\\73\\74\\75\\76\\77\\78\\79\\7a\\7b\\7c\\7d\\7e\\7f'  # noqa: E501
    )
    latin_chars = ''.join(chr(i) for i in range(128, 256))
    assert Filter.escape(latin_chars, EscapeMode.SPECIAL) == latin_chars
    assert (
        Filter.escape(latin_chars, EscapeMode.RESTRICTED)
        == '\\80\\81\\82\\83\\84\\85\\86\\87\\88\\89\\8a\\8b\\8c\\8d\\8e\\8f\\90\\91\\92\\93\\94\\95\\96\\97\\98\\99\\9a\\9b\\9c\\9d\\9e\\9f\\a0\\a1\\a2\\a3\\a4\\a5\\a6\\a7\\a8\\a9\\aa\\ab\\ac\\ad\\ae\\af\\b0\\b1\\b2\\b3\\b4\\b5\\b6\\b7\\b8\\b9\\ba\\bb\\bc\\bd\\be\\bf\\c0\\c1\\c2\\c3\\c4\\c5\\c6\\c7\\c8\\c9\\ca\\cb\\cc\\cd\\ce\\cf\\d0\\d1\\d2\\d3\\d4\\d5\\d6\\d7\\d8\\d9\\da\\db\\dc\\dd\\de\\df\\e0\\e1\\e2\\e3\\e4\\e5\\e6\\e7\\e8\\e9\\ea\\eb\\ec\\ed\\ee\\ef\\f0\\f1\\f2\\f3\\f4\\f5\\f6\\f7\\f8\\f9\\fa\\fb\\fc\\fd\\fe\\ff'  # noqa: E501
    )
    assert (
        Filter.escape(latin_chars, EscapeMode.ALL)
        == '\\80\\81\\82\\83\\84\\85\\86\\87\\88\\89\\8a\\8b\\8c\\8d\\8e\\8f\\90\\91\\92\\93\\94\\95\\96\\97\\98\\99\\9a\\9b\\9c\\9d\\9e\\9f\\a0\\a1\\a2\\a3\\a4\\a5\\a6\\a7\\a8\\a9\\aa\\ab\\ac\\ad\\ae\\af\\b0\\b1\\b2\\b3\\b4\\b5\\b6\\b7\\b8\\b9\\ba\\bb\\bc\\bd\\be\\bf\\c0\\c1\\c2\\c3\\c4\\c5\\c6\\c7\\c8\\c9\\ca\\cb\\cc\\cd\\ce\\cf\\d0\\d1\\d2\\d3\\d4\\d5\\d6\\d7\\d8\\d9\\da\\db\\dc\\dd\\de\\df\\e0\\e1\\e2\\e3\\e4\\e5\\e6\\e7\\e8\\e9\\ea\\eb\\ec\\ed\\ee\\ef\\f0\\f1\\f2\\f3\\f4\\f5\\f6\\f7\\f8\\f9\\fa\\fb\\fc\\fd\\fe\\ff'  # noqa: E501
    )


def test_escape_format():
    assert Filter.escape_formatted('foo=%s', ['*bar*']) == 'foo=\\2abar\\2a'
    assert isinstance(Filter.from_format('foo=%s', ['*bar*']), Filter)


def test_escape_attribute():
    user_input = 'foo (bar)*'
    cn = Filter.attr('cn')

    assert str(cn == '') == 'cn='  # noqa: PLC1901
    assert repr(cn == '') == 'EqualityMatch(cn=)'  # noqa: PLC1901

    assert str(cn != None) == 'cn=*'  # noqa: E711
    assert repr(cn != None) == 'PresenceMatch(cn=*)'  # noqa: E711

    assert str(cn == user_input) == r'cn=foo \28bar\29\2a'
    assert repr(cn == user_input) == "EqualityMatch(cn=escape(b'foo (bar)*'))"

    assert str(cn != user_input) == r'(!(cn=foo \28bar\29\2a))'
    assert repr(cn != user_input) == "NOT( EqualityMatch(cn=escape(b'foo (bar)*')) )"

    # literal '*' in a substring component must NOT become a wildcard.
    expr = cn == ['', user_input, '']
    assert str(expr) == r'cn=*foo \28bar\29\2a*'
    assert repr(expr) == r"SubstringMatch(cn=escape(initial=None, any=(b'foo (bar)*',), final=None))"

    expr = cn == user_input.split('*')
    assert str(expr) == r'cn=foo \28bar\29*'
    assert repr(expr) == r"SubstringMatch(cn=escape(initial=b'foo (bar)', any=(), final=None))"

    assert str(cn > '1000') == '(!(cn<=1000))'
    assert repr(cn > '1000') == "NOT( LessOrEqual(cn<=escape(b'1000')) )"

    assert str(cn >= '1000') == 'cn>=1000'
    assert repr(cn >= '1000') == "GreaterOrEqual(cn>=escape(b'1000'))"

    assert str(cn < '1000') == '(!(cn>=1000))'
    assert repr(cn < '1000') == "NOT( GreaterOrEqual(cn>=escape(b'1000')) )"

    assert str(cn <= '1000') == 'cn<=1000'
    assert repr(cn <= '1000') == "LessOrEqual(cn<=escape(b'1000'))"

    assert str(cn > 1000) == 'cn>=1001'
    assert repr(cn > 1000) == "GreaterOrEqual(cn>=escape(b'1001'))"

    assert str(cn >= 1000) == 'cn>=1000'
    assert repr(cn >= 1000) == "GreaterOrEqual(cn>=escape(b'1000'))"

    assert str(cn < 1000) == 'cn<=999'
    assert repr(cn < 1000) == "LessOrEqual(cn<=escape(b'999'))"

    assert str(cn <= 1000) == 'cn<=1000'
    assert repr(cn <= 1000) == "LessOrEqual(cn<=escape(b'1000'))"

    assert str(cn.approx == user_input) == r'cn~=foo \28bar\29\2a'
    assert repr(cn.approx == user_input) == "ApproximateMatch(cn~=escape(b'foo (bar)*'))"

    assert str(cn.extensible('generalizedTimeMatch') == user_input) == r'cn:generalizedTimeMatch:=foo \28bar\29\2a'
    assert repr(cn.extensible('generalizedTimeMatch') == user_input) == "ExtensibleMatch(cn:generalizedTimeMatch:=escape(b'foo (bar)*'))"

    assert str((cn == 'foo') | (cn == 'bar')) == '(|(cn=foo)(cn=bar))'
    assert repr((cn == 'foo') | (cn == 'bar')) == "OR( EqualityMatch(cn=escape(b'foo')) | EqualityMatch(cn=escape(b'bar')) )"

    assert str((cn != 'foo') & (cn != 'bar')) == '(&(!(cn=foo))(!(cn=bar)))'
    assert repr((cn != 'foo') & (cn != 'bar')) == "AND( NOT( EqualityMatch(cn=escape(b'foo')) ) & NOT( EqualityMatch(cn=escape(b'bar')) ) )"

    assert str(((cn == 'foo') | (cn == 'bar')).negate()) == '(!( |(cn=foo)(cn=bar) ))'.replace(' ', '')
    assert repr(((cn == 'foo') | (cn == 'bar')).negate()) == "NOT( OR( EqualityMatch(cn=escape(b'foo')) | EqualityMatch(cn=escape(b'bar')) ) )"


def test_escape_classic():
    user_input = 'foo (bar)*'
    ipv4 = '127.0.0.1'
    ipv6 = '::1'

    assert repr(Filter.get_pres('cn')) == 'PresenceMatch(cn=*)'
    assert repr(Filter.get_eq('cn', user_input)) == "EqualityMatch(cn=escape(b'foo (bar)*'))"
    assert repr(Filter.get_approx('cn', user_input)) == "ApproximateMatch(cn~=escape(b'foo (bar)*'))"
    assert repr(Filter.get_substring('cn', *user_input.split('*'))) == r"SubstringMatch(cn=escape(initial=b'foo (bar)', any=(), final=None))"
    assert repr(Filter.get_substring('cn', '', 'foo', '')) == "SubstringMatch(cn=escape(initial=None, any=(b'foo',), final=None))"
    assert repr(Filter.get_gt_eq('uidNumber', 1000)) == "GreaterOrEqual(uidNumber>=escape(b'1000'))"
    assert repr(Filter.get_extensible('cn', 'generalizedTimeMatch', user_input)) == "ExtensibleMatch(cn:generalizedTimeMatch:=escape(b'foo (bar)*'))"
    assert (
        repr(Filter.get_and(Filter.get_eq('objectClass', 'person'), Filter.get_eq('cn', user_input)))
        == "AND( EqualityMatch(objectClass=escape(b'person')) & EqualityMatch(cn=escape(b'foo (bar)*')) )"
    )
    assert (
        repr(Filter.get_or(Filter.get_eq('aRecord', ipv4), Filter.get_eq('aAAARecord', ipv6)))
        == "OR( EqualityMatch(aRecord=escape(b'127.0.0.1')) | EqualityMatch(aAAARecord=escape(b'::1')) )"
    )
    assert repr(Filter.get_not(Filter.get_eq('cn', user_input))) == "NOT( EqualityMatch(cn=escape(b'foo (bar)*')) )"


def test_substring_component_literal_asterisk(parser):
    expr = Filter.get_substring('cn', b'prefix', b'literal*asterisk', b'suffix')
    assert expr.initial == b'prefix'
    assert expr.any == (b'literal*asterisk',)
    assert expr.final == b'suffix'
    assert str(expr) == r'cn=prefix*literal\2aasterisk*suffix'
    # the two kinds of '*' must remain distinct after serializing and parsing.
    parsed = get_filter_root(f'({expr})', parser)
    assert isinstance(parsed, SubstringMatch)
    assert parsed.initial == expr.initial
    assert parsed.any == expr.any
    assert parsed.final == expr.final


def test_hash():
    assert hash(Attribute('a')) == hash(Attribute('a'))
    assert hash(Attribute('a') == '1') == hash(Attribute('a') == '1')
    assert hash(EqualityMatch('cn', b'foo')) == hash(EqualityMatch('cn', b'foo'))
    assert hash(EqualityMatch('cn', b'')) != hash(PresenceMatch('cn'))
    assert hash(ExtensibleMatch('cn', b'foo', 'caseIgnoreMatch')) == hash(ExtensibleMatch('cn', b'foo', 'caseIgnoreMatch'))
    assert hash(ExtensibleMatch('cn', b'foo', 'caseIgnoreMatch')) == hash(ExtensibleMatch('CN', b'foo', 'caseignorematch'))
    assert hash(ExtensibleMatch('cn', b'foo', 'caseIgnoreMatch')) != hash(ExtensibleMatch('cn', b'foo', 'caseExactMatch'))
    assert hash(ExtensibleMatch('cn', b'foo', '')) != hash(ExtensibleMatch('cn', b'foo', 'caseExactMatch'))


def test_attribute_error_handling():
    with pytest.raises(ValueError, match=r'a\*'):
        Attribute('a*')
    with pytest.raises(ValueError, match=r'a\*'):
        Attribute('a', dn=True, matchingrule='a*')

    with pytest.raises(ValueError, match=r'1\.a'):
        Attribute('1.a')
    with pytest.raises(ValueError, match=r'1\.a'):
        Attribute('a', dn=True, matchingrule='1.a')


def test_root(parser):
    assert isinstance(Filter('(&(a=b))', parser=parser).root, AND)
    assert isinstance(Filter('(|(a=b))', parser=parser).root, OR)
    assert isinstance(Filter('(!(a=b))', parser=parser).root, NOT)
    assert isinstance(Filter('(a=b)', parser=parser).root, Group)
    assert isinstance(Filter('a=b', parser=parser).root, Container)


def test_copy(parser):
    original = Filter(r'(&(|(cn=J\6fhn)(sn=Smith))(mail=foo*bar*baz)(uid:dn:caseIgnoreMatch:=admin)(l=*))', parser=parser)
    copied = original.ast.copy()

    assert copied is not original.ast
    # assert str(copied) == str(original.ast)
    assert repr(copied) == repr(original.ast)

    # verify that copy() creates independent AST nodes
    def compare_nodes(left, right):
        assert type(left) is type(right)
        assert left is not right

        if isinstance(left, Container):
            assert len(left.expressions) == len(right.expressions)
            for a, b in zip(left.expressions, right.expressions, strict=False):
                compare_nodes(a, b)

    compare_nodes(original.ast, copied)

    # changing a copied assertion must not affect the original
    copied_and = copied.expressions[0]
    copied_or = copied_and.expressions[0]
    copied_cn = copied_or.expressions[0]

    assert isinstance(copied_cn, EqualityMatch)
    copied_cn.value = b'Jane'

    assert 'cn=Jane' in str(copied)
    if parser == 'lark':
        assert r'cn=J\6fhn' in str(original.ast)
    else:
        assert r'cn=John' in str(original.ast)

    assert isinstance(copied_and.expressions[1], SubstringMatch)
    assert isinstance(copied_and.expressions[2], ExtensibleMatch)
    assert isinstance(copied_and.expressions[3], PresenceMatch)


def test_pretty(parser):
    fil = Filter('(&(|(cn=John)(sn=Smith))(mail=foo*bar)(!(uid=guest)))', parser=parser)

    assert fil.pretty() == ('(&\n  (|\n    (cn=John)\n    (sn=Smith)\n  )\n  (mail=foo*bar)\n  (!(uid=guest))\n)')

    assert fil.pretty(indent=1) == ('  (&\n    (|\n      (cn=John)\n      (sn=Smith)\n    )\n    (mail=foo*bar)\n    (!(uid=guest))\n  )')

    assert Filter('(cn=John)', parser=parser).pretty() == '(cn=John)'
    assert not Filter('', parser=parser).pretty()


def test_timespan_filter():
    assert str(Filter.time_span_filter(0, 1)) == '(&(modifyTimestamp>=19700101000000Z)(!(modifyTimestamp>=19700101000001Z)))'


def test_repr():
    expected = "Filter(AND( GreaterOrEqual(modifyTimestamp>=escape(b'19700101000000Z')) & NOT( GreaterOrEqual(modifyTimestamp>=escape(b'19700101000001Z')) ) ))"  # noqa: E501
    assert repr(Filter.time_span_filter(0, 1)) == expected


def test_walk_func(parser):
    import io

    filter_s = '(|(&(!(zone=freeiam.org))(cn=foo))(uid=bar))'
    filter_p = Filter(filter_s, parser=parser)

    def dump(filter_, par, expr):
        print(str(expr), file=s)

    text = """zone=freeiam.org\ncn=foo\nuid=bar"""
    s = io.StringIO()
    filter_p.walk(dump, None, WalkStrategy.POST)
    assert s.getvalue().strip() == text

    s = io.StringIO()
    filter_p.walk(dump, None, WalkStrategy.PRE)
    assert s.getvalue().strip() == text

    s = io.StringIO()
    filter_p.walk(dump, None, WalkStrategy.BOTH)
    assert s.getvalue().strip() == text

    pre_text = '(!(zone=freeiam.org))\n(&(!(zone=freeiam.org))(cn=foo))\n(|(&(!(zone=freeiam.org))(cn=foo))(uid=bar))'
    s = io.StringIO()
    filter_p.walk(None, dump, WalkStrategy.POST)
    assert s.getvalue().strip() == pre_text

    post_text = '(|(&(!(zone=freeiam.org))(cn=foo))(uid=bar))\n(&(!(zone=freeiam.org))(cn=foo))\n(!(zone=freeiam.org))'
    s = io.StringIO()
    filter_p.walk(None, dump, WalkStrategy.PRE)
    assert s.getvalue().strip() == post_text

    s = io.StringIO()
    filter_p.walk(None, dump, WalkStrategy.BOTH)
    assert s.getvalue().strip() == f'{post_text}\n{pre_text}'


def test_walk_replace(parser):
    fil = Filter('(&(append=1)(|(replace=not)(remove=1)(insert=1)(replace=or)(replace=exp)))', parser=parser)

    def comparison_callback(filter_, parent, expression):
        if expression.attr == 'append':
            parent.append(EqualityMatch('action', b'append'))
        elif expression.attr == 'insert':
            parent.insert(EqualityMatch('action', b'insert'))
        elif expression.attr == 'remove':
            parent.remove(expression)
        elif expression.attr == 'replace':
            if expression.decode() == 'not':
                new = NOT([expression.copy()])
            elif expression.decode() == 'or':
                new = OR([EqualityMatch('to', b'be'), EqualityMatch('not', b'to be')])
            elif expression.decode() == 'exp':
                new = EqualityMatch('action', b'replace')
            parent.replace(expression, new)

    fil.walk(comparison_callback, None)
    assert str(fil) == '(&(append=1)(|(action=insert)(!(replace=not))(insert=1)(|(to=be)(not=to be))(action=replace))(action=append))'


FILTER_EXPRESSION = """
(&
  (surName=Smith)
  (fqdn=ldap.freeiam.org)
  (a=192.168.0.1)
  (&
    (objectClass=top)
    (objectClass=person)
    (objectClass=inetOrgPerson)
  )
  (|
    (uid=alice)
    (uid=alice)
    (uid=alice)
  )
  (|
    (uid=alice)
    (uid=bob)
    (uid=alice)
  )
  (app=app*)
  (mail=User@Example.com)
  (|
    (ip=127.0.0.1)
    (ip=0000:0000:0000:0000:0000:0000:0000:0001)
  )
  (unlocked=TRUE)
  (birthdate=2025-07-04)
  (disabled=FALSE)
)
""".strip()


def comparison_callback(filter_, parent, expression):
    a = Attribute

    if expression.attr == 'surName':
        # ``(surName=Smith)`` → ``(sn=Smith)``
        expression.attr = 'sn'
    elif expression.attr == 'fqdn':
        # ``(fqdn=ldap.freeiam.org)`` → ``(&(cn=ldap)(associatedDomain=freeiam.org))`
        host, _, domain = expression.decode().partition('.')
        parent.replace(expression, (a('cn') == host) & (a('associatedDomain') == domain))
    elif expression.attr == 'a':
        # ``(a=192.168.0.1)`` → ``(|(aAAARecord=192.168.0.1)(a=192.168.0.1))``
        r_a = expression.copy()
        r_a.attr = 'aRecord'
        r_aaa = expression.copy()
        r_aaa.attr = 'aAAARecord'
        parent.replace(expression, r_a | r_aaa)
    elif expression.attr == 'ip':
        # ``(ip=127.0.0.1)`` → ``(aRecord=127.0.0.1)``
        # ``(ip=0000:0000:0000:0000:0000:0000:0000:0001)`` → ``(aAAARecord=::1)``
        import ipaddress

        ip = ipaddress.ip_address(expression.decode())
        ip4 = 4
        expression.attr = 'aRecord' if ip.version == ip4 else 'aAAARecord'
        expression.value = str(ip).encode()
    elif expression.attr == 'mail':
        # ``(mail=User@Example.com)`` → ``(mail:caseIgnoreMatch:=User@Example.com)``
        parent.replace(expression, a(expression.attr, 'caseIgnoreMatch') == expression.decode())
    elif expression.attr == 'birthdate':
        # ``(birthdate=2025-07-04)`` → ``(dateOfBirth:generalizedTimeMatch:=20250704000000Z)``
        from datetime import datetime

        dt = datetime.strptime(expression.decode(), '%Y-%m-%d')  # noqa: DTZ007
        parent.replace(expression, a('dateOfBirth', 'generalizedTimeMatch') == dt.strftime('%Y%m%d%H%M%SZ'))
    elif expression.attr == 'unlocked':
        # ``(unlocked=TRUE)`` → ``(!(locked=TRUE))``
        expression.attr = 'locked'
        parent.replace(expression, NOT([expression]))
    elif expression.attr == 'app' and isinstance(expression, SubstringMatch):
        # ``(app=app*)`` → (|(app=app01)(app=app02))
        if expression.initial == b'app' and not expression.any and not expression.final:
            parent.replace(expression, (a('app') == 'app01') | [(a('app') == 'app02'), (a('app') == 'app03')])
        return
    elif expression.attr == 'disabled':
        # ``(disabled=TRUE)`` →
        # ``(&(shadowExpire=1)(krb5KDCFlags:1.2.840.113556.1.4.803:=128)(|(sambaAcctFlags=[UD       ])(sambaAcctFlags=[ULD       ])))``
        disabled = (a('shadowExpire') == '1') & [
            (a('krb5KDCFlags', '1.2.840.113556.1.4.803') == '128'),
            ((a('sambaAcctFlags') == '[UD       ]') | (a('sambaAcctFlags') == '[ULD       ]')),
        ]
        enabled = (a('shadowExpire') != '1') & [
            (a('krb5KDCFlags', '1.2.840.113556.1.4.803') != '128'),
            ((a('sambaAcctFlags') != '[UD       ]') & (a('sambaAcctFlags') != '[ULD       ]')),
        ]
        parent.replace(expression, disabled.copy() if expression.decode() in {'1', 'TRUE'} else enabled.copy())
    else:
        return
    if isinstance(expression, EqualityMatch):
        return
    raise NotImplementedError(type(expression))  # or ignore gracefully :-)


def operator_callback(filter_, parent, expression):
    if any(
        expr.attr.lower() == 'objectClass'.lower() and expr.decode().lower() == 'inetOrgPerson'.lower()
        for expr in expression.expressions
        if isinstance(expr, Assertion)
    ):
        # ``(&(objectClass=top)(objectClass=person)(objectClass=inetOrgPerson))`` → ``(objectClass=inetOrgPerson)``
        for expr in expression.comparisons:
            if expr.attr.lower() == 'objectClass'.lower() and expr.decode().lower() in {'top', 'person'}:
                expression.remove(expr)

    for expr in expression.comparisons:
        # ``(|(uid=alice)(uid=alice))`` → ``(|(uid=alice))``
        if expression.expressions.count(expr) > 1:
            expression.remove(expr)

    if (len(expression.comparisons) + len(expression.operators)) == 1 and not isinstance(expression, NOT):
        # ``(|(uid=alice))`` → ``(uid=alice)``
        parent.replace(expression, expression.expressions[0])


def test_example_walk_replace(parser):
    fil = Filter(FILTER_EXPRESSION, parser=parser)
    fil.walk(comparison_callback, operator_callback, WalkStrategy.POST)
    result = r"""
(&
  (sn=Smith)
  (&
    (cn=ldap)
    (associatedDomain=freeiam.org)
  )
  (|
    (aRecord=192.168.0.1)
    (aAAARecord=192.168.0.1)
  )
  (objectClass=inetOrgPerson)
  (uid=alice)
  (|
    (uid=bob)
    (uid=alice)
  )
  (|
    (app=app01)
    (app=app02)
    (app=app03)
  )
  (mail:caseIgnoreMatch:=User@Example.com)
  (|
    (aRecord=127.0.0.1)
    (aAAARecord=::1)
  )
  (!(locked=TRUE))
  (dateOfBirth:generalizedTimeMatch:=20250704000000Z)
  (&
    (!(shadowExpire=1))
    (!(krb5KDCFlags:1.2.840.113556.1.4.803:=128))
    (&
      (!(sambaAcctFlags=[UD       ]))
      (!(sambaAcctFlags=[ULD       ]))
    )
  )
)""".strip()
    assert fil.pretty() == result


def test_binary_value_roundtrip(parser):
    """An assertion containing invalid UTF-8 must survive serialization."""
    fil = Filter(r'(userCertificate=\30\82\01\0a)', parser=parser)
    assert get_filter_root(r'(userCertificate=\30\82\01\0a)', parser).value == b'\x30\x82\x01\x0a'
    assert Filter.from_ber(fil.to_ber()).to_ber() == fil.to_ber()

    original = b'\xff'

    assertion = EqualityMatch('cn', original)
    serialized = f'({assertion})'

    assert serialized == r'(cn=\ff)'

    parsed = get_filter_root(serialized, parser)

    assert isinstance(parsed, EqualityMatch)
    assert parsed.value == original


def test_outer_parentheses_roundtrip(parser):
    assert str(Filter('(cn=John)', parser=parser)) == '(cn=John)'
    assert str(Filter('cn=John', parser=parser)) == 'cn=John'
    assert str(Filter('(&(cn=John)(sn=Doe))', parser=parser)) == '(&(cn=John)(sn=Doe))'


def test_comparison_repr_binary_values():
    """repr displays raw bytes losslessly, but stays readable for ASCII."""
    assert repr(EqualityMatch('cn', b'plain ASCII')) == "EqualityMatch(cn=escape(b'plain ASCII'))"
    assert repr(EqualityMatch('cn', b'\x00\xff\x80')) == "EqualityMatch(cn=escape(b'\\x00\\xff\\x80'))"
    assert repr(EqualityMatch('cn', 'Jörg'.encode())) == r"EqualityMatch(cn=escape(b'J\xc3\xb6rg'))"
    assert repr(EqualityMatch('cn', b"a'b\\c")) == 'EqualityMatch(cn=escape(b"a\'b\\\\c"))'
    assert repr(ExtensibleMatch('cn', b'\xff', 'caseIgnoreMatch', dn=True)) == "ExtensibleMatch(cn:dn:caseIgnoreMatch:=escape(b'\\xff'))"


def test_substring_repr_distinguishes_literal_asterisks():
    expr = SubstringMatch('cn', initial=b'prefix*literal', final=b'suffix')
    assert repr(expr) == r"SubstringMatch(cn=escape(initial=b'prefix*literal', any=(), final=b'suffix'))"
    # assert r'\x2a' in repr(expr)


def test_all_byte_values_roundtrip(parser):
    """Every possible byte value must survive an RFC 4515 roundtrip."""
    original = bytes(range(256))

    assertion = EqualityMatch('cn', original)
    serialized = f'({assertion})'

    parsed = get_filter_root(serialized, parser)

    assert isinstance(parsed, EqualityMatch)
    assert parsed.value == original


@pytest.mark.parametrize(
    'value',
    [
        b'',
        b'John',
        b'foo*bar',
        b'foo(bar)',
        b'foo\\bar',
        b'\x00',
        b'\xff',
        b'\xc3\xb6',
        b'\x80\xff\x00',
        bytes(range(256)),
    ],
)
def test_equality_match_roundtrip(value, parser):
    assertion = EqualityMatch('cn', value)

    parsed = get_filter_root(f'({assertion})', parser)

    assert isinstance(parsed, EqualityMatch)
    assert parsed.value == value


@pytest.mark.parametrize(
    'initial,any_values,final',
    [
        (b'foo', (), None),
        (None, (), b'bar'),
        (b'foo', (), b'bar'),
        (b'foo', (b'middle',), b'bar'),
        (b'\xff', (b'\x00',), b'\x80'),
        (b'foo*bar', (), b'baz'),
        (b'foo\\bar', (b'(test)',), b'end'),
    ],
)
def test_substring_match_roundtrip(
    initial: bytes | None,
    any_values: tuple[bytes, ...],
    final: bytes | None,
    parser,
):
    assertion = SubstringMatch(
        'cn',
        initial=initial,
        any=any_values,
        final=final,
    )

    parsed = get_filter_root(f'({assertion})', parser)

    assert isinstance(parsed, SubstringMatch)
    assert parsed.initial == initial
    assert parsed.any == any_values
    assert parsed.final == final


def test_substring_mutation_invalidates_escaped_cache(parser):
    """Changing a substring component must invalidate the original syntax."""
    assertion = get_filter_root('(cn=foo*bar)', parser)

    assert isinstance(assertion, SubstringMatch)
    assert assertion.initial == b'foo'
    assert assertion.final == b'bar'

    assertion.final = b'baz'

    assert str(assertion) == 'cn=foo*baz'

    parsed = get_filter_root(f'({assertion})', parser)

    assert isinstance(parsed, SubstringMatch)
    assert parsed.initial == b'foo'
    assert parsed.final == b'baz'


def test_substring_any_cannot_be_mutated_externally():
    """A substring assertion must not retain a mutable sequence reference."""
    parts = [b'foo']

    assertion = SubstringMatch(
        'cn',
        initial=b'start',
        any=parts,
        final=b'end',
    )

    parts.append(b'bar')

    assert assertion.any == (b'foo',)
    assert str(assertion) == 'cn=start*foo*end'


def test_attribute_description_equality_is_case_insensitive():
    """LDAP attribute descriptions must compare case-insensitively."""
    lower = EqualityMatch('cn', b'John')
    upper = EqualityMatch('CN', b'John')

    assert lower == upper

    lower_substring = SubstringMatch(
        'cn',
        initial=b'John',
    )
    upper_substring = SubstringMatch(
        'CN',
        initial=b'John',
    )

    assert lower_substring == upper_substring


def test_extensible_match_without_attribute(parser):
    """An extensible match can specify a matching rule without an attribute."""
    assertion = get_filter_root('(:caseIgnoreMatch:=John)', parser)

    assert isinstance(assertion, ExtensibleMatch)
    assert assertion.attr == ''  # noqa: PLC1901
    assert assertion.dn is False
    assert assertion.matchingrule == 'caseIgnoreMatch'
    assert assertion.value == b'John'

    assert str(assertion) == ':caseIgnoreMatch:=John'


def test_escaped_asterisk_is_not_a_wildcard(parser):
    """An escaped asterisk must be treated as literal assertion data."""
    assertion = get_filter_root(r'(cn=foo\2abar)', parser)

    assert isinstance(assertion, EqualityMatch)
    assert not isinstance(assertion, SubstringMatch)
    assert assertion.value == b'foo*bar'

    assert str(assertion) == r'cn=foo\2abar'


def test_decode_invalid_utf8_raises():
    """Explicit UTF-8 decoding must reject invalid byte sequences."""
    assertion = EqualityMatch('cn', b'\xff')

    with pytest.raises(UnicodeDecodeError):
        assertion.decode('utf-8')

    assert assertion.value == b'\xff'


def test_original_escaped_representation_is_preserved(parser):
    """An unmodified parsed assertion must retain its original escaping."""
    original = r'(cn=J\6fhn)'

    assertion = get_filter_root(original, parser)

    assert isinstance(assertion, EqualityMatch)
    assert assertion.value == b'John'

    if parser == 'libldap':
        pytest.skip('not supported')

    # preserve the original hexadecimal escape instead of normalizing it.
    assert str(assertion) == r'cn=J\6fhn'

    # mutating the value must invalidate the original escaped representation.
    assertion.value = b'Jane'

    assert str(assertion) == 'cn=Jane'


@pytest.mark.parametrize(
    'value,mode,expected',
    [
        (b'foo', EscapeMode.SPECIAL, 'foo'),
        (b'foo', EscapeMode.RESTRICTED, 'foo'),
        (b'foo', EscapeMode.ALL, r'\66\6f\6f'),
        (b'a*b', EscapeMode.SPECIAL, r'a\2ab'),
        (b'a*b', EscapeMode.RESTRICTED, r'a\2ab'),
        (b'a*b', EscapeMode.ALL, r'\61\2a\62'),
        (b'foo bar', EscapeMode.SPECIAL, 'foo bar'),
        (b'foo bar', EscapeMode.RESTRICTED, r'foo\20bar'),
        (b'\x00', EscapeMode.SPECIAL, r'\00'),
        (b'\\', EscapeMode.SPECIAL, r'\5c'),
        (b'\xff', EscapeMode.SPECIAL, r'\ff'),
        (b'\xff', EscapeMode.RESTRICTED, r'\ff'),
        (b'\xff', EscapeMode.ALL, r'\ff'),
        (b'\xc3\xb6', EscapeMode.SPECIAL, r'\c3\b6'),
        (b'\xc3\xb6', EscapeMode.RESTRICTED, r'\c3\b6'),
    ],
)
def test_escape_bytes(value, mode, expected):
    assert Filter.escape_bytes(value, mode) == expected
    assert Filter.unescape(expected.encode('ascii')) == value


@pytest.mark.parametrize('mode', list(EscapeMode))
def test_escape_bytes_all_octets(mode):
    original = bytes(range(256))

    escaped = Filter.escape_bytes(original, mode)

    assert Filter.unescape(escaped.encode('ascii')) == original
    with pytest.raises(ValueError, match='Invalid escape mode'):
        escaped = Filter.escape_bytes(original, 4)


def test_substring_initial_setter(parser):
    match = SubstringMatch.from_escaped('cn', b'foo*bar', initial=b'foo', final=b'bar')

    if parser == 'lark':
        assert match._raw_escaped_value == b'foo*bar'

    match.initial = b'baz'

    assert match.initial == b'baz'
    assert match._raw_escaped_value is None
    assert str(match) == 'cn=baz*bar'

    match.initial = None

    assert match.initial is None
    assert str(match) == 'cn=*bar'


def test_substring_any_setter(parser):
    match = SubstringMatch.from_escaped('cn', b'foo*bar*baz', initial=b'foo', any=(b'bar',), final=b'baz')

    if parser == 'lark':
        assert match._raw_escaped_value == b'foo*bar*baz'

    values = [b'one', b'two']
    match.any = values

    assert match.any == (b'one', b'two')
    assert isinstance(match.any, tuple)
    assert match._raw_escaped_value is None
    assert str(match) == 'cn=foo*one*two*baz'

    values.append(b'three')

    assert match.any == (b'one', b'two')


def test_substring_requires_component():
    with pytest.raises(ValueError, match='SubstringMatch requires at least one component'):
        SubstringMatch('cn')


@pytest.mark.parametrize(
    'encoding,errors,expected',
    [
        ('utf-8', 'strict', ('Jörg', 'Müller', 'Ende')),
        ('utf-8', 'replace', ('Jörg', 'Müller', 'Ende')),
        ('latin-1', 'strict', ('JÃ¶rg', 'MÃ¼ller', 'Ende')),
    ],
)
def test_substring_decode(encoding, errors, expected):
    match = SubstringMatch('cn', initial='Jörg'.encode(), any=('Müller'.encode(),), final=b'Ende')

    assert match.decode(encoding, errors) == expected


def test_substring_decode_invalid_utf8():
    match = SubstringMatch('cn', initial=b'\xff', final=b'end')

    with pytest.raises(UnicodeDecodeError):
        match.decode()

    assert match.decode(errors='replace') == ('\ufffd', 'end')


def test_substring_equality_other_type():
    match = SubstringMatch('cn', initial=b'foo')

    assert match.__eq__(EqualityMatch('cn', b'foo')) is NotImplemented  # noqa: PLC2801
    assert match.__eq__(object()) is NotImplemented  # noqa: PLC2801
    assert match != EqualityMatch('cn', b'foo')


def test_substring_hash():
    first = SubstringMatch('cn', initial=b'foo', any=(b'bar',), final=b'baz')
    equal = SubstringMatch('CN', initial=b'foo', any=(b'bar',), final=b'baz')
    different = SubstringMatch('cn', initial=b'foo', any=(b'other',), final=b'baz')

    assert first == equal
    assert hash(first) == hash(equal)
    assert isinstance(hash(first), int)
    assert first != different

    # verify the hash includes the expected components.
    assert hash(first) == hash((SubstringMatch, 'cn', b'foo', (b'bar',), b'baz'))


@pytest.mark.parametrize(
    'attr,matchingrule',
    [
        ('', None),
        ('', ''),
    ],
)
def test_extensible_match_requires_attribute_or_matchingrule(attr, matchingrule):
    with pytest.raises(ValueError, match='ExtensibleMatch requires a matching rule or an attribute'):
        ExtensibleMatch(attr, b'John', matchingrule)


def test_get_substring_requires_two_parts():
    with pytest.raises(ValueError, match='Substring filter requires at least two parts'):
        Filter.get_substring('cn', 'foo')

    with pytest.raises(ValueError, match='Substring filter requires at least two parts'):
        Filter.get_substring('cn')


@pytest.mark.parametrize(
    'expression,expected',
    [
        (r'(attr=\*)', b'*'),
        (r'(attr=\()', b'('),
        (r'(attr=\))', b')'),
        (r'(attr=\\)', b'\\'),
        (r'(attr=\2a)', b'*'),
        (r'(attr=foo\*bar)', b'foo*bar'),
        (r'(attr=foo\\bar)', b'foo\\bar'),
        (r'(attr=\\20)', b'\\20'),
    ],
)
def test_libldap_compatible_escapes(expression, expected):
    fil = Filter(expression, parser='lark')
    assertion = fil.root.expressions[0]

    assert isinstance(assertion, EqualityMatch)
    assert assertion.value == expected
    assert str(fil) == expression


@pytest.mark.parametrize(
    'raw,expected',
    [
        (r'\20', b' '),
        (r'\\20', b'\\ '),
        (r'\\28', b'\\('),
        (r'\\29', b'\\)'),
        (r'\\2a', b'\\*'),
        (r'\\5c', b'\\\\'),
        (r'\*', b'*'),
        (r'\(', b'('),
        (r'\)', b')'),
        (r'\\', b'\\'),
    ],
)
def test_libldap_escape_compatibility(raw, expected):
    expression = f'(cn={raw})'

    assert Filter(expression, parser='lark').to_ber() == Filter(expression, parser='libldap').to_ber()


@pytest.mark.parametrize(
    'expression,expected_type',
    [
        (r'(cn=\*)', EqualityMatch),
        (r'(cn=\2a)', EqualityMatch),
        (r'(cn=foo\*bar)', EqualityMatch),
        (r'(cn=foo\\*bar)', SubstringMatch),
        (r'(cn=foo\2abar)', EqualityMatch),
        (r'(cn=foo\*bar*)', SubstringMatch),
        (r'(cn=foo\2a*bar)', SubstringMatch),
        ('(cn=*)', PresenceMatch),
    ],
)
def test_escaped_asterisk(expression, expected_type, parser):
    assert isinstance(get_filter_root(expression, parser), expected_type)


@pytest.mark.parametrize(
    'expr,expected_type,expected',
    [
        # EqualityMatch
        (r'(cn=foo\2abar)', EqualityMatch, b'foo*bar'),
        (r'(cn=foo\*bar)', EqualityMatch, b'foo*bar'),
        (r'(cn=foo\\bar)', EqualityMatch, b'foo\\bar'),
        (r'(cn=foo\\20)', EqualityMatch, rb'foo\20'),
        # SubstringMatch: each component must be unescaped separately
        (r'(cn=foo\2a*bar)', SubstringMatch, (b'foo*', b'bar')),
        (r'(cn=foo\*bar*)', SubstringMatch, (b'foo*bar', None)),
        (r'(cn=foo\\*bar)', SubstringMatch, (b'foo\\', b'bar')),
        (r'(cn=*foo\28bar\29*)', SubstringMatch, (None, b'foo(bar)', None)),
        (r'(cn=foo\20*bar\5cbaz)', SubstringMatch, (b'foo ', b'bar\\baz')),
        (r'(cn=foo\\20*bar)', SubstringMatch, (rb'foo\20', b'bar')),
        # ExtensibleMatch: escaped asterisks are always literal values
        (r'(cn:=foo\2abar)', ExtensibleMatch, b'foo*bar'),
        (r'(cn:=foo\*bar)', ExtensibleMatch, b'foo*bar'),
        (r'(cn:=foo\\bar)', ExtensibleMatch, b'foo\\bar'),
        (r'(cn:=foo\\20)', ExtensibleMatch, rb'foo\20'),
        (r'(cn:dn:2.5.13.2:=foo\28bar\29)', ExtensibleMatch, b'foo(bar)'),
        (r'(cn:dn:2.5.13.2:=foo\00bar)', ExtensibleMatch, b'foo\x00bar'),
    ],
)
def test_unescape_match_values(expr, expected_type, expected, parser):
    fil = get_filter_root(expr, parser)

    assert isinstance(fil, expected_type)

    if isinstance(fil, SubstringMatch):
        assert fil.decode() == tuple([x.decode() if x else x for x in expected])
    else:
        assert fil.value == expected

    assert Filter(expr, parser=parser).to_ber() == (Filter(expr, parser='libldap').to_ber())


@pytest.mark.parametrize(
    'expr,expected',
    [
        ('(cn:2.5.13.2:=foo\\2abar)', b'foo*bar'),
    ],
)
def test_extensible_match_asterisk(expr, expected, parser):
    fil = get_filter_root(expr, parser)

    assert isinstance(fil, ExtensibleMatch)
    assert fil.value == expected
