import ldap
import pytest

from freeiam.errors import FilterError
from freeiam.ldap.filter import (
    AND,
    NOT,
    OR,
    ApproximateMatch,
    Attribute,
    Comparision,
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
    '(&(key=va\\\\28!\\\\29ue))',
    r'(1.3.6.1.4.1.1466.0=\04\02\48\69)',
    # rest
    '(0=foo)',
    '(1=foo)',
    '(11=foo)',
    '(x-z=foo)',
    '(cn;extra=foo)',
    # everything
    complex_filter_expr,
]
STRICT_INVALID_FILTERS = [
    '(age>= 18)',
    '(cn= John)',
    '( cn=John )',
    '(&( cn=John))',
    '(cn=  Two  Whitespaces  )',
    '(cn=* )',
    '(cn= *)',
    '(cn=  Two  White*spaces  )',
    '(cn:dn:caseIgnoreMatch:= John)',
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
    '(!(a=b) extra )'
    # text
    'hello'
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
    pytest.param('(!\n  (|(cn=a))\n)', marks=pytest.mark.xfail(reason='libldap denies, we allow')),
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
]


@pytest.mark.parametrize('expr', VALID_FILTERS)
def test_valid_filter(expr):
    try:
        Filter(expr, strict=expr not in STRICT_INVALID_FILTERS)
    except FilterError:
        Filter(expr, _debug=True)

    Filter(Filter(expr).pretty())


@pytest.mark.parametrize(
    'expr,output',
    [(x, x) for x in VALID_FILTERS if x != '(cn= *)']
    + [
        pytest.param('(cn= *)', '(cn= *)', marks=pytest.mark.xfail(reason='Presense or substring match?')),
    ],
)
def test_filter_parse_compose(expr, output):
    try:
        fil = Filter(expr)
    except FilterError:
        pytest.skip('filter invalid - fix first')
    output = expr if output is None else output
    assert str(fil) == output


@pytest.mark.parametrize('expr', VALID_FILTERS)
def test_libldap_valid_filter(expr):
    try:
        _validate_filter(expr)
    except FilterError:
        pytest.fail(expr)


@pytest.mark.parametrize('expr', INVALID_FILTERS)
def test_invalid_filter(expr):
    with pytest.raises(FilterError):
        Filter(expr)


@pytest.mark.parametrize('expr', INVALID_FILTERS)
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


def get_filter_root(filter_expr):
    for expr in Filter(filter_expr, _debug=True).root.expressions:
        if isinstance(expr, (AND, OR, NOT, Comparision)):
            return expr
    return None


@pytest.mark.parametrize(
    'expr',
    [
        '( cn=John )',
        '(&( cn=John))',
        pytest.param('(& (cn=John))', marks=pytest.mark.xfail(reason='SEP is always unset')),
    ],
)
def test_strict_parsing(expr):
    with pytest.raises(FilterError):
        Filter(expr, strict=True)


def test_equality_match():
    fil = get_filter_root('(cn=foo)')
    assert isinstance(fil, EqualityMatch)


def test_approximate_match():
    fil = get_filter_root('(cn~=foo)')
    assert isinstance(fil, ApproximateMatch)


@pytest.mark.parametrize(
    'expr, expected',
    [
        ('(cn:caseIgnoreMatch:=john)', (ExtensibleMatch, 'cn', '', 'caseIgnoreMatch', 'john')),
        ('(cn:dn:=John Doe)', (ExtensibleMatch, 'cn', 'dn', '', 'John Doe')),
        ('(cn:dn:caseIgnoreMatch:=John Doe)', (ExtensibleMatch, 'cn', 'dn', 'caseIgnoreMatch', 'John Doe')),
        ('(:dn:caseIgnoreMatch:=John Doe)', (ExtensibleMatch, '', 'dn', 'caseIgnoreMatch', 'John Doe')),
        ('(sn:2.5.13.3:=DOE)', (ExtensibleMatch, 'sn', '', '2.5.13.3', 'DOE')),
    ],
)
def test_extensible_match(expr, expected):
    fil = get_filter_root(expr)
    assert (type(fil), fil.attr, fil.dn, fil.matchingrule, fil.value) == expected


def test_ge_match():
    fil = get_filter_root('(cn>=1)')
    assert isinstance(fil, GreaterOrEqual)


def test_le_match():
    fil = get_filter_root('(cn<=1)')
    assert isinstance(fil, LessOrEqual)


def test_presence_match():
    fil = get_filter_root('(cn=*)')
    assert isinstance(fil, PresenceMatch)


def test_substring_match():
    fil = get_filter_root('(cn=*foo*)')
    assert isinstance(fil, SubstringMatch)
    assert fil.values == ('', 'foo', '')


@pytest.mark.parametrize(
    'expr,attrs',
    [
        ('(cn= John)', {'attr': 'cn', 'value': 'John'}),
        ('( cn=John )', {'attr': 'cn', 'value': 'John'}),
        ('(cn=John )', {'attr': 'cn', 'value': 'John'}),
        ('(cn= John )', {'attr': 'cn', 'value': 'John'}),
        ('(& (cn=John))', {'attr': 'cn', 'value': 'John'}),
        ('(&(cn=John) )', {'attr': 'cn', 'value': 'John'}),
        ('(&   (cn=John))', {'attr': 'cn', 'value': 'John'}),
        ('(&( cn=John))', {'attr': 'cn', 'value': 'John'}),
        ('(& (  cn=John  ) )', {'attr': 'cn', 'value': 'John'}),
        ('(&  ( cn=John )  )', {'attr': 'cn', 'value': 'John'}),
        ('(&  ( cn= John )  )', {'attr': 'cn', 'value': 'John'}),
        ('(cn=Two  Whitespaces)', {'attr': 'cn', 'value': 'Two  Whitespaces'}),
        ('(cn=* )', {'attr': 'cn', 'value': '', '__class__': PresenceMatch}),
        ('(cn= *)', {'attr': 'cn', 'value': '', '__class__': PresenceMatch}),
        ('(cn=Two  White*spaces)', {'attr': 'cn', 'value': 'Two  White*spaces', '__class__': SubstringMatch}),
        ('(cn=  Two  White*spaces  )', {'attr': 'cn', 'value': 'Two  White*spaces', '__class__': SubstringMatch}),
    ],
)
def test_whitespace_preserve(expr, attrs):
    fil = get_filter_root(expr)
    fil_attr = {key: getattr(fil, key) for key in attrs}
    assert fil_attr == attrs


def test_extensible_match_whitespace_combinations():
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
            Filter(c)
        except FilterError:
            if validate_filter(c):
                errors.append(c)
    assert not errors


@pytest.mark.parametrize(
    'expr,value,unescape',
    [
        (
            r'(description=contains\28parentheses,spaces\20\29\5cand\2astars\2a)',
            r'contains\28parentheses,spaces\20\29\5cand\2astars\2a',
            r'contains(parentheses,spaces )\and*stars*',
        ),
        (r'(cn:dn:2.4.6.8.10:=John\20Doe)', r'John\20Doe', r'John Doe'),
        (r'(filename=C:\5cMyFile)', r'C:\5cMyFile', r'C:\MyFile'),
        (r'(bin=\00\00\00\04)', r'\00\00\00\04', '\00\00\00\04'),
        (r'(sn=Lu\c4\8di\c4\87)', r'Lu\c4\8di\c4\87', b'Lu\xef\xbf\xbd\xef\xbf\xbdi\xef\xbf\xbd\xef\xbf\xbd'.decode('utf-8')),
        (r'(cn=*\2A*)', r'*\2A*', r'***'),
        (r'(cn=John\20Doe)', r'John\20Doe', r'John Doe'),
        (r'(cn=\00)', r'\00', '\x00'),
        (r'(description=with\5cbackslash)', r'with\5cbackslash', r'with\backslash'),
        (r'(cn=\2a)', r'\2a', r'*'),
        (r'(cn=with\28paren\29)', r'with\28paren\29', r'with(paren)'),
        ('(cn=abc\\20)', 'abc\\20', r'abc '),
        (r'(cn=abc\\20)', r'abc\\20', 'abc\\ '),
        ('(&(key=va\\\\28!\\\\29ue))', 'va\\\\28!\\\\29ue', r'va\(!\)ue'),
        (r'(1.3.6.1.4.1.1466.0=\04\02\48\69)', r'\04\02\48\69', '\x04\x02Hi'),
    ],
)
def test_unescape(expr, value, unescape):
    fil = get_filter_root(expr)
    assert fil.raw_value == value
    assert fil.value == unescape


def test_comparision_unescape():
    assert EqualityMatch('cn', r'foo\20bar', is_escaped=True).value == 'foo bar'
    assert EqualityMatch('cn', r' foobar ', is_escaped=False).escaped == r'\20foobar\20'
    assert EqualityMatch('cn', r' foobar ', is_escaped=False).value == ' foobar '


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

    assert str(cn == '') == 'cn=*'  # noqa: PLC1901
    assert repr(cn == '') == "PresenceMatch(cn=*escape(''))"  # noqa: PLC1901

    assert str(cn == user_input) == r'cn=foo \28bar\29\2a'
    assert repr(cn == user_input) == "EqualityMatch(cn=escape('foo (bar)*'))"

    assert str(cn != user_input) == r'(!(cn=foo \28bar\29\2a))'
    assert repr(cn != user_input) == "NOT( EqualityMatch(cn=escape('foo (bar)*')) )"

    assert str(cn == ['', user_input, '']) == r'cn=foo \28bar\29\2a'
    assert repr(cn == ['', user_input, '']) == "SubstringMatch(cn=escape('foo (bar)*'))"

    assert str(cn == user_input.split('*')) == r'cn=foo \28bar\29'
    assert repr(cn == user_input.split('*')) == "SubstringMatch(cn=escape('foo (bar)'))"

    assert str(cn > '1000') == '(!(cn<=1000))'
    assert repr(cn > '1000') == "NOT( LessOrEqual(cn<=escape('1000')) )"

    assert str(cn >= '1000') == 'cn>=1000'
    assert repr(cn >= '1000') == "GreaterOrEqual(cn>=escape('1000'))"

    assert str(cn < '1000') == '(!(cn>=1000))'
    assert repr(cn < '1000') == "NOT( GreaterOrEqual(cn>=escape('1000')) )"

    assert str(cn <= '1000') == 'cn<=1000'
    assert repr(cn <= '1000') == "LessOrEqual(cn<=escape('1000'))"

    assert str(cn > 1000) == 'cn>=1001'
    assert repr(cn > 1000) == "GreaterOrEqual(cn>=escape('1001'))"

    assert str(cn >= 1000) == 'cn>=1000'
    assert repr(cn >= 1000) == "GreaterOrEqual(cn>=escape('1000'))"

    assert str(cn < 1000) == 'cn<=999'
    assert repr(cn < 1000) == "LessOrEqual(cn<=escape('999'))"

    assert str(cn <= 1000) == 'cn<=1000'
    assert repr(cn <= 1000) == "LessOrEqual(cn<=escape('1000'))"

    assert str(cn.approx == user_input) == r'cn~=foo \28bar\29\2a'
    assert repr(cn.approx == user_input) == "ApproximateMatch(cn~=escape('foo (bar)*'))"

    assert str(cn.extensible(None, 'generalizedTimeMatch') == user_input) == r'cn:generalizedTimeMatch:=foo \28bar\29\2a'
    assert repr(cn.extensible(None, 'generalizedTimeMatch') == user_input) == "ExtensibleMatch(cn:generalizedTimeMatch:=escape('foo (bar)*'))"

    assert str((cn == 'foo') | (cn == 'bar')) == '(|(cn=foo)(cn=bar))'
    assert repr((cn == 'foo') | (cn == 'bar')) == "OR( EqualityMatch(cn=escape('foo')) | EqualityMatch(cn=escape('bar')) )"

    assert str((cn != 'foo') & (cn != 'bar')) == '(&(!(cn=foo))(!(cn=bar)))'
    assert repr((cn != 'foo') & (cn != 'bar')) == "AND( NOT( EqualityMatch(cn=escape('foo')) ) & NOT( EqualityMatch(cn=escape('bar')) ) )"

    assert str(((cn == 'foo') | (cn == 'bar')).negate()) == '(!( |(cn=foo)(cn=bar) ))'.replace(' ', '')
    assert repr(((cn == 'foo') | (cn == 'bar')).negate()) == "NOT( OR( EqualityMatch(cn=escape('foo')) | EqualityMatch(cn=escape('bar')) ) )"


def test_escape_classic():
    user_input = 'foo (bar)*'
    ipv4 = '127.0.0.1'
    ipv6 = '::1'

    assert repr(Filter.get_pres('cn')) == "PresenceMatch(cn=*escape(''))"
    assert repr(Filter.get_eq('cn', user_input)) == "EqualityMatch(cn=escape('foo (bar)*'))"
    assert repr(Filter.get_approx('cn', user_input)) == "ApproximateMatch(cn~=escape('foo (bar)*'))"
    assert repr(Filter.get_substring('cn', *user_input.split('*'))) == "SubstringMatch(cn=escape('foo (bar)'))"
    assert repr(Filter.get_substring('cn', '', 'foo', '')) == "SubstringMatch(cn=escape('foo'))"
    assert repr(Filter.get_gt_eq('uidNumber', 1000)) == "GreaterOrEqual(uidNumber>=escape('1000'))"
    assert (
        repr(Filter.get_extensible('cn', None, 'generalizedTimeMatch', user_input))
        == "ExtensibleMatch(cn:generalizedTimeMatch:=escape('foo (bar)*'))"
    )
    assert (
        repr(Filter.get_and(Filter.get_eq('objectClass', 'person'), Filter.get_eq('cn', user_input)))
        == "AND( EqualityMatch(objectClass=escape('person')) & EqualityMatch(cn=escape('foo (bar)*')) )"
    )
    assert (
        repr(Filter.get_or(Filter.get_eq('aRecord', ipv4), Filter.get_eq('aAAARecord', ipv6)))
        == "OR( EqualityMatch(aRecord=escape('127.0.0.1')) | EqualityMatch(aAAARecord=escape('::1')) )"
    )
    assert repr(Filter.get_not(Filter.get_eq('cn', user_input))) == "NOT( EqualityMatch(cn=escape('foo (bar)*')) )"


def test_hash():
    assert hash(Attribute('a')) == hash(Attribute('a'))
    assert hash(Attribute('a') == '1') == hash(Attribute('a') == '1')


def test_attribute_error_handling():
    with pytest.raises(ValueError, match=r'a\*'):
        Attribute('a*')
    with pytest.raises(ValueError, match=r'a'):
        Attribute('a', 'a')
    with pytest.raises(ValueError, match=r'a\*'):
        Attribute('a', 'dn', 'a*')

    with pytest.raises(ValueError, match=r'1\.a'):
        Attribute('1.a')
    with pytest.raises(ValueError, match=r'1\.a'):
        Attribute('a', 'dn', '1.a')


def test_root():
    assert isinstance(Filter('(&(a=b))').root, AND)
    assert isinstance(Filter('(|(a=b))').root, OR)
    assert isinstance(Filter('(!(a=b))').root, NOT)
    assert isinstance(Filter('(a=b)').root, Group)
    assert isinstance(Filter('a=b').root, Container)


def test_copy():
    pass


def test_pretty():
    pass


def test_timespan_filter():
    assert str(Filter.time_span_filter(0, 1)) == '(&(modifyTimestamp>=19700101000000Z)(!(modifyTimestamp>=19700101000001Z)))'


def test_repr():
    expected = "Filter(AND( GreaterOrEqual(modifyTimestamp>='19700101000000Z') & NOT( GreaterOrEqual(modifyTimestamp>='19700101000001Z') ) ))"
    assert repr(Filter.time_span_filter(0, 1)) == expected


def test_walk_func():
    import io

    filter_s = '(|(&(!(zone=freeiam.org))(cn=foo))(uid=bar))'
    filter_p = Filter(filter_s)

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


def test_walk_replace():
    fil = Filter('(&(append=1)(|(replace=not)(remove=1)(insert=1)(replace=or)(replace=exp)))')

    def comparision_callback(filter_, parent, expression):
        if expression.attr == 'append':
            parent.append(EqualityMatch('action', 'append'))
        elif expression.attr == 'insert':
            parent.insert(EqualityMatch('action', 'insert'))
        elif expression.attr == 'remove':
            parent.remove(expression)
        elif expression.attr == 'replace':
            if expression.value == 'not':
                new = NOT([expression.copy()])
            elif expression.value == 'or':
                new = OR([EqualityMatch('to', 'be'), EqualityMatch('not', 'to be')])
            elif expression.value == 'exp':
                new = EqualityMatch('action', 'replace')
            parent.replace(expression, new)

    fil.walk(comparision_callback, None)
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


def comparision_callback(filter_, parent, expression):
    a = Attribute

    if expression.attr == 'surName':
        # ``(surName=Smith)`` → ``(sn=Smith)``
        expression.attr = 'sn'
    elif expression.attr == 'fqdn':
        # ``(fqdn=ldap.freeiam.org)`` → ``(&(cn=ldap)(associatedDomain=freeiam.org))`
        host, _, domain = expression.value.partition('.')
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

        ip = ipaddress.ip_address(expression.value)
        ip4 = 4
        expression.attr = 'aRecord' if ip.version == ip4 else 'aAAARecord'
        expression.value = str(ip)
    elif expression.attr == 'mail':
        # ``(mail=User@Example.com)`` → ``(mail:caseIgnoreMatch:=User@Example.com)``
        parent.replace(expression, a(expression.attr, '', 'caseIgnoreMatch') == expression.value)
    elif expression.attr == 'birthdate':
        # ``(birthdate=2025-07-04)`` → ``(dateOfBirth:generalizedTimeMatch:=20250704000000Z)``
        from datetime import datetime

        dt = datetime.strptime(expression.value, '%Y-%m-%d')  # noqa: DTZ007
        parent.replace(expression, a('dateOfBirth', '', 'generalizedTimeMatch') == dt.strftime('%Y%m%d%H%M%SZ'))
    elif expression.attr == 'unlocked':
        # ``(unlocked=TRUE)`` → ``(!(locked=TRUE))``
        expression.attr = 'locked'
        parent.replace(expression, NOT([expression]))
    elif expression.attr == 'app' and isinstance(expression, SubstringMatch):
        # ``(app=app*)`` → (|(app=app01)(app=app02))
        if expression.value == 'app*':
            parent.replace(expression, (a('app') == 'app01') | [(a('app') == 'app02'), (a('app') == 'app03')])
        return
    elif expression.attr == 'disabled':
        # ``(disabled=TRUE)`` →
        # ``(&(shadowExpire=1)(krb5KDCFlags:1.2.840.113556.1.4.803:=128)(|(sambaAcctFlags=[UD       ])(sambaAcctFlags=[ULD       ])))``
        disabled = (a('shadowExpire') == '1') & [
            (a('krb5KDCFlags', '', '1.2.840.113556.1.4.803') == '128'),
            ((a('sambaAcctFlags') == '[UD       ]') | (a('sambaAcctFlags') == '[ULD       ]')),
        ]
        enabled = (a('shadowExpire') != '1') & [
            (a('krb5KDCFlags', '', '1.2.840.113556.1.4.803') != '128'),
            ((a('sambaAcctFlags') != '[UD       ]') & (a('sambaAcctFlags') != '[ULD       ]')),
        ]
        parent.replace(expression, disabled.copy() if expression.value in {'1', 'TRUE'} else enabled.copy())
    else:
        return
    if isinstance(expression, EqualityMatch):
        return
    raise NotImplementedError(type(expression))  # or ignore gracefully :-)


def operator_callback(filter_, parent, expression):
    if any(
        expr.attr.lower() == 'objectClass'.lower() and expr.value.lower() == 'inetOrgPerson'.lower()
        for expr in expression.expressions
        if isinstance(expr, Comparision)
    ):
        # ``(&(objectClass=top)(objectClass=person)(objectClass=inetOrgPerson))`` → ``(objectClass=inetOrgPerson)``
        for expr in expression.comparisions:
            if expr.attr.lower() == 'objectClass'.lower() and expr.value.lower() in {'top', 'person'}:
                expression.remove(expr)

    for expr in expression.comparisions:
        # ``(|(uid=alice)(uid=alice))`` → ``(|(uid=alice))``
        if expression.expressions.count(expr) > 1:
            expression.remove(expr)

    if (len(expression.comparisions) + len(expression.operators)) == 1 and not isinstance(expression, NOT):
        # ``(|(uid=alice))`` → ``(uid=alice)``
        parent.replace(expression, expression.expressions[0])


def test_example_walk_replace():
    fil = Filter(FILTER_EXPRESSION)
    fil.walk(comparision_callback, operator_callback, WalkStrategy.POST)
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
