# start FILTER ESCAPING
from freeiam.ldap.filter import EscapeMode, Filter


user_input = ' hello (my friend), i am attacking * with \x00 or \\XX'

print(Filter.escape(user_input, EscapeMode.SPECIAL))
print(Filter.escape(user_input, EscapeMode.RESTRICTED))
print(Filter.escape(user_input, EscapeMode.ALL))


# automatic escaping
def print_expr(expression):
    print(expression, ' #', repr(expression))


user_input = 'foo (bar)*'  # example user input, using chars which require escaping
cn = Filter.attr('cn')
print_expr(cn == '')  # noqa: PLC1901
print_expr(cn == user_input)
print_expr(cn != user_input)
print_expr(cn == ['', user_input, ''])  # prefix and suffix with *
print_expr(cn == user_input.split('*'))  # allow '*' filtering in user input
print_expr(cn > '1000')
print_expr(cn >= '1000')
print_expr(cn < '1000')
print_expr(cn <= '1000')
print_expr(cn > 1000)  # using real integers
print_expr(cn >= 1000)
print_expr(cn < 1000)
print_expr(cn <= 1000)
print_expr(cn.approx == user_input)
print_expr(cn.extensible(None, 'generalizedTimeMatch') == user_input)
print_expr((cn == 'foo') | (cn == 'bar'))
print_expr((cn == 'foo') | 'cn=bar')
print_expr((cn != 'foo') & (cn != 'bar'))
print_expr(((cn == 'foo') | (cn == 'bar')).negate())

# classic way
Filter.get_pres('cn')
Filter.get_eq('cn', user_input)
Filter.get_approx('cn', user_input)
Filter.get_substring('cn', *user_input.split('*'))
Filter.get_substring('cn', '', 'foo', '')
Filter.get_gt_eq('uidNumber', 1000)
Filter.get_gt_eq('uidNumber', 1000)
Filter.get_extensible('cn', None, 'generalizedTimeMatch', user_input)

Filter.get_and(Filter.get_eq('objectClass', 'person'), Filter.get_eq('cn', user_input))
ipv4 = '127.0.0.1'
ipv6 = '::1'
Filter.get_or(Filter.get_eq('aRecord', ipv4), Filter.get_eq('aAAARecord', ipv6))
Filter.get_not(Filter.get_eq('cn', user_input))

# end FILTER ESCAPING
# start FILTER TRANSFORMATIONS
from freeiam.ldap.filter import (
    NOT,
    Attribute,
    Comparison,
    EqualityMatch,
    Filter,
    SubstringMatch,
    WalkStrategy,
)


def comparison_callback(filter_, parent, expression):
    a = Attribute

    if expression.attr == 'surName':
        # ``(surName=Smith)`` → ``(sn=Smith)``
        expression.attr = 'sn'
    elif expression.attr == 'fqdn':
        # ``(fqdn=ldap.freeiam.org)`` → ``(&(cn=ldap)(associatedDomain=freeiam.org))`
        host, _, domain = expression.value.partition('.')
        parent.replace(
            expression, (a('cn') == host) & (a('associatedDomain') == domain)
        )
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
        parent.replace(
            expression, a(expression.attr, '', 'caseIgnoreMatch') == expression.value
        )
    elif expression.attr == 'birthdate':
        # ``(birthdate=2025-07-04)``
        # → ``(dateOfBirth:generalizedTimeMatch:=20250704000000Z)``
        from datetime import datetime

        dt = datetime.strptime(expression.value, '%Y-%m-%d')  # noqa: DTZ007
        parent.replace(
            expression,
            a('dateOfBirth', '', 'generalizedTimeMatch')
            == dt.strftime('%Y%m%d%H%M%SZ'),
        )
    elif expression.attr == 'unlocked':
        # ``(unlocked=TRUE)`` → ``(!(locked=TRUE))``
        expression.attr = 'locked'
        parent.replace(expression, NOT([expression]))
    elif expression.attr == 'app' and isinstance(expression, SubstringMatch):
        # ``(app=app*)`` → (|(app=app01)(app=app02))
        if expression.value == 'app*':
            parent.replace(
                expression,
                (a('app') == 'app01') | [(a('app') == 'app02'), (a('app') == 'app03')],
            )
        return
    elif expression.attr == 'disabled':
        # ``(disabled=TRUE)`` →
        # ``(&(shadowExpire=1)(krb5KDCFlags:1.2.840.113556.1.4.803:=128)
        #   (|(sambaAcctFlags=[UD       ])(sambaAcctFlags=[ULD       ])))``
        disabled = (a('shadowExpire') == '1') & [
            (a('krb5KDCFlags', '', '1.2.840.113556.1.4.803') == '128'),
            (
                (a('sambaAcctFlags') == '[UD       ]')
                | (a('sambaAcctFlags') == '[ULD       ]')
            ),
        ]
        enabled = (a('shadowExpire') != '1') & [
            (a('krb5KDCFlags', '', '1.2.840.113556.1.4.803') != '128'),
            (
                (a('sambaAcctFlags') != '[UD       ]')
                & (a('sambaAcctFlags') != '[ULD       ]')
            ),
        ]
        parent.replace(
            expression,
            disabled.copy() if expression.value in {'1', 'TRUE'} else enabled.copy(),
        )
    else:
        return
    if isinstance(expression, EqualityMatch):
        return
    raise NotImplementedError(type(expression))  # or ignore gracefully :-)


def operator_callback(filter_, parent, expression):
    if any(
        expr.attr.lower() == 'objectClass'.lower()
        and expr.value.lower() == 'inetOrgPerson'.lower()
        for expr in expression.expressions
        if isinstance(expr, Comparison)
    ):
        # ``(&(objectClass=top)(objectClass=person)(objectClass=inetOrgPerson))``
        # → ``(objectClass=inetOrgPerson)``
        for expr in expression.comparisons:
            if expr.attr.lower() == 'objectClass'.lower() and expr.value.lower() in {
                'top',
                'person',
            }:
                expression.remove(expr)

    for expr in expression.comparisons:
        # ``(|(uid=alice)(uid=alice))`` → ``(|(uid=alice))``
        if expression.expressions.count(expr) > 1:
            expression.remove(expr)

    if (
        len(expression.comparisons) + len(expression.operators)
    ) == 1 and not isinstance(expression, NOT):
        # ``(|(uid=alice))`` → ``(uid=alice)``
        parent.replace(expression, expression.expressions[0])


FILTER_EXPRESSION: str = ...
fil = Filter(FILTER_EXPRESSION)
fil.walk(comparison_callback, operator_callback, WalkStrategy.POST)
print(fil.pretty())
# end FILTER TRANSFORMATIONS
