import freeiam.errors
import freeiam.ldap
from freeiam.ldap.constants import AVA
from freeiam.ldap.dn import DN


# First example, comparing a DN with a existing object:
conn: freeiam.ldap.Connection = ...
base: DN = ...
scope: int = ...

existing_object = conn.search(
    base, scope, filter_expr='(&(uid=max)(objectClass=person))', unique=True
)[0].dn
some_user_input_dn = 'Uid = mAx , ou = users , dc = FreeIAM , dc = org'
try:
    # this make a compare operation at the LDAP server
    # to compare the given value with each AVA in each RDN with the corresponding object
    is_equal = conn.compare_dn(existing_object, some_user_input_dn)
except freeiam.errors.NoSuchObject:
    ...  # the existing_object does not exists
except freeiam.errors.InsufficientAccess:
    ...  # no "compare" rights exists for any of the RDNs in the tree


# Second, the powerfull DN class provides utilities for every use case:
user_dn = 'uid = Max.Mustermann , cn = users , dc = freeiam, dc = org'
dn = DN(user_dn)

str(DN(user_dn))  # gives normalized: "uid=Max.Mustermann,cn=users,dc=freeiam,dc=org"
repr(dn)  # <DN uid=Max.Mustermann,cn=users,dc=freeiam,dc=org>

# make sure to handle errors for user given DNs:
some_user_input_dn: str = ...
try:
    DN(some_user_input_dn)
except freeiam.errors.InvalidDN as exc:
    print(exc)  # gives: Malformed DN syntax: "foo"

DN(user_dn).parent  # gives: DN("cn=users,dc=freeiam,dc=org")
DN('dc=org').parent  # gives: None
DN('dc=freeiam,dc=org').get_parent('dc=freeiam,dc=org')  # gives: None
DN(user_dn).endswith('dc=freeiam,dc=org')  # True
DN(user_dn).startswith('uid=Max.Mustermann,cn=users')  # True

# constructing new DNs:
base = DN('dc=freeiam,dc=org')
user_input: str = ...
DN.escape('#foo <+  ,=>"; bar#') == r'\#foo \<\+  \,\=\>\"\; bar#'

f'cn={DN.escape(user_input)},dc=freeiam,dc=org'

str(DN.compose(('cn', 'admin'), 'ou=foo,ou=bar', base))
# gives: 'cn=admin,ou=foo,ou=bar,dc=freeiam,dc=org'

str(DN('cn=foo,cn=bar') + 'dc=freeiam,dc=org')  # DN('cn=foo,cn=bar,dc=freeiam,dc=org')

len(dn)  # 4
dn[2]  # <DN dc=freeiam>
dn[:-2]  # <DN uid=Max.Mustermann,cn=users>


dn.rdn  # ('uid', 'Max.Mustermann')
dn.attribute  # 'uid'
dn.value  # 'Max.Mustermann'
multi_valued_rdn = DN('uid=1+cn=2,dc=3')
multi_valued_rdn.multi_rdn  # (('uid', '1'), ('cn', '2'))
multi_valued_rdn.attributes  # ('uid', 'cn')
multi_valued_rdn.values  # ('1', '2')

'cn=users' in dn  # True
DN('cn=users') in dn  # True
'cn=users,dc=freeiam' in dn  # False

# even broken DNs from Samba are supported:
str(DN(r'uid=foo\?bar,cn=users')) == 'uid=foo?bar,cn=users'

user_dn.rdns == [
    [('uid', 'Max.Mustermann', AVA.String)],
    [('cn', 'users', AVA.String)],
    [('dc', 'freeiam', AVA.String)],
    [('dc', 'org', AVA.String)],
]

list(dn.walk('dc=freeiam,dc=org'))  # walks from the right-most:
# [
#                                <DN dc=freeiam,dc=org>,
#                       <DN cn=users,dc=freeiam,dc=org>,
#    <DN uid=Max.Mustermann,cn=users,dc=freeiam,dc=org>
# ]

# DN objects are hashable and suitable for use a dictionary keys
{DN('UID = Administrator'): 1}[DN('uid=Administrator')] == 1

DN.normalize('uid = Max.Mustermann , cn = users , dc = freeiam, dc = org')
# "uid=Max.Mustermann,cn=users,dc=freeiam,dc=org"

isinstance(DN.get('uid=foo'), DN)
isinstance(DN.get(DN('uid=foo')), DN)


# comparisions, see the notes from the docs!
DN('foo=1') == DN('foo=1')
DN('foo=1') != DN('foo=2')
DN('Foo=1') == DN('foo=1')
DN('Foo=1') != DN('foo=2')
DN('uid=Administrator') == DN('uid=administrator')
DN('foo=Foo') != DN('foo=foo')
DN('foo=1,bar=2') == DN('foo=1,bar=2')
DN('bar=2,foo=1') != DN('foo=1,bar=2')
DN('foo=1+bar=2') == DN('foo=1+bar=2')
DN('bar=2+foo=1') == DN('foo=1+bar=2')
DN('bar=2+Foo=1') == DN('foo=1+Bar=2')
DN(f'foo={chr(92)}31') == DN(r'foo=1')

DN.get_unique(
    [
        'CN=users,dc=freeiam,dc=org',
        'cn=users,dc=freeiam,dc=org',
        'cn = users,dc=freeiam,dc=org',
        'CN=Users,dc=freeiam,dc=org',
    ]
)  # gives a set of unique DNs: {<DN CN=users,dc=freeiam,dc=org>}

DN.get_unique_str(
    DN.get_unique(['cn=foo', 'cn=bar']) - DN.get_unique(['cn = foo'])
    ) == {'cn=bar'}  # fmt: skip
