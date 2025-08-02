from freeiam import ldap
from freeiam.ldap.constants import Scope


def ldap_synchronous_examples():
    """Yes, you can do all this also synchronously! Just enter the synchronous context manager."""
    with ldap.Connection('ldap://localhost:389') as conn:
        conn.bind('cn=admin,dc=freeiam,dc=org', 'iamfree')

        search_base = 'dc=freeiam,dc=org'

        # search for DN and attrs
        for entry in conn.search(search_base, Scope.SUBTREE, '(&(uid=*)(objectClass=person))'):
            print(entry.dn, entry.attr)

        ...  # take a look at the API docs or other examples!
