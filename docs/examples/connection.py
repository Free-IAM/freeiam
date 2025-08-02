from freeiam import ldap
from freeiam.ldap.constants import TLSOptionValue


TIMEOUT = 30  # set a usefull default timeout!


async def ldap_connection_example():
    """Basic LDAP connection handling."""

    # you can just do everything manually, or with a context manager, see next example
    connection = ldap.Connection('ldap://localhost:389', timeout=TIMEOUT)
    connection.connect()
    await connection.bind('cn=admin,dc=freeiam,dc=org', 'iamfree')

    # you can also reconnect!
    connection.reconnect()

    # or unbind
    await connection.unbind()

    # and disconnect
    connection.disconnect()


async def ldap_start_tls_connection_example():
    """A connection to the LDAP server using StartTLS (bound to the admin account)"""

    # connect via START TLS to the plaintext port
    async with ldap.Connection('ldap://localhost:389', timeout=TIMEOUT) as conn:
        conn.set_tls(ca_certfile='/path/to/ca.crt', require_cert=TLSOptionValue.Hard)  # support self signed certificates? be strict?!
        await conn.start_tls()
        await conn.bind('cn=admin,dc=freeiam,dc=org', 'iamfree')

        ...


async def ldaps_secure_connection_example():
    """A connection to the LDAP server using TLS (bound to the admin account)"""

    # connect via TLS encryption to the TLS port
    async with ldap.Connection('ldap://localhost:389', timeout=TIMEOUT) as conn:
        conn.set_tls(ca_certfile='/path/to/ca.crt', require_cert=TLSOptionValue.Never)  # be unstrict (verify=False)
        await conn.bind('cn=admin,dc=freeiam,dc=org', 'iamfree')

        ...


async def ldap_plaintext_connection_example():
    """A connection to the LDAP server using plaintext (bound to the admin account)"""

    # connect via plaintext (unsafe!)
    async with ldap.Connection('ldap://localhost:389', timeout=TIMEOUT) as conn:
        await conn.bind('cn=admin,dc=freeiam,dc=org', 'iamfree')

        ...
