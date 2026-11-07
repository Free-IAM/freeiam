# start regular
from freeiam import ldap


TIMEOUT = 30  # set a usefull default timeout!


async def ldap_connection_example():
    """Basic LDAP connection handling."""

    # you can just do everything manually, or with a context manager, see next example
    connection = ldap.Connection('ldap://ldap.freeiam.org:389', timeout=TIMEOUT)
    connection.connect()
    await connection.bind('cn=admin,dc=freeiam,dc=org', 'iamfree')

    # you can also reconnect!
    connection.reconnect()

    # or unbind
    await connection.unbind()

    # and disconnect
    connection.disconnect()
    # end regular


# start STARTTLS
async def ldap_start_tls_connection_example():
    """A connection to the LDAP server using StartTLS (bound to the admin account)"""

    # connect via START TLS to the plaintext port
    ldap.Connection.set_global_tls(
        ca_certfile='/path/to/ca.pem',
    )  # defaults: TLSv1.2 demand server certificate and SAN verification!
    async with ldap.Connection('ldap://ldap.freeiam.org:389', timeout=TIMEOUT) as conn:
        await conn.start_tls()
        await conn.bind('cn=admin,dc=freeiam,dc=org', 'iamfree')

        ...
    # end STARTTLS


# start TLS
async def ldaps_secure_connection_example():
    """A connection to the LDAP server using TLS (bound to the admin account)"""

    # connect via TLS encryption to the TLS port
    ldap.Connection.set_global_tls(
        ca_certfile='/path/to/ca.pem',
    )  # defaults: TLSv1.2 demand server certificate and SAN verification!
    async with ldap.Connection('ldaps://ldap.example.org:636', timeout=TIMEOUT) as conn:
        await conn.bind('cn=admin,dc=freeiam,dc=org', 'iamfree')

        ...
    # end TLS


# start plain
async def ldap_plaintext_connection_example():
    """A connection to the LDAP server using plaintext (bound to the admin account)"""

    # connect via plaintext (unsafe!)
    async with ldap.Connection('ldap://localhost:389', timeout=TIMEOUT) as conn:
        await conn.bind('cn=admin,dc=freeiam,dc=org', 'iamdumb')

        ...
    # end plain


# start test TLS
async def ldap_test_tls_connection_example():
    """Trust a self-signed certificate in a testing environment."""

    async with ldap.Connection('ldaps://localhost:636', timeout=TIMEOUT) as conn:
        conn.set_tls(
            ca_certfile='/path/to/self-signed-ca.pem',
        )
        await conn.bind('cn=admin,dc=freeiam,dc=org', 'iamfree')

        ...


# end test TLS


# start insecure TLS
async def ldap_insecure_tls_connection_example():
    """Disable certificate verification for isolated testing only."""

    from freeiam.ldap.constants import TLSRequireCert

    async with ldap.Connection('ldaps://localhost:636', timeout=TIMEOUT) as conn:
        conn.set_tls(
            require_cert=TLSRequireCert.Never,
            require_san=TLSRequireCert.Never,
        )
        await conn.bind('cn=admin,dc=freeiam,dc=org', 'iamdumb')

        ...


# end insecure TLS
