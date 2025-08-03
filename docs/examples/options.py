from freeiam import ldap
from freeiam.ldap.constants import Version


async def ldap_set_connection_options_example():
    """Set various connection options easily"""

    async with ldap.Connection('ldap://localhost:389') as conn:
        # you can't remeber the constant names?
        # or you don't want to type `conn.set_option(Option.Foo, value)`?

        # Limit on waiting for any response, in seconds.
        conn.timelimit = 30

        # Limit on waiting for a network response, in seconds.
        conn.network_timeout = 30

        conn.follow_referrals = True

        # Controls whether aliases are automatically dereferenced.

        # Set the protocol version
        assert conn.protocol_version == Version.LDAPV3
        conn.protocol_version = Version.LDAPV3

        # Limit on size of message to receive from server.
        conn.sizelimit = 50
