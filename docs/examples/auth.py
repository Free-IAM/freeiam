import sys

from freeiam import errors, ldap
from freeiam.ldap.constants import Option, TLSOptionValue


async def ldap_authenticate_example():
    """
    Authenticate using different mechanisms.

    e.g. PLAIN or
    Simple Authentication and Security Layer (SASL): EXTERNAL, GSSAPI, OAUTHBEARER
    """

    async with ldap.Connection('ldap://localhost:389') as conn:
        conn.set_tls(ca_certfile='/path/to/ca.crt', require_cert=TLSOptionValue.Hard)
        await conn.start_tls()

        # perform a simple bind
        try:
            await conn.bind('cn=admin,dc=freeiam,dc=org', 'iamfree')
        except errors.InvalidCredentials as exc:
            # don't forge to handle errors on wrong password!
            sys.exit(str(exc))
            ...

        # perform a GSSAPI SASL if you have a valid ticket
        await conn.bind_gssapi()

        # perform SASL OAUTHBEARER authentication using OAuth 2.0 access token (JWT)
        authzid = None
        token = 'eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxIn0.dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk'  # noqa: S105,E501
        await conn.bind_oauthbearer(authzid, token)

        dn = await conn.whoami()  # check who you are

        # if your server supports it you can also change your password
        await conn.change_password(dn, 'iamfree', 'noiamunfree')

    # perform SASL EXTERNAL authentication using local UNIX socket
    async with ldap.Connection('ldapi:///path/to/unix/socket') as conn:
        # you might want to set certain options
        conn.set_option(Option.Referrals, 0)

        # perform SASL EXTERNAL auth
        await conn.bind_external()

        await conn.whoami()  # check who you are
