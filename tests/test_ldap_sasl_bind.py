import json
import time
import uuid
from pathlib import Path

import jwt
import pytest

from freeiam import errors, ldap


def get_token(ldap_server, username):
    now = int(time.time())
    kid = json.load(Path(ldap_server['ca_cert']).with_name('jwks.json').open('rb'))['keys'][0]['kid']
    return jwt.encode(
        {
            'sub': 'uid=testuser,ou=users,dc=freeiam,dc=org',
            'iss': 'https://openid-provider.freeiam.org/realms/test',
            'aud': 'ldaps://ldap.freeiam.org/',
            'azp': 'https://test.freeiam.org/oidc/',
            'client_id': 'https://test.freeiam.org/oidc/',
            'scope': 'openid profile email',
            'iat': now,
            'nbf': now,
            'exp': now + 300,
            'jti': str(uuid.uuid4()),
            'preferred_username': username,
        },
        Path(ldap_server['ca_cert']).with_name('ldap.key').read_text(encoding='utf-8'),
        algorithm='RS256',
        headers={
            'typ': 'at+jwt',
            'kid': kid,
        },
    )


@pytest.mark.asyncio
async def test_sasl_bind_oauthbearer(ldap_server, base_dn):
    async with ldap.Connection(ldap_server['ldap_uri'], retry_delay=1) as conn:
        conn.start_tls()
        await conn.bind_oauthbearer(get_token(ldap_server, 'myuser01'))
        assert (await conn.whoami()) == 'uid=myuser01,cn=oauthbearer,cn=auth'  # TODO: authz-regexp


def test_sasl_bind_oauthbearer_sync_forbidden_username(ldap_server, base_dn):
    with ldap.Connection(ldap_server['ldap_uri'], retry_delay=1) as conn:
        conn.start_tls()
        with pytest.raises(errors.InvalidCredentials) as exc:
            conn.bind_oauthbearer(get_token(ldap_server, 'admin'))
        assert 'username "admin" is disallowed' in str(exc.value)
