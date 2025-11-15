# SPDX-FileCopyrightText: 2025 Florian Best
# SPDX-License-Identifier: MIT OR Apache-2.0
"""LDAP Extended Operations."""

from ldap.extop import ExtendedRequest, ExtendedResponse
from ldap.extop.dds import RefreshRequest, RefreshResponse
from ldap.extop.passwd import PasswordModifyResponse
from pyasn1.codec.ber import decoder, encoder
from pyasn1.type import univ

from freeiam.ldap.dn import DN


__all__ = ('ExtendedRequest', 'ExtendedResponse', 'PasswordModifyResponse', 'RefreshRequest', 'RefreshResponse', 'refresh_ttl')


def refresh_ttl(entry_name: DN | str, ttl: int | None):
    """Get Refresh request."""
    req = RefreshRequest(RefreshRequest.requestName, str(entry_name), ttl)
    req.requestValue = b''  # req.encodedRequestValue()
    return req


refresh_ttl.response = RefreshResponse


class StartTransactionRequest(ExtendedRequest):
    requestName = '1.3.6.1.1.21.1'  # noqa: N815

    def __init__(self):
        super().__init__(self.requestName, None)


class StartTransactionResponse(ExtendedResponse):
    responseName = '1.3.6.1.1.21.1'  # noqa: N815

    def __init__(self, responseName, encodedResponseValue):  # noqa: N803
        self.txn_id = b''
        if encodedResponseValue:
            self.txn_id, _ = decoder.decode(encodedResponseValue, asn1Spec=univ.OctetString())
        super().__init__(responseName or self.responseName, encodedResponseValue)


class EndTransactionRequest(ExtendedRequest):
    requestName = '1.3.6.1.1.21.3'  # noqa: N815

    def __init__(self, commit=True):
        self.commit = commit
        value = encoder.encode(univ.Boolean(self.commit))
        super().__init__(self.requestName, value)


class EndTransactionResponse(ExtendedResponse):
    responseName = '1.3.6.1.1.21.3'  # noqa: N815


class AbortedTransactionNotice(ExtendedResponse):
    responseName = '1.3.6.1.1.21.4'  # noqa: N815


def transaction_start():
    return StartTransactionRequest()


transaction_start.response = StartTransactionResponse


def transaction_commit(commit: bool = True):
    return EndTransactionRequest(commit)


transaction_commit.response = EndTransactionResponse
