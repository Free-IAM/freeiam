# SPDX-FileCopyrightText: 2025 Florian Best
# SPDX-License-Identifier: MIT OR Apache-2.0
"""LDAP Extended Operations."""

from ldap.extop import ExtendedRequest, ExtendedResponse
from ldap.extop.dds import RefreshRequest, RefreshResponse
from ldap.extop.passwd import PasswordModifyResponse
from pyasn1.codec.ber import decoder, encoder
from pyasn1.type import namedtype, univ

from freeiam.ldap.dn import DN


__all__ = (
    'ExtendedRequest',
    'ExtendedResponse',
    'PasswordModifyResponse',
    'refresh_ttl',
    'transaction_commit',
    'transaction_start',
)


def refresh_ttl(entry_name: DN | str, ttl: int | None):
    """Get Refresh request."""
    req = RefreshRequest(RefreshRequest.requestName, str(entry_name).encode('UTF-8'), ttl)
    if not hasattr(req, 'requestValue'):  # pragma: no cover
        # https://github.com/python-ldap/python-ldap/commit/414ae1de91543a1c0fee0738f97fe1a33d0fe666
        req.requestValue = req.encodedRequestValue()
    return req


def transaction_start():
    """Start a transaction."""
    return StartTransactionRequest()


def transaction_commit(transaction_id: bytes | None = None, commit: bool = True):
    """End (abort or commit) a transaction."""
    return EndTransactionRequest(commit, transaction_id)


class StartTransactionRequest(ExtendedRequest):
    requestName = '1.3.6.1.1.21.1'  # noqa: N815

    def __init__(self):
        super().__init__(self.requestName, None)


class StartTransactionResponse(ExtendedResponse):
    responseName = None  # noqa: N815

    def __init__(self, responseName, encodedResponseValue):  # noqa: N803  # pragma: no cover
        self.txn_id = b''
        if encodedResponseValue:
            self.txn_id, _ = decoder.decode(encodedResponseValue, asn1Spec=univ.OctetString())
        super().__init__(responseName or self.responseName, encodedResponseValue)


class EndTransactionRequest(ExtendedRequest):
    requestName = '1.3.6.1.1.21.3'  # noqa: N815

    class TxnEndReq(univ.Sequence):
        componentType = namedtype.NamedTypes(  # noqa: N815
            namedtype.DefaultedNamedType('commit', univ.Boolean(True)),  # noqa: FBT003
            namedtype.NamedType('identifier', univ.OctetString()),
        )

    def __init__(self, commit=True, txn_id: bytes | None = None):
        self.commit = commit
        self.txn_id = txn_id
        super().__init__(self.requestName, None)

    def encodedRequestValue(self):  # noqa: N802
        req = self.TxnEndReq()
        req['commit'] = self.commit
        req['identifier'] = self.txn_id or b''
        return encoder.encode(req)


class EndTransactionResponse(ExtendedResponse):
    responseName = None  # noqa: N815

    # TODO: implement the optional response structure
    # TxnEndRes ::= SEQUENCE {
    #      messageID MessageID OPTIONAL,
    #           -- msgid associated with non-success resultCode
    #      updatesControls SEQUENCE OF UpdateControl SEQUENCE {
    #           messageID MessageID,
    #                -- msgid associated with controls
    #           controls  Controls
    #      } OPTIONAL
    # }

    # UpdateControl SEQUENCE {
    #      messageID MessageID,
    #           -- msgid associated with controls
    #      controls  Controls
    # }


class AbortedTransactionNotice(ExtendedResponse):
    responseName = '1.3.6.1.1.21.4'  # noqa: N815


refresh_ttl.response = RefreshResponse
transaction_start.response = StartTransactionResponse
transaction_commit.response = EndTransactionResponse
