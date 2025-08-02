# SPDX-FileCopyrightText: 2025 Florian Best
# SPDX-License-Identifier: MIT OR Apache-2.0
"""LDAP Constants."""

# See https://app.readthedocs.org/projects/python-ldap/downloads/pdf/latest/

from enum import IntEnum
from typing import TypeAlias

import ldap


class Scope(IntEnum):
    """All possible search scopes."""

    Base = ldap.SCOPE_BASE
    """Base entry scope"""

    Onelevel = ldap.SCOPE_ONELEVEL
    """Direct children scope"""

    Subtree = ldap.SCOPE_SUBTREE
    """Whole subtree scope"""

    One = Onelevel
    Sub = Subtree

    BASE = Base
    ONELEVEL = Onelevel
    SUBTREE = Subtree


class Mod(IntEnum):
    """Modification list entry."""

    Add = ldap.MOD_ADD
    BinaryValues = ldap.MOD_BVALUES
    Delete = ldap.MOD_DELETE
    Increment = ldap.MOD_INCREMENT
    Replace = ldap.MOD_REPLACE


class Version(IntEnum):
    """LDAP Protocol Version."""

    LDAPV1 = ldap.VERSION1
    """Version 1"""

    LDAPV2 = ldap.VERSION2
    """Version 2"""

    LDAPV3 = ldap.VERSION3
    """Version 3"""

    Max = ldap.VERSION_MAX
    """Maximum protocol version"""

    Min = ldap.VERSION_MIN
    """Minimum protocol version"""

    V1 = LDAPV1
    V2 = LDAPV2
    V3 = LDAPV3


class Option(IntEnum):
    """LDAP Options."""

    ApiFeatureInfo = ldap.OPT_API_FEATURE_INFO
    ApiInfo = ldap.OPT_API_INFO
    ClientControls = ldap.OPT_CLIENT_CONTROLS
    ConnectAsync = ldap.OPT_CONNECT_ASYNC
    DebugLevel = ldap.OPT_DEBUG_LEVEL
    """Sets the debug level within the underlying OpenLDAP C lib. libldap sends the log messages to stderr."""
    Defbase = ldap.OPT_DEFBASE
    Dereference = ldap.OPT_DEREF
    """Specifies how alias dereferencing is done within the underlying LDAP C lib."""
    Desc = ldap.OPT_DESC
    DiagnosticMessage = ldap.OPT_DIAGNOSTIC_MESSAGE
    ErrorNumber = ldap.OPT_ERROR_NUMBER
    """Get the errno of the last occurred error."""
    ErrorString = ldap.OPT_ERROR_STRING
    """Get the errno string of the last occurred error."""
    HostName = ldap.OPT_HOST_NAME
    MatchedDN = ldap.OPT_MATCHED_DN
    NetworkTimeout = ldap.OPT_NETWORK_TIMEOUT
    """Network timeout. A timeout of -1 or None resets timeout to infinity."""
    ProtocolVersion = ldap.OPT_PROTOCOL_VERSION
    """Sets the LDAP protocol version used for a connection."""
    Referrals = ldap.OPT_REFERRALS
    """Specifies whether referrals should be automatically chased within the underlying LDAP C lib."""
    Refhoplimit = ldap.OPT_REFHOPLIMIT
    Restart = ldap.OPT_RESTART
    ResultCode = ldap.OPT_RESULT_CODE
    ServerControls = ldap.OPT_SERVER_CONTROLS
    Sizelimit = ldap.OPT_SIZELIMIT
    # TCPUserTimeout = ldap.OPT_TCP_USER_TIMEOUT
    Timelimit = ldap.OPT_TIMELIMIT
    Timeout = ldap.OPT_TIMEOUT
    """Timeout. A timeout of -1 or None resets timeout to infinity."""
    URI = ldap.OPT_URI


class SASLOption(IntEnum):
    """SASL Options (must be set per connection)."""

    AuthCID = ldap.OPT_X_SASL_AUTHCID
    AuthZID = ldap.OPT_X_SASL_AUTHZID
    Mechanism = ldap.OPT_X_SASL_MECH
    NoCanonicalization = ldap.OPT_X_SASL_NOCANON
    """If set to zero, SASL host name canonicalization is disabled."""
    Realm = ldap.OPT_X_SASL_REALM
    Secprops = ldap.OPT_X_SASL_SECPROPS
    SSF = ldap.OPT_X_SASL_SSF
    """Security Strength Factor"""
    SSFExternal = ldap.OPT_X_SASL_SSF_EXTERNAL
    SSFMax = ldap.OPT_X_SASL_SSF_MAX
    """Maximum Security Strength Factor"""
    SSFMin = ldap.OPT_X_SASL_SSF_MIN
    """Minimum Security Strength Factor"""
    Username = ldap.OPT_X_SASL_USERNAME
    """SASL Username"""


class OptionValue(IntEnum):
    """LDAP Option Values."""

    Off = ldap.OPT_OFF
    On = ldap.OPT_ON
    Success = ldap.OPT_SUCCESS

    # X-Keep-Alive
    KeepAliveIdle = ldap.OPT_X_KEEPALIVE_IDLE
    KeepAliveInterval = ldap.OPT_X_KEEPALIVE_INTERVAL
    KeepAliveProbes = ldap.OPT_X_KEEPALIVE_PROBES

    NoLimit = ldap.NO_LIMIT


class TLSOption(IntEnum):
    """TLS Options."""

    TLS = ldap.OPT_X_TLS  # Deprecated!
    CACertdir = ldap.OPT_X_TLS_CACERTDIR
    CACertfile = ldap.OPT_X_TLS_CACERTFILE
    Certfile = ldap.OPT_X_TLS_CERTFILE
    # Cipher = ldap.OPT_X_TLS_CIPHER
    CipherSuite = ldap.OPT_X_TLS_CIPHER_SUITE
    CRLCheck = ldap.OPT_X_TLS_CRLCHECK
    CRLFile = ldap.OPT_X_TLS_CRLFILE
    Context = ldap.OPT_X_TLS_CTX  # DO NOT USE!
    # DHFile = ldap.OPT_X_TLS_DHFILE
    # ECName = ldap.OPT_X_TLS_ECNAME
    Keyfile = ldap.OPT_X_TLS_KEYFILE
    # NewContext = ldap.OPT_X_TLS_NEWCTX
    """libldap does not materialize all TLS settings immediately. You must use OPT_X_TLS_NEWCTX with value 0 to instruct libldap to apply pending TLS settings and create a new internal TLS context"""  # noqa: E501
    Package = ldap.OPT_X_TLS_PACKAGE
    # PeerCert = ldap.OPT_X_TLS_PEERCERT
    # ProtocolMax = ldap.OPT_X_TLS_PROTOCOL_MAX
    # ProtocolMin = ldap.OPT_X_TLS_PROTOCOL_MIN
    RandomFile = ldap.OPT_X_TLS_RANDOM_FILE  # DO NOT USE!
    # RequireCert = ldap.OPT_X_TLS_REQUIRE_CERT
    # RequireSAN = ldap.OPT_X_TLS_REQUIRE_SAN
    # Version = ldap.OPT_X_TLS_VERSION


class TLSOptionValue(IntEnum):
    """TLS Option values."""

    # for OPT_X_TLS_CRLCHECK
    CrlNone = ldap.OPT_X_TLS_CRL_NONE
    CrlPeer = ldap.OPT_X_TLS_CRL_PEER
    CrlAll = ldap.OPT_X_TLS_CRL_ALL

    # for OPT_X_TLS_REQUIRE_CERT / OPT_X_TLS_REQUIRE_SAN
    Never = ldap.OPT_X_TLS_NEVER
    Allow = ldap.OPT_X_TLS_ALLOW
    Try = ldap.OPT_X_TLS_TRY
    Demand = ldap.OPT_X_TLS_DEMAND
    Hard = ldap.OPT_X_TLS_HARD

    # for OPT_X_TLS_PROTOCOL_MIN / OPT_X_TLS_PROTOCOL_MAX
    ProtocolSSL3 = ldap.OPT_X_TLS_PROTOCOL_SSL3
    ProtocolTLS10 = ldap.OPT_X_TLS_PROTOCOL_TLS1_0
    ProtocolTLS11 = ldap.OPT_X_TLS_PROTOCOL_TLS1_1
    ProtocolTLS12 = ldap.OPT_X_TLS_PROTOCOL_TLS1_2
    # ProtocolTLS13 = ldap.OPT_X_TLS_PROTOCOL_TLS1_3


class Dereference(IntEnum):
    """Dereference options."""

    Always = ldap.DEREF_ALWAYS
    Never = ldap.DEREF_NEVER
    Searching = ldap.DEREF_SEARCHING
    Finding = ldap.DEREF_FINDING


AnyOption: TypeAlias = Option | SASLOption | TLSOption | int
AnyOptionValue: TypeAlias = OptionValue | TLSOptionValue | Dereference | int | str


class DNFormat(IntEnum):
    """Used for DN-parsing functions."""

    LDAP = ldap.DN_FORMAT_LDAP
    LDAPV2 = ldap.DN_FORMAT_LDAPV2
    LDAPV3 = ldap.DN_FORMAT_LDAPV3
    DCE = ldap.DN_FORMAT_DCE
    UFN = ldap.DN_FORMAT_UFN
    ADCanonical = ldap.DN_FORMAT_AD_CANONICAL
    Mask = ldap.DN_FORMAT_MASK
    Pretty = ldap.DN_PRETTY
    Skip = ldap.DN_SKIP
    NoLeadTrailSpaces = ldap.DN_P_NOLEADTRAILSPACES
    NoSpaceAfterDN = ldap.DN_P_NOSPACEAFTERRDN
    Pedantic = ldap.DN_PEDANTIC


class AVA(IntEnum):
    """Attribute Value Assertion."""

    Binary = ldap.AVA_BINARY
    NonPrintable = ldap.AVA_NONPRINTABLE
    Null = ldap.AVA_NULL
    String = ldap.AVA_STRING


class ResponseType(IntEnum):
    """LDAP Respons types."""

    Add = ldap.RES_ADD
    Any = ldap.RES_ANY
    Bind = ldap.RES_BIND
    Compare = ldap.RES_COMPARE
    Delete = ldap.RES_DELETE
    Extended = ldap.RES_EXTENDED
    Intermediate = ldap.RES_INTERMEDIATE
    Modify = ldap.RES_MODIFY
    ModRDN = ldap.RES_MODRDN
    SearchEntry = ldap.RES_SEARCH_ENTRY
    SearchReference = ldap.RES_SEARCH_REFERENCE
    SearchResult = ldap.RES_SEARCH_RESULT
    Unsolicited = ldap.RES_UNSOLICITED
