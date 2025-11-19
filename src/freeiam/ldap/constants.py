# SPDX-FileCopyrightText: 2025 Florian Best
# SPDX-License-Identifier: MIT OR Apache-2.0
"""LDAP Constants."""

# See https://app.readthedocs.org/projects/python-ldap/downloads/pdf/latest/

from enum import IntEnum
from typing import TypeAlias

import ldap


def _getoptional(name: str, default: int) -> int:
    return getattr(ldap, name, default)


class Scope(IntEnum):
    """All possible search scopes."""

    Base = ldap.SCOPE_BASE
    """Base entry scope"""

    Onelevel = ldap.SCOPE_ONELEVEL
    """Direct children scope"""

    Subtree = ldap.SCOPE_SUBTREE
    """Whole subtree scope"""

    Subordinate = _getoptional('SCOPE_SUBORDINATE', 3)

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

    # API / Info
    ApiFeatureInfo = ldap.OPT_API_FEATURE_INFO
    """Returns API feature information (`int`)."""

    ApiInfo = ldap.OPT_API_INFO
    """Returns API information (`int`)."""

    # Debug / Diagnostics
    DebugLevel = ldap.OPT_DEBUG_LEVEL
    """Sets the debug level within the underlying OpenLDAP C library (`int`).

    libldap sends the log messages to stderr.
    """

    DiagnosticMessage = ldap.OPT_DIAGNOSTIC_MESSAGE
    """Gets the diagnostic message of the last operation (`str`)."""

    ErrorNumber = ldap.OPT_ERROR_NUMBER
    """Gets the error number of the last occurred error (`int`)."""

    ErrorString = ldap.OPT_ERROR_STRING
    """Gets the error string corresponding to the last occurred error (`str`)."""

    # Connection / Network
    FileDescriptor = ldap.OPT_DESC
    """Gets the file descriptor of the LDAP connection (`int`)."""

    ConnectAsync = _getoptional('OPT_CONNECT_ASYNC', 20496)
    """Enables asynchronous connect mode (`int`)."""

    HostName = ldap.OPT_HOST_NAME
    """The hostname used for the connection (`str`)."""

    NetworkTimeout = ldap.OPT_NETWORK_TIMEOUT
    """Network timeout in seconds (`int`).

    A timeout of -1 or None resets the timeout to infinity.
    """

    TCPUserTimeout = _getoptional('OPT_TCP_USER_TIMEOUT', 20501)
    """TCP user timeout in milliseconds (`int`)."""

    Timeout = ldap.OPT_TIMEOUT
    """Operation timeout in seconds (`int`).

    A timeout of -1 or None resets the timeout to infinity.
    """

    # LDAP behavior
    ProtocolVersion = ldap.OPT_PROTOCOL_VERSION
    """LDAP protocol version to use for the connection (`Version`)."""

    Dereference = ldap.OPT_DEREF
    """Specifies how alias dereferencing is performed (`Dereference`)."""

    Referrals = _getoptional('OPT_REFERRALS', 8)
    """Specifies whether referrals should be automatically chased (`int`)."""

    Refhoplimit = ldap.OPT_REFHOPLIMIT
    """Maximum number of referral hops (`int`)."""

    Restart = ldap.OPT_RESTART
    """Specifies whether operations are automatically restarted (`int`)."""

    DefaultBase = _getoptional('OPT_DEFBASE', 20489)
    """Default search base DN for operations (`str`)."""

    URI = ldap.OPT_URI
    """LDAP URI(s) for the connection (`str`)."""

    # Result / Limits
    ResultCode = ldap.OPT_RESULT_CODE
    """Gets the result code of the last operation (`int`)."""

    MatchedDN = ldap.OPT_MATCHED_DN
    """Gets the matched distinguished name from the last operation (`str`)."""

    Sizelimit = ldap.OPT_SIZELIMIT
    """Specifies the maximum number of entries to return for a search (`int`)."""

    Timelimit = ldap.OPT_TIMELIMIT
    """Specifies the maximum time in seconds a search may run (`int`)."""

    # Controls
    ClientControls = ldap.OPT_CLIENT_CONTROLS
    """List of LDAP client controls (`list`)."""

    ServerControls = ldap.OPT_SERVER_CONTROLS
    """List of LDAP server controls (`list`)."""


class SASLOption(IntEnum):
    """SASL Options (must be set per connection)."""

    AuthCID = ldap.OPT_X_SASL_AUTHCID
    AuthZID = ldap.OPT_X_SASL_AUTHZID
    Mechanism = ldap.OPT_X_SASL_MECH
    NoCanonicalization = _getoptional('OPT_X_SASL_NOCANON', 24843)
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
    Username = _getoptional('OPT_X_SASL_USERNAME', 24844)
    """SASL Username"""


class OptionValue(IntEnum):
    """LDAP Option Values."""

    Off = ldap.OPT_OFF
    On = ldap.OPT_ON
    Success = ldap.OPT_SUCCESS

    NoLimit = ldap.NO_LIMIT


class KeepAlive(IntEnum):
    """Keep Alive Option values."""

    Idle = _getoptional('OPT_X_KEEPALIVE_IDLE', 25344)
    Interval = _getoptional('OPT_X_KEEPALIVE_INTERVAL', 25346)
    Probes = _getoptional('OPT_X_KEEPALIVE_PROBES', 25345)


class TLSOption(IntEnum):
    """TLS Options."""

    # Certificate files and directories
    CACertdir = ldap.OPT_X_TLS_CACERTDIR
    """Path to a directory containing CA certificates (`str`)."""

    CACertfile = ldap.OPT_X_TLS_CACERTFILE
    """Path to a CA certificate file (`str`)."""

    Certfile = ldap.OPT_X_TLS_CERTFILE
    """Path to the client/server certificate file (`str`)."""

    Keyfile = ldap.OPT_X_TLS_KEYFILE
    """Path to the private key file corresponding to the certificate (`str`)."""

    DHFile = ldap.OPT_X_TLS_DHFILE
    """Path to the Diffie-Hellman parameters file (`str`)."""

    ECName = _getoptional('OPT_X_TLS_ECNAME', 24594)
    """Name of the elliptic curve to use (`str`)."""

    # Certificate verification
    CRLCheck = _getoptional('OPT_X_TLS_CRLCHECK', 24587)
    """Certificate Revocation List check policy (`TLSCRLCheck`)."""

    CRLFile = _getoptional('OPT_X_TLS_CRLFILE', 24592)
    """Path to a CRL file (`str`)."""

    RequireCert = ldap.OPT_X_TLS_REQUIRE_CERT
    """Certificate requirement level (`TLSRequireCert`)."""

    RequireSAN = _getoptional('OPT_X_TLS_REQUIRE_SAN', 24602)
    """Requirement for Subject Alternative Name (`TLSRequireCert`)."""

    PeerCert = _getoptional('OPT_X_TLS_PEERCERT', 24597)
    """Path to the peer certificate file (`str`)."""

    # Protocol and version settings
    ProtocolMin = _getoptional('OPT_X_TLS_PROTOCOL_MIN', 24583)
    """Minimum allowed TLS protocol (`TLSProtocol`)."""

    ProtocolMax = _getoptional('OPT_X_TLS_PROTOCOL_MAX', 24603)
    """Maximum allowed TLS protocol (`TLSProtocol`)."""

    Version = _getoptional('OPT_X_TLS_VERSION', 24595)
    """TLS library version (`str`)."""

    # Cipher settings
    Cipher = _getoptional('OPT_X_TLS_CIPHER', 24596)
    """Cipher specification (`str`)."""

    CipherSuite = ldap.OPT_X_TLS_CIPHER_SUITE
    """Cipher suite selection (`str`)."""

    # Misc / control
    Package = _getoptional('OPT_X_TLS_PACKAGE', 24593)
    """TLS package to use (`str`)."""

    NewContext = _getoptional('OPT_X_TLS_NEWCTX', 24591)
    """Create a new internal TLS context (`int`).

    libldap does not apply all TLS settings immediately.
    Use this option with value 0 to instruct libldap to apply
    pending TLS settings and create a new internal TLS context.
    """


class TLSCRLCheck(IntEnum):
    """Values for Certificate Revocation List checks (TLSOption.CRLCheck)."""

    None_ = ldap.OPT_X_TLS_CRL_NONE
    Peer = ldap.OPT_X_TLS_CRL_PEER
    All = ldap.OPT_X_TLS_CRL_ALL


class TLSRequireCert(IntEnum):
    """Values for Certificate requirement or Subject Alternative Name (TLSOption.RequireCert and TLSOption.RequireSAN)."""

    Never = ldap.OPT_X_TLS_NEVER
    Allow = ldap.OPT_X_TLS_ALLOW
    Try = ldap.OPT_X_TLS_TRY
    Demand = ldap.OPT_X_TLS_DEMAND
    Hard = ldap.OPT_X_TLS_HARD


class TLSProtocol(IntEnum):
    """Values for TLSOption.ProtocolMin / TLSOption.ProtocolMax."""

    SSL3 = _getoptional('OPT_X_TLS_PROTOCOL_SSL3', 0x300)
    TLS10 = _getoptional('OPT_X_TLS_PROTOCOL_TLS1_0', 0x301)
    TLS11 = _getoptional('OPT_X_TLS_PROTOCOL_TLS1_1', 0x302)
    TLS12 = _getoptional('OPT_X_TLS_PROTOCOL_TLS1_2', 0x303)
    TLS13 = _getoptional('OPT_X_TLS_PROTOCOL_TLS1_3', 0x304)


class Dereference(IntEnum):
    """Dereference options."""

    Always = ldap.DEREF_ALWAYS
    Never = ldap.DEREF_NEVER
    Searching = ldap.DEREF_SEARCHING
    Finding = ldap.DEREF_FINDING


AnyOption: TypeAlias = Option | SASLOption | TLSOption | int
AnyOptionValue: TypeAlias = OptionValue | TLSCRLCheck | TLSRequireCert | TLSProtocol | KeepAlive | Dereference | int | str


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
    """Attribute Value Assertion formats."""

    Binary = ldap.AVA_BINARY
    NonPrintable = ldap.AVA_NONPRINTABLE
    Null = ldap.AVA_NULL
    String = ldap.AVA_STRING


class ResponseType(IntEnum):
    """LDAP Response protocol operation."""

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


class LDAPChangeType(IntEnum):
    """LDAP change type for PersistentSearchControl control."""

    Add = 1
    Delete = 2
    Modify = 4
    ModifyDN = 8
