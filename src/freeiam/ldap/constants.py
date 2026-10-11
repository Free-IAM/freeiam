# SPDX-FileCopyrightText: 2025 Florian Best
# SPDX-License-Identifier: MIT OR Apache-2.0
"""LDAP Constants."""

# See https://app.readthedocs.org/projects/python-ldap/downloads/pdf/latest/

from enum import IntEnum, StrEnum
from typing import TypeAlias

import ldap
from ldap.controls.sessiontrack import (
    SESSION_TRACKING_FORMAT_OID_RADIUS_ACCT_MULTI_SESSION_ID,
    SESSION_TRACKING_FORMAT_OID_RADIUS_ACCT_SESSION_ID,
    SESSION_TRACKING_FORMAT_OID_USERNAME,
)


def _getoptional(name: str, default: int) -> int:
    return getattr(ldap, name, default)


class Scope(IntEnum):
    """All possible search scopes."""

    Base = ldap.SCOPE_BASE
    """Search only the base entry."""

    Onelevel = ldap.SCOPE_ONELEVEL
    """Search the immediate children of the base entry, excluding the base entry itself."""

    Subtree = ldap.SCOPE_SUBTREE
    """Search the base entry and all its descendants."""

    Subordinate = _getoptional('SCOPE_SUBORDINATE', 3)
    """Search all descendants (children) of the base entry, excluding the base entry itself."""

    One = Onelevel
    """Alias for :attr:`Onelevel`."""
    Sub = Subtree
    """Alias for :attr:`Subtree`."""
    Children = Subordinate
    """Alias for :attr:`Subordinate`."""

    BASE = Base
    """Alias for :attr:`Base`."""
    ONELEVEL = Onelevel
    """Alias for :attr:`Onelevel`."""
    SUBTREE = Subtree
    """Alias for :attr:`Subtree`."""


class Mod(IntEnum):
    """Modification list entry."""

    Add = ldap.MOD_ADD
    """Add values to an attribute."""
    BinaryValues = ldap.MOD_BVALUES
    """Indicate that modification values are binary. Internal flag - don't use it!"""
    Delete = ldap.MOD_DELETE
    """Delete values from an attribute."""
    Increment = ldap.MOD_INCREMENT
    """Increment an integer-valued attribute."""
    Replace = ldap.MOD_REPLACE
    """Replace all values of an attribute."""


class Version(IntEnum):
    """LDAP protocol version."""

    LDAPV1 = ldap.VERSION1
    """Version 1"""

    LDAPV2 = ldap.VERSION2
    """Version 2"""

    LDAPV3 = ldap.VERSION3
    """Version 3"""

    Max = ldap.VERSION_MAX
    """Maximum supported protocol version."""

    Min = ldap.VERSION_MIN
    """Minimum supported protocol version."""

    V1 = LDAPV1
    """Alias for :attr:`LDAPV1`."""
    V2 = LDAPV2
    """Alias for :attr:`LDAPV2`."""
    V3 = LDAPV3
    """Alias for :attr:`LDAPV3`."""


class Option(IntEnum):
    """LDAP options."""

    # API / Info
    ApiFeatureInfo = ldap.OPT_API_FEATURE_INFO
    """Returns API feature information (`int`)."""

    ApiInfo = ldap.OPT_API_INFO
    """Returns API information (`int`)."""

    # Debug / Diagnostics
    DebugLevel = ldap.OPT_DEBUG_LEVEL
    """Set the debug level within the underlying OpenLDAP C library (`int`).

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
    """SASL options, which must be set per connection."""

    AuthCID = ldap.OPT_X_SASL_AUTHCID
    """SASL authentication identity."""
    AuthZID = ldap.OPT_X_SASL_AUTHZID
    """SASL authorization identity."""
    Mechanism = ldap.OPT_X_SASL_MECH
    """SASL mechanism to use."""
    NoCanonicalization = _getoptional('OPT_X_SASL_NOCANON', 24843)
    """If set to zero, SASL host name canonicalization is disabled."""
    Realm = ldap.OPT_X_SASL_REALM
    """SASL realm."""
    Secprops = ldap.OPT_X_SASL_SECPROPS
    """SASL security properties."""
    SSF = ldap.OPT_X_SASL_SSF
    """Security strength factor."""
    SSFExternal = ldap.OPT_X_SASL_SSF_EXTERNAL
    """External security strength factor."""
    SSFMax = ldap.OPT_X_SASL_SSF_MAX
    """Maximum security strength factor."""
    SSFMin = ldap.OPT_X_SASL_SSF_MIN
    """Minimum security strength factor."""
    Username = _getoptional('OPT_X_SASL_USERNAME', 24844)
    """SASL username."""


class OptionValue(IntEnum):
    """LDAP option values."""

    Off = ldap.OPT_OFF
    """Disable the option."""
    On = ldap.OPT_ON
    """Enable the option."""
    Success = ldap.OPT_SUCCESS
    """Successful operation result."""

    NoLimit = ldap.NO_LIMIT
    """No limit is imposed."""


class KeepAlive(IntEnum):
    """Keep-alive option values."""

    Idle = _getoptional('OPT_X_KEEPALIVE_IDLE', 25344)
    """Idle time before keep-alive probes start, in seconds."""
    Interval = _getoptional('OPT_X_KEEPALIVE_INTERVAL', 25346)
    """Interval between keep-alive probes, in seconds."""
    Probes = _getoptional('OPT_X_KEEPALIVE_PROBES', 25345)
    """Number of keep-alive probes before the connection is considered dead."""


class TLSOption(IntEnum):
    """TLS options."""

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
    """Do not check certificate revocation lists."""
    Peer = ldap.OPT_X_TLS_CRL_PEER
    """Check the peer certificate against a certificate revocation list."""
    All = ldap.OPT_X_TLS_CRL_ALL
    """Check all certificates against a certificate revocation list."""


class TLSRequireCert(IntEnum):
    """Values for Certificate requirement or Subject Alternative Name (TLSOption.RequireCert and TLSOption.RequireSAN)."""

    Never = ldap.OPT_X_TLS_NEVER
    """Never request or require a client certificate."""
    Allow = ldap.OPT_X_TLS_ALLOW
    """Allow an unavailable or invalid client certificate."""
    Try = ldap.OPT_X_TLS_TRY
    """Request a client certificate without requiring one."""
    Demand = ldap.OPT_X_TLS_DEMAND
    """Require a valid client certificate."""
    Hard = ldap.OPT_X_TLS_HARD
    """Require a valid client certificate and fail hard on errors."""


class TLSProtocol(IntEnum):
    """Values for TLSOption.ProtocolMin / TLSOption.ProtocolMax."""

    SSL3 = _getoptional('OPT_X_TLS_PROTOCOL_SSL3', 0x300)
    """SSL 3.0."""
    TLS10 = _getoptional('OPT_X_TLS_PROTOCOL_TLS1_0', 0x301)
    """TLS 1.0."""
    TLS11 = _getoptional('OPT_X_TLS_PROTOCOL_TLS1_1', 0x302)
    """TLS 1.1."""
    TLS12 = _getoptional('OPT_X_TLS_PROTOCOL_TLS1_2', 0x303)
    """TLS 1.2."""
    TLS13 = _getoptional('OPT_X_TLS_PROTOCOL_TLS1_3', 0x304)
    """TLS 1.3."""


class Dereference(IntEnum):
    """Dereference options."""

    Always = ldap.DEREF_ALWAYS
    """Always dereference aliases."""
    Never = ldap.DEREF_NEVER
    """Never dereference aliases."""
    Searching = ldap.DEREF_SEARCHING
    """Dereference aliases when searching below the base."""
    Finding = ldap.DEREF_FINDING
    """Dereference aliases when locating the base object."""


AnyOption: TypeAlias = Option | SASLOption | TLSOption | int
AnyOptionValue: TypeAlias = OptionValue | TLSCRLCheck | TLSRequireCert | TLSProtocol | KeepAlive | Dereference | int | str


class DNFormat(IntEnum):
    """Used for DN-parsing functions."""

    LDAP = ldap.DN_FORMAT_LDAP
    """Standard LDAP distinguished-name format."""
    LDAPV2 = ldap.DN_FORMAT_LDAPV2
    """LDAPv2 distinguished-name format."""
    LDAPV3 = ldap.DN_FORMAT_LDAPV3
    """LDAPv3 distinguished-name format."""
    DCE = ldap.DN_FORMAT_DCE
    """DCE distinguished-name format."""
    UFN = ldap.DN_FORMAT_UFN
    """User-friendly naming format."""
    ADCanonical = ldap.DN_FORMAT_AD_CANONICAL
    """Active Directory canonical name format."""
    Mask = ldap.DN_FORMAT_MASK
    """Mask for distinguished-name format flags."""
    Pretty = ldap.DN_PRETTY
    """Format a distinguished name for display."""
    Skip = ldap.DN_SKIP
    """Skip distinguished-name parsing."""
    NoLeadTrailSpaces = ldap.DN_P_NOLEADTRAILSPACES
    """Do not allow leading or trailing spaces."""
    NoSpaceAfterDN = ldap.DN_P_NOSPACEAFTERRDN
    """Do not allow spaces after an RDN separator."""
    Pedantic = ldap.DN_PEDANTIC
    """Apply strict distinguished-name parsing rules."""


class AVA(IntEnum):
    """Attribute Value Assertion formats."""

    Binary = ldap.AVA_BINARY
    """Binary attribute value."""
    NonPrintable = ldap.AVA_NONPRINTABLE
    """Non-printable attribute value."""
    Null = ldap.AVA_NULL
    """Null attribute value."""
    String = ldap.AVA_STRING
    """String attribute value."""


class ResponseType(IntEnum):
    """LDAP response protocol operation."""

    Add = ldap.RES_ADD
    """Add response."""
    Any = ldap.RES_ANY
    """Any response type."""
    Bind = ldap.RES_BIND
    """Bind response."""
    Compare = ldap.RES_COMPARE
    """Compare response."""
    Delete = ldap.RES_DELETE
    """Delete response."""
    Extended = ldap.RES_EXTENDED
    """Extended operation response."""
    Intermediate = ldap.RES_INTERMEDIATE
    """Intermediate response."""
    Modify = ldap.RES_MODIFY
    """Modify response."""
    ModRDN = ldap.RES_MODRDN
    """Modify RDN response."""
    SearchEntry = ldap.RES_SEARCH_ENTRY
    """Search entry response."""
    SearchReference = ldap.RES_SEARCH_REFERENCE
    """Search reference response."""
    SearchResult = ldap.RES_SEARCH_RESULT
    """Search result response."""
    Unsolicited = ldap.RES_UNSOLICITED
    """Unsolicited response."""


class LDAPChangeType(IntEnum):
    """LDAP change type for the Persistent Search control."""

    Add = 1
    """An entry was added."""
    Delete = 2
    """An entry was deleted."""
    Modify = 4
    """An entry was modified."""
    ModifyDN = 8
    """An entry's distinguished name was modified."""


class SessionTrackingFormat(StrEnum):
    """OID of format values for SessionTracking control."""

    RadiusAcctSessionID = SESSION_TRACKING_FORMAT_OID_RADIUS_ACCT_SESSION_ID
    """RADIUS accounting session ID format."""
    RadiusAcctMultiSessionID = SESSION_TRACKING_FORMAT_OID_RADIUS_ACCT_MULTI_SESSION_ID
    """RADIUS accounting multi-session ID format."""
    Username = SESSION_TRACKING_FORMAT_OID_USERNAME
    """Username format."""
