# SPDX-FileCopyrightText: 2025 Florian Best
# SPDX-License-Identifier: MIT OR Apache-2.0
"""Errors."""

import typing
from contextlib import contextmanager

import ldap


if typing.TYPE_CHECKING:
    import freeiam


class Error(Exception):
    """Base Error."""


class InvalidFilter(Error):
    """Invalid Filter Syntax."""


class CancelOperation(Error):
    """Cancel a running operation."""


class NotUnique(Error):
    """More than one unique search result."""

    args: tuple[list['freeiam.ldap._wrapper.Result']]

    @property
    def results(self) -> list['freeiam.ldap._wrapper.Result']:
        """The non unique search results."""
        return self.args[0]


class LdapError(Error):
    """LDAP Error wrapper base class."""

    _MAP: typing.ClassVar[dict[type[ldap.LDAPError], type[typing.Self]]] = {}
    exc_class = ldap.LDAPError
    _controls: list[tuple[str, bool, bytes]] | None
    _controls_decoded: list['ldap.controls.ResponseControl'] | None

    @property
    def result(self) -> int | None:
        """Numeric code of the error class."""
        return self._result

    @property
    def description(self) -> str | None:
        """String giving a description of the error class, as provided by calling OpenLDAP's ldap_err2string on the result."""
        return self._description

    @property
    def info(self) -> str | None:
        """
        String containing more information that the server may have sent.

        The value is server-speciﬁc: for example, the OpenLDAP server may send different info messages than Active Directory or 389-DS
        """
        return self._info

    @property
    def matched(self) -> str | None:
        """Truncated form of the name provided or alias. dereferenced for the lowest entry (object or alias) that was matched."""
        return self._matched

    @property
    def errno(self) -> int | None:
        """The C errno, usually set by system calls or libc rather than the LDAP libraries."""
        return self._errno

    @property
    def controls(self) -> list['ldap.controls.ResponseControl'] | None:
        """List of LDAP Control instances attached to the error."""
        if self._controls_decoded is None:
            from freeiam.ldap.controls import decode  # noqa: PLC0415

            assert self._controls is not None  # noqa: S101
            self._controls_decoded = decode(self._controls)
        return self._controls_decoded

    def __init_subclass__(cls: type[typing.Self], **kwargs: typing.Any):
        super().__init_subclass__(**kwargs)
        cls._MAP[cls.exc_class] = cls

    def __init__(self, args: dict[str, str | int | list[tuple[str, int, bytes]]] | None = None):
        args = args or {}
        self._result = typing.cast('int', args.get('result'))
        self._description = typing.cast('str', args.get('desc'))
        self._info = typing.cast('str', args.get('info'))
        self._matched = typing.cast('str', args.get('matched'))
        self._errno = typing.cast('int', args.get('errno'))
        self._controls = typing.cast('list[tuple[str, bool, bytes]]', args.get('ctrls'))
        self._controls_decoded = None
        super().__init__(args)

    def __str__(self) -> str:
        msg = f'{self.description or ""}: {self.info or ""}'.removesuffix(': ')
        if self.matched:
            msg = f'{msg} (exists: {self.matched})'
        return msg

    _repr_fields: typing.ClassVar = ['description', 'info', 'matched', 'result', 'errno']

    def __repr__(self) -> str:
        msg = ', '.join(f'{f}={getattr(self, f)!r}' for f in self._repr_fields)
        return f'{type(self).__name__}({msg})'

    @classmethod
    def from_ldap_exception(cls, exc: ldap.LDAPError) -> typing.Self:
        """Get instance from the correct child exception."""
        error = cls._MAP.get(type(exc), cls)
        args = exc.args[0] if exc and exc.args and isinstance(exc.args[0], dict) else {}
        return error(args)

    @classmethod
    def wrap(cls, hide_parent_exception: bool = True) -> typing.ContextManager[None]:
        """Context manager to wrap LDAP exceptions."""

        @contextmanager
        def _wrap() -> typing.Generator[None, None, None]:
            try:
                yield
            except ldap.LDAPError as exc:
                error = cls.from_ldap_exception(exc)
                if hide_parent_exception:
                    raise error from None
                raise error from exc

        return _wrap()


class AdminlimitExceeded(LdapError):
    """Adminlimit exceeded."""

    exc_class = ldap.ADMINLIMIT_EXCEEDED


class AffectsMultipleDSAs(LdapError):
    """Affects multiple Directory System Agent."""

    exc_class = ldap.AFFECTS_MULTIPLE_DSAS


class AliasDerefProblem(LdapError):
    """A problem was encountered when dereferencing an alias."""

    exc_class = ldap.ALIAS_DEREF_PROBLEM
    # sets matched


class AliasProblem(LdapError):
    """An alias in the directory points to a nonexistent entry."""

    exc_class = ldap.ALIAS_PROBLEM
    # sets matched


class AlreadyExists(LdapError):
    """The entry already exists. E.g. the DN speciﬁed with add() already exists in the DIT."""

    exc_class = ldap.ALREADY_EXISTS


class AssertionFailed(LdapError):
    """Assertion failed."""

    exc_class = ldap.ASSERTION_FAILED


class AuthMethodNotSupported(LdapError):
    """Authentication method is not supported."""

    exc_class = ldap.AUTH_METHOD_NOT_SUPPORTED


class AuthUnknown(LdapError):
    """The authentication method speciﬁed to bind() is not known."""

    exc_class = ldap.AUTH_UNKNOWN


class Busy(LdapError):
    """The DSA is busy."""

    exc_class = ldap.BUSY


class Cancelled(LdapError):
    """Cancelled."""

    exc_class = ldap.CANCELLED


class CannotCancel(LdapError):
    """Cannot cancel."""

    exc_class = ldap.CANNOT_CANCEL


class ClientLoop(LdapError):
    """Client loop."""

    exc_class = ldap.CLIENT_LOOP


class CompareFalse(LdapError):
    """A compare operation returned False."""

    exc_class = ldap.COMPARE_FALSE


class CompareTrue(LdapError):
    """A compare operation returned true."""

    exc_class = ldap.COMPARE_TRUE


class ConfidentialityRequired(LdapError):
    """
    Indicates that the session is not protected by a protocol such as Transport Layer Security (TLS).

    which provides session conﬁdentiality.
    """

    exc_class = ldap.CONFIDENTIALITY_REQUIRED


class ConnectError(LdapError):
    """Connect error."""

    exc_class = ldap.CONNECT_ERROR


class ConstraintViolation(LdapError):
    """
    An attribute value speciﬁed or an operation started violates some server-side constraint.

    (e.g., a postalAddress has too many lines or a line that is too long or a password is expired).
    """

    exc_class = ldap.CONSTRAINT_VIOLATION


class ControlNotFound(LdapError):
    """Control was not found."""

    exc_class = ldap.CONTROL_NOT_FOUND


class DecodingError(LdapError):
    """An error was encountered decoding a result from the LDAP server."""

    exc_class = ldap.DECODING_ERROR


class EncodingError(LdapError):
    """An error was encountered encoding parameters to send to the LDAP server."""

    exc_class = ldap.ENCODING_ERROR


class FilterError(LdapError):
    """The filter syntax is invalid e.g. due to unbalanced parentheses."""

    exc_class = ldap.FILTER_ERROR


class InappropriateAuthentication(LdapError):
    """
    Inappropriate authentication was speciﬁed.

    (e.g. if the user has no userPassword attribute on a simple bind)
    """

    exc_class = ldap.INAPPROPRIATE_AUTH


class InappropriateMatching(LdapError):
    """The filter type is not supported for the speciﬁed attribute."""

    exc_class = ldap.INAPPROPRIATE_MATCHING


class InsufficientAccess(LdapError):
    """The user has insufﬁcient access to perform the operation."""

    exc_class = ldap.INSUFFICIENT_ACCESS


class InvalidCredentials(LdapError):
    """Invalid credentials were presented during bind() or simple_bind(). (e.g., a wrong password)."""

    exc_class = ldap.INVALID_CREDENTIALS


class InvalidDN(LdapError):
    """A syntactically invalid DN was speciﬁed."""

    exc_class = ldap.INVALID_DN_SYNTAX
    # sets the matched field


class InvalidSyntax(LdapError):
    """An attribute value speciﬁed by the client did not comply to the syntax deﬁned in the server-side schema."""

    exc_class = ldap.INVALID_SYNTAX


class IsLeaf(LdapError):
    """The object speciﬁed is a leaf of the directory tree."""

    exc_class = ldap.IS_LEAF
    # sets the matched field


class LocalError(LdapError):
    """Some local error occurred. Usually caused by failed memory allocation."""

    exc_class = ldap.LOCAL_ERROR


class LoopDetected(LdapError):
    """A loop was detected."""

    exc_class = ldap.LOOP_DETECT


class MoreResultsToReturn(LdapError):
    """More results to return."""

    exc_class = ldap.MORE_RESULTS_TO_RETURN


class NamingViolation(LdapError):
    """A naming violation occurred. This is raised e.g. if the LDAP server has constraints about the tree naming."""

    exc_class = ldap.NAMING_VIOLATION


class NotAllowedOnNonleaf(LdapError):
    """The operation is not allowed on a non-leaf object."""

    exc_class = ldap.NOT_ALLOWED_ON_NONLEAF


class NotAllowedOnRDN(LdapError):
    """The operation is not allowed on an RDN."""

    exc_class = ldap.NOT_ALLOWED_ON_RDN


class NotSupported(LdapError):
    """Not supported."""

    exc_class = ldap.NOT_SUPPORTED


class NoMemory(LdapError):
    """No memory."""

    exc_class = ldap.NO_MEMORY


class NoObjectClassMods(LdapError):
    """Modifying the objectClass attribute as requested is not allowed (e.g. modifying structural object class of existing entry)."""

    exc_class = ldap.NO_OBJECT_CLASS_MODS


class NoResultsReturned(LdapError):
    """No results returned."""

    exc_class = ldap.NO_RESULTS_RETURNED


class NoSuchAttribute(LdapError):
    """The attribute type speciﬁed does not exist in the entry."""

    exc_class = ldap.NO_SUCH_ATTRIBUTE


class NoSuchObject(LdapError):
    """The speciﬁed object does not exist in the directory."""

    exc_class = ldap.NO_SUCH_OBJECT
    # sets the matched field

    _repr_fields: typing.ClassVar = [*LdapError._repr_fields, 'base_dn']

    def __init__(self, *args: typing.Any, **kwargs: typing.Any) -> None:
        self._base_dn: freeiam.ldap.dn.DN | None = None
        self.filter: str | None = None
        self.scope: freeiam.ldap.constants.Scope | None = None
        self.attrs: list[str] | None = None
        super().__init__(*args, **kwargs)

    @property
    def base_dn(self) -> 'freeiam.ldap.dn.DN | None':
        """Get search base DN."""
        return self._base_dn

    @base_dn.setter
    def base_dn(self, value: 'freeiam.ldap.dn.DN') -> None:
        """Set search base DN."""
        self._base_dn = value

    def __str__(self) -> str:
        string = super().__str__()
        if self.base_dn:
            string = f'{string} (base: {self._base_dn})'
        return string


class NoSuchOperation(LdapError):
    """No such operation."""

    exc_class = ldap.NO_SUCH_OPERATION


class NoUniqueEntry(LdapError):
    """No unique entry."""

    exc_class = ldap.NO_UNIQUE_ENTRY


class ObjectClassViolation(LdapError):
    """
    An object class violation occurred.

    When the LDAP server checked the data sent by the client against the server-side schema (e.g. a "must" attribute was missing in the entry data)
    """

    exc_class = ldap.OBJECT_CLASS_VIOLATION


class OperationsError(LdapError):
    """An operations error occurred."""

    exc_class = ldap.OPERATIONS_ERROR


class Other(LdapError):
    """An unclassiﬁed error occurred."""

    exc_class = ldap.OTHER


class ParamError(LdapError):
    """An LDAP routine was called with a bad parameter."""

    exc_class = ldap.PARAM_ERROR


class PartialResults(LdapError):
    """
    Only partial results were returned.

    This exception is raised if a referral is received when using LDAPv2.
    This exception should never be seen with LDAPv3.
    """

    exc_class = ldap.PARTIAL_RESULTS


class ProtocolError(LdapError):
    """A violation of the LDAP protocol was detected."""

    exc_class = ldap.PROTOCOL_ERROR


class ProxiedAuthorizationDenied(LdapError):
    """Proxied authorization was denied."""

    exc_class = getattr(ldap, 'PROXIED_AUTHORIZATION_DENIED', ldap.LDAPError)


class Referral(LdapError):
    """Referral."""

    exc_class = ldap.REFERRAL


class ReferralLimitExceeded(LdapError):
    """Referral limit exceeded."""

    exc_class = ldap.REFERRAL_LIMIT_EXCEEDED


class ResultsTooLarge(LdapError):
    """
    The result does not fit into a UDP packet.

    This happens only when using UDP-based CLDAP (connection-less LDAP) which is not supported anyway.
    """

    exc_class = ldap.RESULTS_TOO_LARGE


class SASLBindInProgress(LdapError):
    """SASL bind in progress."""

    exc_class = ldap.SASL_BIND_IN_PROGRESS


class ServerDown(LdapError):
    """The LDAP library can't contact the LDAP server."""

    exc_class = ldap.SERVER_DOWN


class SizelimitExceeded(LdapError):
    """An LDAP size limit was exceeded. This could be due to a sizelimit conﬁguration on the LDAP server."""

    exc_class = ldap.SIZELIMIT_EXCEEDED


class StrongAuthNotSupported(LdapError):
    """The LDAP server does not support strong authentication."""

    exc_class = ldap.STRONG_AUTH_NOT_SUPPORTED


class StrongAuthRequired(LdapError):
    """Strong authentication is required for the operation."""

    exc_class = ldap.STRONG_AUTH_REQUIRED


class Success(LdapError):
    """Success."""

    exc_class = ldap.SUCCESS


class TimelimitExceeded(LdapError):
    """An LDAP time limit was exceeded."""

    exc_class = ldap.TIMELIMIT_EXCEEDED


class Timeout(LdapError):
    """A timelimit was exceeded while waiting for a result from the server."""

    exc_class = ldap.TIMEOUT


class TooLate(LdapError):
    """Too late."""

    exc_class = ldap.TOO_LATE


class TypeOrValueExists(LdapError):
    """An attribute type or attribute value speciﬁed already exists in the entry."""

    exc_class = ldap.TYPE_OR_VALUE_EXISTS


class Unavailable(LdapError):
    """The DSA is unavailable."""

    exc_class = ldap.UNAVAILABLE


class UnavailableCriticalExtension(LdapError):
    """
    Indicates that the LDAP server was unable to satisfy a request.

    Because one or more critical extensions were not available.
    Either the server does not support the control or the control is not appropriate for the operation type.
    """

    exc_class = ldap.UNAVAILABLE_CRITICAL_EXTENSION


class UndefinedType(LdapError):
    """An attribute type used is not deﬁned in the server-side schema."""

    exc_class = ldap.UNDEFINED_TYPE


class UnwillingToPerform(LdapError):
    """The DSA is unwilling to perform the operation."""

    exc_class = ldap.UNWILLING_TO_PERFORM


class UserCancelled(LdapError):
    """The operation was cancelled via the abandon() method."""

    exc_class = ldap.USER_CANCELLED


class VLVError(LdapError):
    """Virtual List View control error."""

    exc_class = ldap.VLV_ERROR


class ProxyAuthZFailure(LdapError):
    """X-Proxy Authorization failure."""

    exc_class = ldap.X_PROXY_AUTHZ_FAILURE
