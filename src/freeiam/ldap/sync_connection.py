# SPDX-FileCopyrightText: 2025 Florian Best
# SPDX-License-Identifier: MIT OR Apache-2.0
"""LDAP Connection."""

import contextlib
import logging
import time
from collections.abc import AsyncGenerator, Callable, Generator
from typing import Any, Self, TypeAlias

import ldap.ldapobject
import ldap.modlist
import ldap.sasl
from ldap.schema import SCHEMA_ATTRS

from freeiam import errors
from freeiam.ldap._wrapper import Controls, Result, SimplePage, _Response
from freeiam.ldap.attr import Attributes
from freeiam.ldap.constants import AnyOption, AnyOptionValue, Option, OptionValue, ResponseType, Scope, TLSOption, TLSOptionValue, Version
from freeiam.ldap.controls import simple_paged_results
from freeiam.ldap.dn import DN
from freeiam.ldap.schema import Schema


__all__ = ('Connection',)

log = logging.getLogger(__name__)

LDAPObject: TypeAlias = ldap.ldapobject.SimpleLDAPObject
LDAPAddList: TypeAlias = list[tuple[str, list[bytes]]]
LDAPModList: TypeAlias = list[tuple[int, str, list[bytes] | None]]


class Connection:
    """
    A LDAP Connection.

    :ivar str uri: The LDAP URI.
    :ivar int timelimit: The global timelimit.
    :ivar bool automatic_reconnect: Wheather automatic reconnection is enabled.
    :ivar int max_connection_attempts: number of connection attempt on connection loss.
    :ivar float retry_delay: The retry delay (in seconds) between the reconnection attempts.
    """

    __slots__ = (
        '__conn_s',
        '__reconnects_counter',
        '__schema',
        '_conn',
        '_hide_parent_exception',
        '_last_auth_state',
        '_options',
        '_start_tls',
        'automatic_reconnect',
        'max_connection_attempts',
        'retry_delay',
        'timeout',
        'uri',
    )

    @property
    def conn(self) -> LDAPObject:
        """The underlying connection."""
        if self._conn is None:
            raise RuntimeError('not connected')  # noqa: TRY003
        return self._conn

    @property
    def fileno(self):
        """Get the file descriptor number of the active socket connection."""
        if not self._conn or not hasattr(self._conn, '_l'):
            return -1
        return self._conn.fileno()

    @property
    def connected(self) -> bool:
        """Wheather the connection is established."""
        return self.fileno != -1

    def __init__(
        self,
        uri: str = '',
        *,
        start_tls: bool = False,
        timeout: int = -1,
        automatic_reconnect: bool = True,
        max_connection_attempts: int = 10,
        retry_delay: float = 0.0,
        _hide_parent_exception: bool = True,
        _conn: LDAPObject = None,
    ):
        self._conn = _conn
        self.uri = uri
        self.timeout = timeout
        self.automatic_reconnect = automatic_reconnect
        self.max_connection_attempts = max_connection_attempts
        self.retry_delay = retry_delay
        self._start_tls = start_tls
        self.__reconnects_counter = 0
        self.__schema = {}
        self._last_auth_state = None
        self._options = []
        self._hide_parent_exception = _hide_parent_exception
        self.__conn_s = None

    def __enter__(self) -> Self:
        """Initialize asynchronous connection."""
        self.connect()
        return self

    def __exit__(self, etype, exc, etraceback) -> None:
        """Close connection on shutdown."""
        self.unbind()
        self.disconnect()

    def get_option(self, option: AnyOption) -> int:
        """Get a LDAP connection option."""
        with errors.LdapError.wrap(self._hide_parent_exception):
            return self.conn.get_option(option)

    def set_option(self, option: AnyOption, value: AnyOptionValue, *, append=True) -> None:
        """Set a LDAP connection option."""
        if append:
            self._options.append((option, value))
        with errors.LdapError.wrap(self._hide_parent_exception):
            return self.conn.set_option(option, value)

    @property
    def protocol_version(self) -> Version:
        """Get the LDAP protocol version."""
        return Version(self.get_option(Option.ProtocolVersion))

    @protocol_version.setter
    def protocol_version(self, value: Version):
        """Set the LDAP protocol version."""
        return self.set_option(Option.ProtocolVersion, value)

    @property
    def timelimit(self) -> int:
        """Get the LDAP time limit."""
        return self.get_option(Option.Timelimit)

    @timelimit.setter
    def timelimit(self, value: int):
        """Set the LDAP time limit."""
        return self.set_option(Option.Timelimit, value)

    @property
    def network_timeout(self) -> int:
        """Get the LDAP network timeout."""
        return self.get_option(Option.NetworkTimeout)

    @network_timeout.setter
    def network_timeout(self, value: int):
        """Set the LDAP network timeout."""
        return self.set_option(Option.NetworkTimeout, value)

    @property
    def dereference(self) -> int:
        """Get the de-reference setting."""
        return self.get_option(Option.Dereference)

    @dereference.setter
    def dereference(self, value: int):
        """Set the de-reference setting."""
        return self.set_option(Option.Dereference, value)

    @property
    def follow_referrals(self) -> bool | None:
        """Follow referrals enabled."""
        follow = self.get_option(Option.Referrals)
        if follow == -1:
            return None
        return follow == OptionValue.On

    @follow_referrals.setter
    def follow_referrals(self, value: bool):
        """Enable following of referrals."""
        return self.set_option(Option.Referrals, OptionValue.On if value else OptionValue.Off)

    @property
    def sizelimit(self) -> int:
        """Get the sizelimit setting."""
        return self.get_option(Option.Sizelimit)

    @sizelimit.setter
    def sizelimit(self, value: int):
        """Set the sizelimit setting."""
        return self.set_option(Option.Sizelimit, value)

    @classmethod
    def set_tls(cls, *, certfile: str | None = None, ca_certfile: str | None = None, require_cert: int = TLSOptionValue.Demand) -> None:
        """Set the TLS certificate settings globally."""
        cls.set_global_option(TLSOption.CACertfile, ca_certfile)
        cls.set_global_option(TLSOption.RequireCert, require_cert)
        if certfile:  # pragma: no cover
            cls.set_global_option(TLSOption.Certfile, certfile)
        # instruct to apply the pending TLS settings, create new context:
        cls.set_global_option(TLSOption.NewContext, 0)

    @classmethod
    def get_global_option(cls, option: AnyOption) -> int:
        """Get a LDAP connection option."""
        return ldap.get_option(option)

    @classmethod
    def set_global_option(cls, option: AnyOption, value: AnyOptionValue) -> None:
        """Set a global LDAP option."""
        ldap.set_option(option, value)

    def connect(self, fileno: bool | None = None) -> None:
        """Connect to the LDAP server."""
        if self.connected:
            raise RuntimeError('already connected')  # noqa: TRY003

        if self.automatic_reconnect:
            self._conn = ldap.ldapobject.ReconnectLDAPObject(
                self.uri,
                trace_level=0,
                trace_file=None,
                trace_stack_limit=None,
                fileno=fileno,
                retry_max=self.max_connection_attempts,
                retry_delay=self.retry_delay,
            )
        else:
            self._conn = ldap.ldapobject.SimpleLDAPObject(
                self.uri,
                trace_level=0,
                trace_file=None,
                trace_stack_limit=None,
                fileno=fileno,
            )
        self.__conn_s = None
        self.__reconnects_counter = 0
        if self._start_tls:
            self.start_tls()

    def disconnect(self) -> None:
        """Disconnect from LDAP server."""
        self._conn = None
        self.__conn_s = None

    def reconnect(self, *, force: bool = True) -> None:
        """Reconnect to the LDAP server."""
        with errors.LdapError.wrap(self._hide_parent_exception):
            self.conn.reconnect(self.uri, self.max_connection_attempts, self.retry_delay, force=force)
            # if self._start_tls:
            #     self.start_tls()
            self._restore_options()
            self._restore_auth_state()

    def start_tls(self) -> None:
        """Start TLS."""
        self._start_tls = True
        with errors.LdapError.wrap(self._hide_parent_exception):
            self.conn.start_tls_s()

    def get_schema(self, subschema_dn: DN | str | None = None) -> ldap.schema.subentry.SubSchema:
        """Get LDAP Schema."""
        conn = self.conn
        # cache schema by connection
        if isinstance(conn, ldap.ldapobject.ReconnectLDAPObject) and conn._reconnects_done > self.__reconnects_counter:
            self.__schema[subschema_dn] = None
            self.__reconnects_counter = self.conn._reconnects_done

        if not self.__schema.get(subschema_dn):
            try:
                subschemasubentry = self.get(subschema_dn, attrs=['subschemaSubentry']) if subschema_dn else self.get_root_dse(['subschemaSubentry'])
                try:
                    subschemasubentry_dn = subschemasubentry.attr['subschemaSubentry'][0].decode('UTF-8')
                except KeyError:  # pragma: no cover; impossible?
                    if subschema_dn:
                        return self.get_schema()
                    subschema = None
            except (errors.NoSuchObject, errors.NoSuchAttribute, errors.InsufficientAccess, errors.UndefinedType):
                subschema = None
            else:
                try:
                    subschema = (self.get(subschemasubentry_dn, SCHEMA_ATTRS, '(objectClass=subschema)')).attr
                except errors.NoSuchObject:  # pragma: no cover
                    subschema = None
            self.__schema[subschema_dn] = Schema(ldap.schema.SubSchema(subschema, 0))
            Attributes.set_schema(self.__schema[subschema_dn])
        return self.__schema[subschema_dn]

    def bind(self, authzid: str | None, password: str | None, *, controls: Controls | None = None) -> None:
        """Authenticate via plaintext credentials."""
        conn = self.conn
        self._last_auth_state = ('simple_bind_s', authzid, password)
        response = self._execute(conn, conn.simple_bind, authzid, password, **Controls.expand(controls))
        return Result.from_response(None, None, controls, response)

    def bind_external(self):  # pragma: no cover
        """Authenticate via EXTERNAL method e.g. UNIX socket or TLS client certificate."""
        with errors.LdapError.wrap(self._hide_parent_exception):
            self.conn.sasl_interactive_bind_s('', ldap.sasl.external())

    def bind_sasl_gssapi(self) -> None:  # pragma: no cover
        """Authenticate via GSSAPI e.g. via Kerberos ticket."""
        with errors.LdapError.wrap(self._hide_parent_exception):
            self.conn.sasl_interactive_bind_s('', ldap.sasl.gssapi())

    def bind_oauthbearer(self, authzid, token) -> None:  # pragma: no cover; requires SASL module
        """Authenticate via OAuth 2.0 Access Token."""
        oauth = ldap.sasl.sasl(
            {
                ldap.sasl.CB_AUTHNAME: authzid,
                ldap.sasl.CB_PASS: token,
            },
            'OAUTHBEARER',
        )
        with errors.LdapError.wrap(self._hide_parent_exception):
            self.conn.sasl_interactive_bind_s('', oauth)

    def _restore_options(self) -> None:
        for option, value in self._options:
            self.set_option(option, value, append=False)

    def _restore_auth_state(self) -> None:
        if self._last_auth_state:
            with errors.LdapError.wrap(self._hide_parent_exception):
                getattr(self.conn, self._last_auth_state[0])(*self._last_auth_state[1:])

    def unbind(self, *, controls: Controls | None = None) -> Result:
        """Unbind."""
        self._last_auth_state = None
        try:
            conn = self.conn
        except RuntimeError:  # not connected
            return None
        try:
            response = self._execute(conn, conn.unbind_ext, **Controls.expand(controls))
        except AttributeError as exc:  # duplicated unbind
            if exc.args and exc.args[0] == "ReconnectLDAPObject has no attribute '_l'":
                return None
            raise  # pragma: no cover; not possible
        return Result.from_response(None, None, controls, response)

    def whoami(self, *, controls: Controls | None = None) -> DN | str:
        """Get authenticated user DN (authzid). "Who am I?" Operation."""
        try:
            with errors.LdapError.wrap(self._hide_parent_exception):
                dn = self.conn.whoami_s(**Controls.expand(controls))
        except RuntimeError:
            return None
        if dn.startswith('dn:'):
            return DN(dn.removeprefix('dn:'))
        return dn  # pragma: no cover

    def change_password(self, dn: DN | str, old_password: str, new_password: str, *, controls: Controls | None = None) -> Result:
        """Change password."""
        conn = self.conn
        response = self._execute(conn, conn.passwd, str(dn), old_password, new_password, **Controls.expand(controls))
        return Result.from_response(dn, None, controls, response)  # pragma: no cover

    def exists(self, dn: DN | str, unique: bool = False, *, controls: Controls | None = None) -> bool:
        """Check if LDAP object exists."""
        try:
            self.get(dn, ['1.1'], unique=unique, controls=controls)
        except errors.NoSuchObject:
            return False
        return True

    def get(self, dn: DN | str, attrs=None, filter_expr='(objectClass=*)', *, unique: bool = False, controls: Controls | None = None) -> Result:
        """Get a LDAP object."""
        for obj in self.search(base=dn, scope=Scope.BASE, filter_expr=filter_expr, attrs=attrs, unique=unique, controls=controls):
            return obj
        return None  # pragma: no cover; impossible
        # obj, = [_ for _ in self.search_iter(base=dn, scope=Scope.BASE, filter_expr=filter_expr, attrs=attrs, unique=unique, controls=controls)]  # noqa: E501
        # return obj[0]
        # # GC calls gen.aclose() causing unnecessary .cancel() to be called:
        # # return next(self.search_iter(base=dn, scope=Scope.BASE, filter_expr=filter_expr, attrs=attrs, unique=unique, controls=controls))

    def get_attr(self, dn, attr, filter_expr='(objectClass=*)', *, unique: bool = False, controls: Controls | None = None) -> list[bytes]:
        """Get attribute of an LDAP object."""
        attributes = (self.get(dn, attrs=[attr], filter_expr=filter_expr, unique=unique, controls=controls)).attr
        try:
            return attributes[attr]
        except KeyError:
            self.get_schema()
            return attributes[attr]

    def search_iter(
        self,
        base: DN | str = '',
        scope: Scope = Scope.SUBTREE,
        filter_expr: str = '(objectClass=*)',
        attrs: list[str] | None = None,
        *,
        unique: bool = False,
        sizelimit: bool | None = None,
        controls: Controls | None = None,
        _attrsonly: bool = False,
    ) -> AsyncGenerator[Result, None]:
        """Search iterative for DN and Attributes of LDAP objects."""
        conn = self.conn
        all_results = []
        # sizelimit = 1 if unique else sizelimit
        try:
            for response in self._execute_iter(
                conn,
                conn.search_ext,
                str(base),
                scope,
                filterstr=filter_expr,
                attrlist=attrs,
                attrsonly=int(_attrsonly),
                **Controls.expand(controls),
                timeout=self.timeout,
                sizelimit=sizelimit or OptionValue.NoLimit,
            ):
                Result.set_controls(response, controls)
                results = [Result.from_response(dn, attributes, controls, response) for dn, attributes in response.data]
                all_results.extend(results)
                if unique and len(all_results) > 1:
                    raise errors.NotUnique(all_results)
                try:
                    yield from results
                except GeneratorExit as exc:
                    with contextlib.suppress(errors.NoSuchOperation):
                        # self.cancel(response.msgid)  # better do it immediately
                        self.cancel(response.msgid)
                    raise exc from exc
        except errors.NoSuchObject as no_object_error:
            no_object_error.base_dn = DN.get(base)
            no_object_error.filter = filter_expr
            no_object_error.scope = scope
            no_object_error.attrs = attrs
            raise
        # except errors.SizelimitExceeded:
        #     if not unique:
        #         raise
        #     raise errors.NotUnique() from None

    def search(
        self,
        base: DN | str = '',
        scope: Scope = Scope.SUBTREE,
        filter_expr: str = '(objectClass=*)',
        attrs: list[str] | None = None,
        *,
        unique: bool = False,
        sizelimit: bool | None = None,
        controls: Controls | None = None,
        _attrsonly: bool = False,
    ) -> AsyncGenerator[Result, None]:
        """Search for DN and Attributes of LDAP objects."""
        conn = self.conn
        all_results = []
        try:
            response = self._execute(
                conn,
                conn.search_ext,
                str(base),
                scope,
                filterstr=filter_expr,
                attrlist=attrs,
                attrsonly=int(_attrsonly),
                **Controls.expand(controls),
                timeout=self.timeout,
                sizelimit=sizelimit or OptionValue.NoLimit,
            )
            Result.set_controls(response, controls)
            results = [Result.from_response(dn, attributes, controls, response) for dn, attributes in response.data]
            all_results.extend(results)
            if unique and len(all_results) > 1:
                raise errors.NotUnique(all_results)
        except errors.NoSuchObject as no_object_error:
            no_object_error.base_dn = DN.get(base)
            no_object_error.filter = filter_expr
            no_object_error.scope = scope
            no_object_error.attrs = attrs
            raise
        return results

    def search_dn(
        self,
        base: DN | str = '',
        scope: Scope = Scope.SUBTREE,
        filter_expr: str = '(objectClass=*)',
        *,
        unique: bool = False,
        sizelimit: bool | None = None,
        controls: Controls | None = None,
    ) -> AsyncGenerator[DN, None]:
        """Search for DNs of LDAP objects."""
        # FIXME: the following hangs forever as the iterative search is unfinished while the FD reader is replaced
        # for result in self.search(base, scope, filter_expr, ['1.1'], unique=unique, sizelimit=sizelimit, controls=controls, _attrsonly=True):
        for result in self.search(base, scope, filter_expr, [], unique=unique, sizelimit=sizelimit, controls=controls, _attrsonly=True):
            yield result.dn

    def search_paginated(
        self,
        base: DN | str = '',
        scope: Scope = Scope.SUBTREE,
        filter_expr: str = '(objectClass=*)',
        attrs: list[str] | None = None,
        page_size: int = 100,
        *,
        unique: bool = False,
        sizelimit: bool | None = None,
        controls: Controls | None = None,
    ) -> AsyncGenerator[Result, None]:
        """Search paginated using SimplePagedResults control."""
        pagination = simple_paged_results(criticality=True, size=page_size, cookie='')
        controls = Controls.append_server(controls, pagination)
        page = 0
        while True:
            current = None
            page += 1
            entry_number = 0
            for result in self.search_iter(base, scope, filter_expr, attrs, unique=unique, sizelimit=sizelimit, controls=controls):
                entry_number += 1  # noqa: SIM113
                result.page = SimplePage(page=page, entry=entry_number, page_size=page_size)
                current = result
                yield result

            if current is None:  # no search results
                break
            control = controls.get(pagination)
            if not control:  # pragma: no cover
                break  # Server doesn't support pagination

            pagination.cookie = controls.get(pagination).cookie
            if not pagination.cookie:
                break

    def add(
        self,
        dn: DN | str,
        attrs: dict | Attributes,
        *,
        controls: Controls | None = None,
    ) -> Result:
        """Create a LDAP object."""
        al = ldap.modlist.addModlist(attrs)
        return self.add_al(dn, al, controls=controls)

    def add_al(
        self,
        dn: DN | str,
        al: LDAPAddList,
        *,
        controls: Controls | None = None,
    ) -> Result:
        """Create a LDAP object from addlist."""
        conn = self.conn
        response = self._execute(conn, conn.add_ext, str(dn), al, **Controls.expand(controls))
        return Result.from_response(dn, None, controls, response)

    def modify(
        self,
        dn: DN | str,
        oldattr: dict | Attributes,
        newattr: dict | Attributes,
        *,
        controls: Controls | None = None,
    ) -> Result:
        """Modify a LDAP object."""
        ml = ldap.modlist.modifyModlist(oldattr, newattr)
        return self.modify_ml(dn, ml, controls=controls)

    def modify_ml(
        self,
        dn: DN | str,
        ml: LDAPModList,
        *,
        controls: Controls | None = None,
    ) -> Result:
        """Modify a LDAP object from modlist."""
        conn = self.conn
        new_dn = self._compute_changed_dn(DN(dn), ml)
        if dn != new_dn:
            dn = (self.rename(dn, new_dn)).dn
        response = self._execute(conn, conn.modify_ext, str(dn), ml, **Controls.expand(controls))
        return Result.from_response(dn, None, controls, response)

    @classmethod
    def _compute_changed_dn(cls, dn: DN, ml: list[tuple[int, str, list[bytes] | None]]) -> DN:
        """
        Get changed DN.

        >>> Connection._compute_changed_dn('cn=foo,dc=bar', [(ldap.MOD_REPLACE, 'cn', b'foo')])
        'cn=foo,dc=bar'
        >>> Connection._compute_changed_dn('cn=foo,dc=bar', [(ldap.MOD_REPLACE, 'cn', b'bar')])
        'cn=bar,dc=bar'
        >>> Connection._compute_changed_dn('cn=foo,dc=bar', [(ldap.MOD_REPLACE, 'cn', b'föo')]) == 'cn=föo,dc=bar'
        True
        """
        rdn = dn.rdns[0]
        dn_vals = {x[0].lower(): x[1] for x in rdn}
        new_vals = {
            key.lower(): val.decode('UTF-8') if isinstance(val, bytes) else val[0].decode('UTF-8')
            for op, key, val in ml
            if key.lower() in dn_vals and val and op != ldap.MOD_DELETE
        }
        new_rdn_ava = [(x, new_vals.get(x.lower(), dn_vals[x.lower()]), ldap.AVA_STRING) for x in [y[0] for y in rdn]]
        new_rdn = DN(
            ldap.dn.dn2str(
                [
                    [(key, val, ava_type) for key, val, ava_type in new_rdn_ava],
                ],
            ),
        )
        if dn[0] != new_rdn:
            return new_rdn + dn.parent
        return dn

    def move(
        self,
        dn: DN | str,
        newposition: DN | str,
        *,
        controls: Controls | None = None,
    ) -> Result:
        """Move a LDAP object."""
        dn = DN.get(dn)
        newposition = DN.get(newposition)
        return self.rename(dn, dn[0] + newposition, delete_old=True, controls=controls)

    def rename(
        self,
        dn: DN | str,
        newdn: DN | str,
        delete_old: bool = True,
        *,
        controls: Controls | None = None,
    ) -> Result:
        """Rename a LDAP object."""
        conn = self.conn
        newdn = DN.get(newdn)
        response = self._execute(conn, conn.rename, str(dn), str(newdn[0]), str(newdn.parent), int(delete_old), **Controls.expand(controls))
        return Result.from_response(newdn, None, controls, response)

    def modrdn(
        self,
        dn: DN | str,
        newrdn: DN | str,
        delete_old: bool = True,
        *,
        controls: Controls | None = None,
    ) -> Result:
        """Rename a LDAP object."""
        return self.rename(dn, DN.get(newrdn) + DN.get(dn).parent, delete_old, controls=controls)

    def delete(self, dn: DN | str, *, controls: Controls | None = None) -> Result:
        """Delete a LDAP object."""
        conn = self.conn
        response = self._execute(conn, conn.delete_ext, str(dn), **Controls.expand(controls))
        return Result.from_response(dn, None, controls, response)

    def delete_recursive(self, dn: DN | str, *, controls: Controls | None = None) -> Result:
        """Delete a LDAP object recursively."""
        try:
            return self.delete(dn, controls=controls)
        except errors.NotAllowedOnNonleaf:
            for child in self.search_dn(dn, Scope.ONELEVEL):
                self.delete_recursive(child)
        return self.delete(dn, controls=controls)

    def compare(
        self,
        dn: DN | str,
        attr: str,
        value: bytes,
        *,
        controls: Controls | None = None,
    ) -> bool:
        """Compare the value of an LDAP object."""
        conn = self.conn
        try:
            self._execute(conn, conn.compare_ext, str(dn), attr, value, **Controls.expand(controls))
        except errors.NoSuchObject as no_object_error:
            no_object_error.base_dn = DN.get(dn)
            raise
        except errors.CompareTrue:
            return True
        except errors.CompareFalse:
            return False
        raise RuntimeError()  # pragma: no cover; impossible

    def compare_dn(self, entry: DN | str, dn: DN | str) -> bool:
        """Compare LDAP DN with existing entry."""
        dn = DN.get(dn)
        entry = DN.get(entry)

        for i, parent in enumerate(entry.walk()):
            for attr, value, _ in dn.rdns[-i - 1]:
                try:
                    equal = self.compare(str(parent), attr, value)
                    if not equal:  # pragma: no cover; https://github.com/nedbat/coveragepy/issues/2014
                        return False
                except errors.NoSuchObject:
                    if attr == entry.rdns[-1][0][0]:
                        continue
                    raise
        return True

    def get_root_dse(self, attrs: list[str] | None = None, filter_expr: str = '(objectClass=*)') -> Result:
        """Get Root DSE (Directory Server Entry)."""
        return self.get('', attrs or ['*', '+'], filter_expr=filter_expr)

    def get_naming_contexts(self) -> list[str]:
        """Return namingContexts of Root DSE."""
        result = self.get_attr('', 'namingContexts')
        return [x.decode('UTF-8') for x in result]

    def abandon(self, msgid: int, *, controls: Controls | None = None) -> Result:
        """Abandon a LDAP operation."""
        log.debug('Abandon: %s', msgid)
        conn = self.conn
        response = self._execute(conn, conn.abandon_ext, msgid, **Controls.expand(controls))
        return Result.from_response(None, None, controls, response)

    def cancel(self, msgid: int, *, controls: Controls | None = None) -> bool:
        """Cancel a LDAP operation."""
        log.debug('Cancel: %s', msgid)
        try:
            conn = self.conn
        except RuntimeError:
            return False
        try:
            self._execute(conn, conn.cancel, msgid, **Controls.expand(controls))
        except errors.NoSuchOperation:
            log.warning('Cancel failed', extra={'msgid': msgid})
            raise
        except (errors.Cancelled, errors.Success):  # pragma: no cover; theoretically, according to python-ldap
            return True
        except errors.TooLate:  # pragma: no cover
            return False
        else:  # pragma: no cover
            return True

    def extop(self, extreq: ldap.extop.ExtendedRequest, extop_resp_class=None, *, controls: Controls | None = None) -> Result | Any:
        """Perform extended operation."""
        conn = self.conn
        response = self._execute(conn, conn.extop, extreq, **Controls.expand(controls))

        if extop_resp_class:  # pragma: no cover
            return extop_resp_class(response.name, response.value)
        return Result.from_response(None, None, controls, response)  # pragma: no cover

    def __getstate__(self) -> dict:
        """Return state for pickle."""
        return {slot: getattr(self, slot) for slot in set(self.__slots__) - {'_conn'} | {'connected'} if not slot.startswith('__')}

    def __setstate__(self, state: dict) -> None:
        """Set state for pickle."""
        self._conn = None
        connected = state.pop('connected', None)
        for slot, value in state.items():
            setattr(self, slot, value)
        if connected:
            self.connect()
            self._restore_options()
        self._restore_auth_state()

    def _execute(self, conn: LDAPObject, operation: Callable, *args: Any, **kwargs: Any) -> _Response:
        """Execute the operation and wait asynchronously for the result."""
        msgid = self._retry(self.request, operation, *args, **kwargs)
        if msgid is None:  # abandon_ext, unbind_ext
            return _Response(None, None, msgid, [], None, None)
        response = None
        for resp in self._poll(conn, msgid, 1):
            if response is not None:  # pragma: no cover
                raise RuntimeError('Wrong method used! Use _execute_iter instead!')  # noqa: TRY003
            response = resp
        return response

    def _execute_iter(self, conn: LDAPObject, operation: Callable, *args: Any, **kwargs: Any) -> AsyncGenerator[_Response, None]:
        """Execute the operation and yield the results asynchronously."""
        msgid = self._retry(self.request, operation, *args, **kwargs)
        if msgid is None:  # abandon_ext, unbind_ext
            return
        yield from self._poll(conn, msgid, 0)

    def get_result(self, conn: LDAPObject, msgid: ResponseType = ResponseType.Any, _all: int = 0, timeout: int = 0) -> _Response:
        """Get the LDAP result for the given msgid."""
        log.debug('result(%r, timeout=%r)', msgid, timeout, extra={'MSGID': msgid, 'ALL': _all, 'TIMEOUT': timeout, 'FUNC': 'result'})
        try:
            with errors.LdapError.wrap(self._hide_parent_exception):
                response = _Response(*conn.result4(msgid, all=_all, timeout=timeout))
        except (errors.LdapError, OSError) as exc:
            log.debug('result(%r) -> raised %r', msgid, exc, extra={'MSGID': msgid, 'OPERATION': 'result', 'EXCEPTION': str(exc)})
            raise
        log.debug('result(%r) -> %s', msgid, repr(response)[:200], extra={'MSGID': msgid, 'OPERATION': 'result'})
        return response

    def request(self, operation: Callable, *args: Any, **kwargs: Any) -> int | None:
        """Make the LDAP request for the given operation."""
        op = operation.__name__
        arg_str = ', '.join(map(repr, args)) if 'bind' not in op else ''
        kw = ', '.join(f'{k}={v!r}' for k, v in kwargs.items()) if 'bind' not in op else ''
        log.debug('Request %s(%s%s%s)', op, arg_str, ', ' if kw else '', kw, extra={'OPERATION': op, 'ARGUMENTS': arg_str, 'KEYWORDS': kw})
        try:
            with errors.LdapError.wrap(self._hide_parent_exception):
                msgid = operation(*args, **kwargs)
        except (errors.LdapError, OSError) as exc:
            log.debug('%s() -> %r', op, exc, extra={'OPERATION': op, 'EXCEPTION': str(exc)})
            raise
        log.debug('%s() -> %r', op, msgid, extra={'OPERATION': op, 'MSGID': msgid})
        return msgid

    def _retry(self, func: Callable, *args: Any, **kwargs: Any) -> Any:
        """Retry operation or reconnect if necessary."""
        max_attempts = attempts = self.max_connection_attempts
        while attempts:
            try:
                if attempts != max_attempts:
                    # do a sync reconnect, make sure we don't end in recursion
                    self.reconnect()  # FIXME: recursion!?
                    # self.conn.reconnect(self.uri)
                    # self._restore_auth_state()  # FIXME: recursion

                return func(*args, **kwargs)
            except (errors.ServerDown, errors.Unavailable, errors.ConnectError, errors.Timeout):
                attempts -= 1
                if not attempts:
                    raise
                time.sleep(self.retry_delay)
        raise RuntimeError()  # pragma: no cover; impossible

    def _poll(self, conn: LDAPObject, msgid: ResponseType = ResponseType.Any, _all: int = 0) -> Generator[_Response, None]:  # pragma: no cover
        """Wait synchronously for operation to succeed."""
        # this method must only used by the synchronous variant of this class
        while True:
            try:
                response = self._retry(self.get_result, conn, msgid, _all=_all, timeout=self.timeout)
            except errors.NoResultsReturned:  # pragma: no cover
                break

            rtype = response.type
            if rtype is None:
                continue

            yield response
            if rtype == ldap.RES_SEARCH_ENTRY:
                continue
            if rtype == ldap.RES_SEARCH_RESULT:
                break
            break
