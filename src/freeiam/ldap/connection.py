# SPDX-FileCopyrightText: 2025 Florian Best
# SPDX-License-Identifier: MIT OR Apache-2.0
"""LDAP Connection."""

import asyncio
import contextlib
import logging
import os
from collections.abc import AsyncGenerator, Callable, Generator
from typing import Any, Self, TypeAlias

import ldap.ldapobject
import ldap.modlist
import ldap.sasl
from ldap.controls import SimplePagedResultsControl
from ldap.schema import SCHEMA_ATTRS

from freeiam import errors
from freeiam.ldap._wrapper import Result, _Response
from freeiam.ldap.attr import Attributes
from freeiam.ldap.constants import AnyOption, AnyOptionValue, Option, OptionValue, ResponseType, Scope, TLSOption, TLSOptionValue, Version
from freeiam.ldap.dn import DN
from freeiam.ldap.schema import Schema
from freeiam.ldap.sync_connection import Connection as SynchronousConnection


__all__ = ('Connection',)

log = logging.getLogger(__name__)

LDAPControlList: TypeAlias = list[ldap.controls.LDAPControl]
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

    @property
    def _sync_connection(self):
        if self.__conn_s is None:
            self.__conn_s = SynchronousConnection(
                self.uri,
                # start_tls=self._start_tls,
                timeout=self.timeout,
                automatic_reconnect=self.automatic_reconnect,
                max_connection_attempts=self.max_connection_attempts,
                retry_delay=self.retry_delay,
                _hide_parent_exception=self._hide_parent_exception,
                _conn=self._conn,
            )
        return self.__conn_s

    async def __aenter__(self) -> Self:
        """Initialize asynchronous connection."""
        self.connect()
        return self

    async def __aexit__(self, etype, exc, etraceback) -> None:
        """Close connection on shutdown."""
        await self.unbind()
        self.disconnect()

    def __enter__(self) -> SynchronousConnection:
        """Initialize synchronous connection."""
        return self._sync_connection.__enter__()

    def __exit__(self, etype, exc, etraceback) -> None:
        """Close connection on shutdown."""
        self._sync_connection.__exit__(etype, exc, etraceback)
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
        self._remove_reader()
        self._conn = None
        self.__conn_s = None

    def reconnect(self, *, force: bool = True) -> None:
        """Reconnect to the LDAP server."""
        self._remove_reader()
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

    async def get_schema(self, subschema_dn: DN | str | None = None) -> ldap.schema.subentry.SubSchema:
        """Get LDAP Schema."""
        conn = self.conn
        # cache schema by connection
        if isinstance(conn, ldap.ldapobject.ReconnectLDAPObject) and conn._reconnects_done > self.__reconnects_counter:
            self.__schema[subschema_dn] = None
            self.__reconnects_counter = self.conn._reconnects_done

        if not self.__schema.get(subschema_dn):
            try:
                subschemasubentry = await (
                    self.get(subschema_dn, attrs=['subschemaSubentry']) if subschema_dn else self.get_root_dse(['subschemaSubentry'])
                )
                try:
                    subschemasubentry_dn = subschemasubentry.attr['subschemaSubentry'][0].decode('UTF-8')
                except KeyError:  # pragma: no cover; impossible?
                    if subschema_dn:
                        return await self.get_schema()
                    subschema = None
            except (errors.NoSuchObject, errors.NoSuchAttribute, errors.InsufficientAccess, errors.UndefinedType):
                subschema = None
            else:
                try:
                    subschema = (await self.get(subschemasubentry_dn, SCHEMA_ATTRS, '(objectClass=subschema)')).attr
                except errors.NoSuchObject:  # pragma: no cover
                    subschema = None
            self.__schema[subschema_dn] = Schema(ldap.schema.SubSchema(subschema, 0))
            Attributes.set_schema(self.__schema[subschema_dn])
        return self.__schema[subschema_dn]

    async def bind(self, authzid: str | None, password: str | None, *, controls: LDAPControlList | None = None) -> None:
        """Authenticate via plaintext credentials."""
        conn = self.conn
        self._last_auth_state = ('simple_bind_s', authzid, password)
        response = await self._execute(conn, conn.simple_bind, authzid, password, controls)
        return Result(None, None, response.ctrls, response)

    async def bind_external(self):  # pragma: no cover
        """Authenticate via EXTERNAL method e.g. UNIX socket or TLS client certificate."""
        with errors.LdapError.wrap(self._hide_parent_exception):
            self.conn.sasl_interactive_bind_s('', ldap.sasl.external())

    async def bind_sasl_gssapi(self) -> None:  # pragma: no cover
        """Authenticate via GSSAPI e.g. via Kerberos ticket."""
        with errors.LdapError.wrap(self._hide_parent_exception):
            self.conn.sasl_interactive_bind_s('', ldap.sasl.gssapi())

    async def bind_oauthbearer(self, authzid, token) -> None:  # pragma: no cover; requires SASL module
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

    async def unbind(self, *, controls: LDAPControlList | None = None) -> Result:
        """Unbind."""
        self._last_auth_state = None
        try:
            conn = self.conn
        except RuntimeError:  # not connected
            return None
        try:
            response = await self._execute(conn, conn.unbind_ext, controls)
        except AttributeError as exc:  # duplicated unbind
            if exc.args and exc.args[0] == "ReconnectLDAPObject has no attribute '_l'":
                return None
            raise  # pragma: no cover; not possible
        return Result(None, None, response.ctrls, response)

    async def whoami(self, *, controls: LDAPControlList | None = None) -> DN | str:
        """Get authenticated user DN (authzid). "Who am I?" Operation."""
        try:
            with errors.LdapError.wrap(self._hide_parent_exception):
                dn = self.conn.whoami_s(controls)
        except RuntimeError:
            return None
        if dn.startswith('dn:'):
            return DN(dn.removeprefix('dn:'))
        return dn  # pragma: no cover

    async def change_password(self, dn: DN | str, old_password: str, new_password: str, *, controls: LDAPControlList | None = None) -> Result:
        """Change password."""
        conn = self.conn
        response = await self._execute(conn, conn.passwd, str(dn), old_password, new_password, controls)
        return Result(DN.get(dn), None, response.ctrls, response)  # pragma: no cover

    async def exists(self, dn: DN | str, unique: bool = False, *, controls: LDAPControlList | None = None) -> bool:
        """Check if LDAP object exists."""
        try:
            await self.get(dn, ['1.1'], unique=unique, controls=controls)
        except errors.NoSuchObject:
            return False
        return True

    async def get(
        self, dn: DN | str, attrs=None, filter_expr='(objectClass=*)', *, unique: bool = False, controls: LDAPControlList | None = None
    ) -> Result:
        """Get a LDAP object."""
        for obj in await self.search(base=dn, scope=Scope.BASE, filter_expr=filter_expr, attrs=attrs, unique=unique, controls=controls):
            return obj
        return None  # pragma: no cover; impossible
        # obj, = [_ async for _ in self.search_iter(base=dn, scope=Scope.BASE, filter_expr=filter_expr, attrs=attrs, unique=unique, controls=controls)]  # noqa: E501
        # return obj[0]
        # # GC calls gen.aclose() causing unnecessary .cancel() to be called:
        # # return await anext(self.search_iter(base=dn, scope=Scope.BASE, filter_expr=filter_expr, attrs=attrs, unique=unique, controls=controls))

    async def get_attr(
        self, dn, attr, filter_expr='(objectClass=*)', *, unique: bool = False, controls: LDAPControlList | None = None
    ) -> list[bytes]:
        """Get attribute of an LDAP object."""
        attributes = (await self.get(dn, attrs=[attr], filter_expr=filter_expr, unique=unique, controls=controls)).attr
        try:
            return attributes[attr]
        except KeyError:
            await self.get_schema()
            return attributes[attr]

    async def search_iter(
        self,
        base: DN | str = '',
        scope: Scope = Scope.SUBTREE,
        filter_expr: str = '(objectClass=*)',
        attrs: list[str] | None = None,
        *,
        unique: bool = False,
        sizelimit: bool | None = None,
        controls: LDAPControlList | None = None,
        _attrsonly: bool = False,
    ) -> AsyncGenerator[Result, None]:
        """Search iterative for DN and Attributes of LDAP objects."""
        conn = self.conn
        all_results = []
        # sizelimit = 1 if unique else sizelimit
        try:
            async for response in self._execute_iter(
                conn,
                conn.search_ext,
                str(base),
                scope,
                filterstr=filter_expr,
                attrlist=attrs,
                attrsonly=int(_attrsonly),
                serverctrls=controls,
                clientctrls=None,
                timeout=self.timeout,
                sizelimit=sizelimit or OptionValue.NoLimit,
            ):
                results = [Result(DN(dn), Attributes(attributes), response.ctrls, response) for dn, attributes in response.data]
                all_results.extend(results)
                if unique and len(all_results) > 1:
                    raise errors.NotUnique(all_results)
                try:
                    for result in results:
                        yield result
                    if response.ctrls:
                        yield Result(None, None, response.ctrls, response)
                except GeneratorExit as exc:
                    with contextlib.suppress(errors.NoSuchOperation):
                        # await self.cancel(response.msgid)  # better do it immediately
                        self._sync_connection.cancel(response.msgid)
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

    async def search(
        self,
        base: DN | str = '',
        scope: Scope = Scope.SUBTREE,
        filter_expr: str = '(objectClass=*)',
        attrs: list[str] | None = None,
        *,
        unique: bool = False,
        sizelimit: bool | None = None,
        controls: LDAPControlList | None = None,
        _attrsonly: bool = False,
    ) -> AsyncGenerator[Result, None]:
        """Search for DN and Attributes of LDAP objects."""
        conn = self.conn
        all_results = []
        try:
            response = await self._execute(
                conn,
                conn.search_ext,
                str(base),
                scope,
                filterstr=filter_expr,
                attrlist=attrs,
                attrsonly=int(_attrsonly),
                serverctrls=controls,
                clientctrls=None,
                timeout=self.timeout,
                sizelimit=sizelimit or OptionValue.NoLimit,
            )
            results = [Result((dn), Attributes(attributes), response.ctrls, response) for dn, attributes in response.data]
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

    async def search_dn(
        self,
        base: DN | str = '',
        scope: Scope = Scope.SUBTREE,
        filter_expr: str = '(objectClass=*)',
        *,
        unique: bool = False,
        sizelimit: bool | None = None,
        controls: LDAPControlList | None = None,
    ) -> AsyncGenerator[DN, None]:
        """Search for DNs of LDAP objects."""
        # FIXME: the following hangs forever as the iterative search is unfinished while the FD reader is replaced
        # async for result in self.search(base, scope, filter_expr, ['1.1'], unique=unique, sizelimit=sizelimit, controls=controls, _attrsonly=True):
        for result in await self.search(base, scope, filter_expr, [], unique=unique, sizelimit=sizelimit, controls=controls, _attrsonly=True):
            yield result.dn

    async def search_paginated(
        self,
        base: DN | str = '',
        scope: Scope = Scope.SUBTREE,
        filter_expr: str = '(objectClass=*)',
        attrs: list[str] | None = None,
        page_size: int = 100,
        *,
        unique: bool = False,
        sizelimit: bool | None = None,
        controls: LDAPControlList | None = None,
    ) -> AsyncGenerator[Result, None]:
        """Search paginated using SimplePagedResults control."""
        pagination = SimplePagedResultsControl(criticality=True, size=page_size, cookie='')
        while True:
            last = None
            async for result in self.search_iter(
                base, scope, filter_expr, attrs, unique=unique, sizelimit=sizelimit, controls=[*(controls or []), pagination]
            ):
                last = result
                if result.dn is not None:
                    yield result

            if last is None:  # pragma: no cover
                break
            control = last.get_control(pagination)
            if not control:  # pragma: no cover
                break  # Server doesn't support pagination

            pagination.cookie = control.cookie
            if not pagination.cookie:
                break

    async def add(
        self,
        dn: DN | str,
        attrs: dict | Attributes,
        *,
        controls: LDAPControlList | None = None,
    ) -> Result:
        """Create a LDAP object."""
        al = ldap.modlist.addModlist(attrs)
        return await self.add_al(dn, al, controls=controls)

    async def add_al(
        self,
        dn: DN | str,
        al: LDAPAddList,
        *,
        controls: LDAPControlList | None = None,
    ) -> Result:
        """Create a LDAP object from addlist."""
        conn = self.conn
        response = await self._execute(conn, conn.add_ext, str(dn), al, controls)
        return Result(DN.get(dn), None, response.ctrls, response)

    async def modify(
        self,
        dn: DN | str,
        oldattr: dict | Attributes,
        newattr: dict | Attributes,
        *,
        controls: LDAPControlList | None = None,
    ) -> Result:
        """Modify a LDAP object."""
        ml = ldap.modlist.modifyModlist(oldattr, newattr)
        return await self.modify_ml(dn, ml, controls=controls)

    async def modify_ml(
        self,
        dn: DN | str,
        ml: LDAPModList,
        *,
        controls: LDAPControlList | None = None,
    ) -> Result:
        """Modify a LDAP object from modlist."""
        conn = self.conn
        new_dn = self._compute_changed_dn(DN(dn), ml)
        if dn != new_dn:
            dn = (await self.rename(dn, new_dn)).dn
        response = await self._execute(conn, conn.modify_ext, str(dn), ml, controls)
        return Result(DN.get(dn), None, response.ctrls, response)

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

    async def move(
        self,
        dn: DN | str,
        newposition: DN | str,
        *,
        controls: LDAPControlList | None = None,
    ) -> Result:
        """Move a LDAP object."""
        dn = DN.get(dn)
        newposition = DN.get(newposition)
        return await self.rename(dn, dn[0] + newposition, delete_old=True, controls=controls)

    async def rename(
        self,
        dn: DN | str,
        newdn: DN | str,
        delete_old: bool = True,
        *,
        controls: LDAPControlList | None = None,
    ) -> Result:
        """Rename a LDAP object."""
        conn = self.conn
        newdn = DN.get(newdn)
        response = await self._execute(conn, conn.rename, str(dn), str(newdn[0]), str(newdn.parent), int(delete_old), controls)
        return Result(newdn, None, response.ctrls, response)

    async def modrdn(
        self,
        dn: DN | str,
        newrdn: DN | str,
        delete_old: bool = True,
        *,
        controls: LDAPControlList | None = None,
    ) -> Result:
        """Rename a LDAP object."""
        return await self.rename(dn, DN.get(newrdn) + DN.get(dn).parent, delete_old, controls=controls)

    async def delete(self, dn: DN | str, *, controls: LDAPControlList | None = None) -> Result:
        """Delete a LDAP object."""
        conn = self.conn
        response = await self._execute(conn, conn.delete_ext, str(dn), controls)
        return Result(DN.get(dn), None, response.ctrls, response)

    async def delete_recursive(self, dn: DN | str, *, controls: LDAPControlList | None = None) -> Result:
        """Delete a LDAP object recursively."""
        try:
            return await self.delete(dn, controls=controls)
        except errors.NotAllowedOnNonleaf:
            async for child in self.search_dn(dn, Scope.ONELEVEL):
                await self.delete_recursive(child)
        return await self.delete(dn, controls=controls)

    async def compare(
        self,
        dn: DN | str,
        attr: str,
        value: bytes,
        *,
        controls: LDAPControlList | None = None,
    ) -> bool:
        """Compare the value of an LDAP object."""
        conn = self.conn
        try:
            await self._execute(conn, conn.compare_ext, str(dn), attr, value, controls)
        except errors.NoSuchObject as no_object_error:
            no_object_error.base_dn = DN.get(dn)
            raise
        except errors.CompareTrue:
            return True
        except errors.CompareFalse:
            return False
        raise RuntimeError()  # pragma: no cover; impossible

    async def compare_dn(self, entry: DN | str, dn: DN | str) -> bool:
        """Compare LDAP DN with existing entry."""
        dn = DN.get(dn)
        entry = DN.get(entry)

        for i, parent in enumerate(entry.walk()):
            for attr, value, _ in dn.rdns[-i - 1]:
                try:
                    equal = await self.compare(str(parent), attr, value)
                    if not equal:  # pragma: no cover; https://github.com/nedbat/coveragepy/issues/2014
                        return False
                except errors.NoSuchObject:
                    if attr == entry.rdns[-1][0][0]:
                        continue
                    raise
        return True

    async def get_root_dse(self, attrs: list[str] | None = None, filter_expr: str = '(objectClass=*)') -> Result:
        """Get Root DSE (Directory Server Entry)."""
        return await self.get('', attrs or ['*', '+'], filter_expr=filter_expr)

    async def get_naming_contexts(self) -> list[str]:
        """Return namingContexts of Root DSE."""
        result = await self.get_attr('', 'namingContexts')
        return [x.decode('UTF-8') for x in result]

    async def abandon(self, msgid: int, *, controls: LDAPControlList | None = None) -> Result:
        """Abandon a LDAP operation."""
        log.debug('Abandon: %s', msgid)
        conn = self.conn
        response = await self._execute(conn, conn.abandon_ext, msgid, controls)
        return Result(None, None, response.ctrls, response)

    async def cancel(self, msgid: int, *, controls: LDAPControlList | None = None) -> bool:
        """Cancel a LDAP operation."""
        log.debug('Cancel: %s', msgid)
        try:
            conn = self.conn
        except RuntimeError:
            return False
        try:
            await self._execute(conn, conn.cancel, msgid, controls)
        except errors.NoSuchOperation:
            log.warning('Cancel failed', extra={'msgid': msgid})
            raise
        except (errors.Cancelled, errors.Success):  # pragma: no cover; theoretically, according to python-ldap
            return True
        except errors.TooLate:  # pragma: no cover
            return False
        else:  # pragma: no cover
            return True

    async def extop(self, extreq: ldap.extop.ExtendedRequest, extop_resp_class=None, *, controls: LDAPControlList | None = None) -> Result | Any:
        """Perform extended operation."""
        conn = self.conn
        response = await self._execute(conn, conn.extop, extreq, controls)

        if extop_resp_class:  # pragma: no cover
            return extop_resp_class(response.name, response.value)
        return Result(None, None, response.ctrls, response)  # pragma: no cover

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

    async def _execute(self, conn: LDAPObject, operation: Callable, *args: Any, **kwargs: Any) -> _Response:
        """Execute the operation and wait asynchronously for the result."""
        msgid = await self._retry(self.request, operation, *args, **kwargs)
        if msgid is None:  # abandon_ext, unbind_ext
            return _Response(None, None, msgid, [], None, None)
        response = None
        async for resp in self._poll(conn, msgid, 1):
            if response is not None:  # pragma: no cover
                raise RuntimeError('Wrong method used! Use _execute_iter instead!')  # noqa: TRY003
            response = resp
        return response

    async def _execute_iter(self, conn: LDAPObject, operation: Callable, *args: Any, **kwargs: Any) -> AsyncGenerator[_Response, None]:
        """Execute the operation and yield the results asynchronously."""
        msgid = await self._retry(self.request, operation, *args, **kwargs)
        if msgid is None:  # abandon_ext, unbind_ext
            return
        async for response in self._poll(conn, msgid, 0):
            yield response

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

    async def _retry(self, func: Callable, *args: Any, **kwargs: Any) -> Any:
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
                await asyncio.sleep(self.retry_delay)
        raise RuntimeError()  # pragma: no cover; impossible

    def _poll_s(self, conn: LDAPObject, msgid: ResponseType = ResponseType.Any, _all: int = 0) -> Generator[_Response, None]:  # pragma: no cover
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

    async def _poll(self, conn: LDAPObject, msgid: ResponseType = ResponseType.Any, _all: int = 0) -> AsyncGenerator[_Response, None]:
        """Wait asynchronously for operation to succeed."""
        loop = asyncio.get_running_loop()
        while True:
            # TODO: move the asyncio stuff out of here
            fut = loop.create_future()

            fd = conn.fileno()
            self._add_reader(loop, fd, self._ready, conn, msgid, fut, _all)

            try:
                response = await self._wait_for(fut)
            except errors.NoResultsReturned:  # pragma: no cover; how?
                self._remove_reader(fd)
                break
            except Exception:
                self._remove_reader(fd)
                raise

            rtype = response.type
            if rtype is None:  # pragma: no cover; handled in _ready()
                continue

            yield response
            if rtype == ldap.RES_SEARCH_ENTRY:
                continue
            if rtype == ldap.RES_SEARCH_RESULT:
                break
            break

    def _ready(self, fd: int, conn: LDAPObject, msgid: int, fut: asyncio.Future[_Response], _all: ResponseType):
        log.debug('FD %s is ready', fd)
        try:
            os.fstat(fd)
            response = self.get_result(conn, msgid, _all=_all, timeout=0)
            if response.type is None:
                return

            fut.set_result(response)
            self._remove_reader(fd)
        except (OSError, errors.LdapError) as exc:
            log.error('FD %s is not valid - maybe connection is closed', fd)  # noqa: TRY400
            fut.set_exception(exc)
            self._remove_reader(fd)

    async def _wait_for(self, fut: asyncio.Future[_Response]) -> _Response:
        if self.timeout > 0:
            return await asyncio.wait_for(fut, timeout=self.timeout)
        return await fut

    @classmethod
    def _add_reader(cls, loop: asyncio.AbstractEventLoop, fd: int, func, *args: Any) -> None:
        log.debug('Select on FD %s', fd)
        os.fstat(fd)
        # FIXME: deadlock; it replaces a previous reader, e.g. when in a iterative search or other parallel operation
        loop.add_reader(fd, func, fd, *args)
        # register reader from the loop thread
        # loop.call_soon_threadsafe(lambda: loop.add_reader(fd, func, fd, *args))

    def _remove_reader(self, fd: int | None = None) -> None:
        fd = fd or self.fileno
        log.debug('Remove reader FD %s', fd)
        if fd == -1:  # pragma: no cover
            return
        loop = asyncio.get_running_loop()
        loop.remove_reader(fd)
        # loop.call_soon_threadsafe(lambda: loop.remove_reader(fd))
