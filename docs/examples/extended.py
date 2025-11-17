from freeiam import ldap


async def ldap_extended_operation_example():
    """Extended operation"""

    async with ldap.Connection('ldap://localhost:389', timeout=30) as conn:
        ...  # bind
        base_dn = next(conn.get_naming_contexts())

        # start WHOAMI
        dn = await conn.whoami()
        print(dn)
        # end WHOAMI

        # start REFRESH
        attrs = {
            'objectClass': [b'inetOrgPerson', b'dynamicObject'],
            'uid': [b'dynamic'],
            'cn': [b'common name'],
            'sn': [b'sir name'],
        }
        result = await conn.add(f'uid=dynamic,{base_dn}', attrs)
        result = await conn.refresh_ttl(result.dn, 20)
        print(result.extended_value)  # 20
        # end REFRESH

        # start TRANSACTION
        from freeiam.ldap.controls import Controls, transaction
        from freeiam.ldap.extended_operations import (
            transaction_commit,
            transaction_start,
        )

        result = await conn.extended(transaction_start(), transaction_start.response)
        txn_id = result.extended_value
        controls = Controls.set_server(None, transaction(txn_id, criticality=True))
        try:
            for i in range(10):
                attrs = {
                    'objectClass': [b'inetOrgPerson'],
                    'uid': [f'txn{i}'.encode()],
                    'cn': [b'common name'],
                    'sn': [b'sir name'],
                }
                await conn.add(f'uid=txn{i},{base_dn}', attrs, controls=controls)
        except Exception:  # noqa: BLE001
            # abort transaction
            await conn.extended(
                transaction_commit(txn_id, commit=False),
                transaction_commit.response,
            )
        else:
            await conn.extended(
                transaction_commit(txn_id, commit=True), transaction_commit.response
            )
        # end TRANSACTION

        # start CONTEXT TRANSACTION
        async with conn.transaction() as transaction_id:
            print(transaction_id)  # None for OpenLDAP
            # it sets the connections wide transaction control with the transaction ID
            # so that it gets applied automatically for all subsequent requests.
            # If any uncatched exception happens here, the transaction is aborted!
            # otherwise it's commited.
            for i in range(10):
                attrs = {
                    'objectClass': [b'inetOrgPerson'],
                    'uid': [f'txn{i}'.encode()],
                    'cn': [b'common name'],
                    'sn': [b'sir name'],
                }
                await conn.add(f'uid=txn{i},{base_dn}', attrs)
        # end CONTEXT TRANSACTION

        # start SYNCREPL
        # TODO: implement syncrepl examples
        # end SYNCREPL

        # start EXTENDED
        from freeiam.ldap.extended_operation import ExtendedRequest, ExtendedResponse
        # custom extended operations can be implemented by yourself
        # by creating a suitable subclasses of the above

        class FooExtended(ExtendedRequest):
            requestName = '1.3.6.1.1.21.1'  # insert OID HERE

            # implement "encodedRequestValue" method, which
            # returns the BER-encoded ASN.1 request value

        class FooExtendedResponse(ExtendedResponse):
            responseName = '1.3.6.1.1.21.3'  # insert OID here

            # implement "decodeResponseValue" method, which
            # decodes the BER-encoded ASN.1 extended operation response value

        # you could even build modules for OpenLDAP implementing
        # custom extended operations

        await conn.extended(FooExtended(), FooExtendedResponse)
        # end EXTENDED
