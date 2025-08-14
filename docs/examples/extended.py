from freeiam import ldap


async def ldap_extended_operation_example():
    """Extended operation"""

    async with ldap.Connection('ldap://localhost:389', timeout=30) as conn:
        ...  # bind

        # If you know what you are doing
        # you can also perform LDAP extended operation
        from ldap.extop import ExtendedRequest, ExtendedResponse
        # but you have to implement it yourself
        # by creating a suitable subclasses of the above

        await conn.extended(ExtendedRequest(), ExtendedResponse)
