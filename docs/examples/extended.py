from freeiam import ldap


TIMEOUT = 30  # set a usefull default timeout!


async def ldap_extended_stuff_example():
    """Extended stuff"""

    async with ldap.Connection('ldap://localhost:389', timeout=TIMEOUT) as conn:
        ...  # bind

        # Get Root DSE (Directory Server Entry)
        result = await conn.get_root_dse()
        print(result.attr)

        # Get all LDAP databases
        bases = await conn.get_naming_contexts()
        print(bases)

        # Get SubSchema
        subschema = await conn.get_schema()
        print(subschema)

        # If you know what you are doing and are an expert you can also perform LDAP extended operation
        from ldap.extop import ExtendedRequest, ExtendedResponse  # use suitable subclasses

        await conn.extop(ExtendedRequest(), ExtendedResponse)
