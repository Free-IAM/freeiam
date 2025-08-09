Receiving server information
============================

Get Root DSE (Directory Server Entry)
-------------------------------------
.. code-block:: python

    # Get Root DSE (Directory Server Entry)
    result = await conn.get_root_dse()
    print(result.attr)

Get all LDAP databases
----------------------
.. code-block:: python

    # Get all LDAP databases
    bases = await conn.get_naming_contexts()
    print(bases)

Get SubSchema
-------------
.. code-block:: python

    # Get SubSchema
    subschema = await conn.get_schema()
    print(subschema)
