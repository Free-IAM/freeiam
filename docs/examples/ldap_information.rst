Receiving server information
============================

LDAP servers can provide metadata describing their capabilities, structure,
and available schema definitions. This information is useful for discovering
server features, supported controls, available naming contexts, and the
object classes and attributes you can use.

The following examples demonstrate:

* **Root DSE** — retrieving the Directory Server Entry, which contains
  server-supported features, controls, extensions, and other capabilities.
* **Naming contexts** — listing the base DNs for all databases managed by the server.
* **Subschema** — obtaining the schema definitions that describe allowable
  object classes, attributes, syntaxes, and matching rules.

These operations typically require no authentication, but access controls
may restrict certain attributes depending on the server’s configuration.

Get Root Directory Server Entry (DSE)
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
