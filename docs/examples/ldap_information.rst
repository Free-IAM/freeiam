Receiving server information
============================

LDAP servers can provide metadata describing their capabilities, structure,
and available schema definitions. This information is useful for discovering
server features, supported controls, available naming contexts, and the
object classes and attributes you can use.

The following examples demonstrate:

* **Root DSE** - retrieving the Directory Server Entry, which contains
  server-supported features, controls, extensions, and other capabilities.
* **Naming contexts** - listing the base DNs for all databases managed by the server.
* **Subschema** - obtaining the schema definitions that describe allowable
  object classes, attributes, syntaxes, and matching rules.

These operations typically require no authentication, but access controls
may restrict certain attributes depending on the server’s configuration.

Get Root Directory Server Entry (DSE)
-------------------------------------
The Root DSE is the server's entry point for capability discovery. It is not
part of the directory information tree and is addressed with the empty base
DN. The response can include supported LDAP versions, controls, extended
operations, SASL mechanisms, and naming contexts.

.. code-block:: python

    # Get Root DSE (Directory Server Entry)
    result = await conn.get_root_dse()
    print(result.attr)

Get all LDAP databases
----------------------
Naming contexts identify the base DNs served by the LDAP server. They are
useful when an application needs to construct searches without assuming a
particular directory layout.

.. code-block:: python

    # Get all LDAP databases
    bases = await conn.get_naming_contexts()
    print(bases)

Get SubSchema
-------------
The subschema subentry describes the schema enforced by the server. It
contains definitions for object classes, attributes, syntaxes, and matching
rules, allowing clients to inspect which values are valid before constructing
entries or filters.

.. code-block:: python

    # Get SubSchema
    subschema = await conn.get_schema()
    print(subschema)
