Distinguished Name (DN) Handling
================================

An LDAP Distinguished Name (DN) consists of zero, one, or multiple relative distinguished names (RDNs), and serves as the unique identifier for an object in the LDAP directory.

For example, ``uid=max.mustermann,ou=Developers,dc=freeiam,dc=org`` is the fully distinguished name of a user object.
It represents the position of the object in the LDAP tree, with the hierarchy proceeding from right to left.

The trailing RDNs (e.g., ``dc=freeiam,dc=org``) typically form the base DN, also known as the naming context or root object of the directory.
Note that the directory might not contain an actual object entry for each component (e.g., ``dc=org`` may not exist as a separate object).

Each RDN usually consists of a single Attribute Value Assertion (AVA), such as ``uid=max``.
In some cases, multiple AVAs can be combined to form a multi-valued RDN, for example: ``uid=max + sn=Mustermann``.

Working with LDAP DNs in applications is not always straightforward. There are several important considerations:

1. **Escaping special characters**

   Values derived from user input must be properly escaped, similar to how URL components are encoded.
   Special characters such as ``+``, ``=``, ``,``, ``\\``, ``#``, ``;``, ``"``, ``<``, and ``>`` must be escaped.
   When parsing a DN, these escape sequences must be correctly handled, which rules out naïve string splitting or regular expression matching.
   Instead, parsing requires a proper state machine.

   Escaping is typically done by prefixing the character with a backslash, or by using a hexadecimal escape sequence.  
   Examples: ``cn=Mustermann\,Max``, ``cn=Mustermann\2CMax``.

   Historically, LDAPv2/RFC 1779 also allowed an entire attribute value to be enclosed in double quotes,
   for example ``cn="Mustermann,Max"``. Within quoted values, only the backslash and the quote character
   itself had to be escaped. Some legacy LDAP implementations and APIs still support quoted RDN values.
   RFC 4514, however, does not define quoted attribute values; portable LDAP DN strings must therefore
   use backslash or hexadecimal escaping.

2. **Canonical equivalence and normalization**

   LDAP DNs can be written in multiple equivalent forms, which means string comparisons must not be done directly.
   For example, ``uid = Administrator`` is equivalent to ``uid=Administrator``. Proper **DN normalization** is required to compare DNs correctly.

3. **Case sensitivity**

   DNs are not universally case-insensitive.
   Whether an RDN value is case-insensitive depends on the attribute's syntax and matching rules as defined in the LDAP schema.
   For example, ``dc=FreeIAM`` is considered equal to ``dc=freeiam``, while ``memberUid=alice`` is **not** equal to ``memberUid=Alice``.  
   However, **attribute names** themselves are always case-insensitive, so ``DC=freeiam`` equals ``dc=freeiam``.

   Server implementations may handle this differently in practice. For bind operations, DNs are generally treated in a case-insensitive way.

4. **Attribute aliases and OIDs**

   LDAP attributes may have aliases. For example, a server schema can define
   ``cn=foo`` and ``commonName=foo`` as equivalent. It is also valid to
   specify an attribute type by its object identifier, such as
   ``2.5.4.3=foo`` for ``cn=foo``. Whether these forms compare equal depends
   on the server schema and matching rules.

5. **Attribute-specific constraints**

   Certain attributes have restrictions on allowed values.
   For example, the ``c`` (countryName) attribute must be a two-letter country code, making ``c=FOO`` invalid.

6. **Different DN representations**

   LDAP Distinguished Names can be expressed in multiple notations.
   While LDAPv3 string representation is the standard, several alternative formats exist.
   These are mostly used for display or integration purposes and are **not interchangeable** without proper conversion:

   - **LDAPv3 format** (standard):  
     ``uid=max.mustermann,ou=Developers,dc=freeiam,dc=org``  
     This is the formal string representation used in protocols and schemas.

   - **LDAPv2 format** (legacy):
      ``<OID.2.5.4.3="John Smith";o=example;c=US>``
      Older implementations may accept quoted values and other LDAPv2 syntax.

   - **AD Canonical Name format** (used in Microsoft Active Directory):  
     ``freeiam.org/Developers/max.mustermann``  
     Commonly used by Active Directory tools and user interfaces, but is not an LDAP protocol DN.

   - **DCE format** (Directory Cell Name / X.500 style):  
     ``/org/freeiam/Developers/max.mustermann``  
     Common in older X.500 or DCE environments.

   - **User-Friendly Name (UFN)** (deprecated):  
     ``max.mustermann, Developers, freeiam.org``  
     A more human-readable form, not standardized in modern LDAP.

   - **URL notation** (LDAP URLs):  
     ``ldap://ldap.freeiam.org/uid=max.mustermann,ou=Developers,dc=freeiam,dc=org``  
     Combines a server location with a DN and possibly search options.

   Applications must normalize and convert these forms to proper LDAPv3 syntax before using them in directory operations.

7. **UTF-8 encoding**

   At least all LDAP DNs must have a valid UTF-8 string representation :-).
   Binary attribute values (such as ``jpegPhoto``) cannot appear as raw bytes in a DN, nor can Latin-1-encoded characters.
   However, RFC 4514 also supports hexadecimal representations of BER-encoded attribute values (e.g. ``jpegPhoto=#C3BFC398C3BFC3A000104A46494600,dc=freeiam,dc=org``).

Equivalent LDAPv3 representations
---------------------------------

The following example forms below have the same structure or can compare as equal when the
referenced attribute syntax defines the corresponding matching rule:

.. code-block:: text
   :caption: Original DN. Special DN-separator chars (``+,=\"<>;``) must be backslash-escaped.

   uid=Dirk T. Tree,cn=users,ou=Identity \+ Access Management,dc=freeiam,dc=org

.. code-block:: text
   :caption: Attribute type names are case-insensitive.

   Uid=Dirk T. Tree,Cn=users,Ou=Identity \+ Access Management,Dc=freeiam,Dc=org
   UID=Dirk T. Tree,CN=users,OU=Identity \+ Access Management,DC=freeiam,DC=org

.. code-block:: text
   :caption: Attribute values may compare case-insensitively, depending on their matching rules (requires schema).

   UID=DIRK T. TREE,CN=USERS,OU=IDENTITY \+ ACCESS MANAGEMENT,DC=FREEIAM,DC=ORG

.. code-block:: text
   :caption: Characters can be escaped as hexadecimal UTF-8 octets.

   UID=DIRK T. TREE,CN=USERS,OU=IDENTITY \2B ACCESS MANAGEMENT,DC=FREEIAM,DC=ORG
   UID=DIRK T. TREE,CN=\55\53\65\52\53,OU=IDENTITY \2B ACCESS MANAGEMENT,DC=FREEIAM,DC=ORG
   UID=DIRK T. TREE,CN=#5553655253,OU=IDENTITY \2B ACCESS MANAGEMENT,DC=FREEIAM,DC=ORG

.. code-block:: text
   :caption: Attribute type aliases can denote the same attribute (``commonName`` and ``cn`` refer to the same attribute type)

   UID=DIRK T. TREE,commonName=\55\53\65\52\53,OU=IDENTITY \2B ACCESS MANAGEMENT,DC=FREEIAM,DC=ORG

.. code-block:: text
   :caption: Attribute types can also be identified by their numeric OIDs. For example, ``2.5.4.3`` identifies ``commonName`` (``cn``).

   UID=DIRK T. TREE,2.5.4.3=\55\53\65\52\53,OU=IDENTITY \2B ACCESS MANAGEMENT,DC=FREEIAM,DC=ORG

.. code-block:: text
   :caption: Matching rules such as ``caseIgnoreMatch`` can ignore insignificant whitespace within attribute values.

   UID=DIRK    T.    TREE,2.5.4.3=\55\53\65\52\53,OU=IDENTITY \2B ACCESS MANAGEMENT,DC=FREEIAM,DC=ORG

.. code-block:: text
   :caption: Additional whitespace around attribute types, equals signs, and RDN separators is tolerated (not guaranteed by RFC 4514).

   UID  =  DIRK    T.    TREE  ,  2.5.4.3  =  \55\53\65\52\53  ,  OU  =  IDENTITY \2B ACCESS MANAGEMENT  ,  DC  =  FREEIAM  ,  DC  =  ORG


Additionaly the order of AVAs in a multi-valued RDN is not significant:

.. code-block:: text

   givenName=Dirk+SN=Tree
   SN=Tree+givenName=Dirk

Due to these many nuances, DNs should never be manually parsed, compared, or interpreted in security-sensitive contexts.
Instead let the LDAP server handle DN logic and comparisons.

Object oriented DN class
------------------------

The :class:`~freeiam.ldap.dn.DN` class provides utilities for parsing,
validating, normalizing, comparing and manipulating LDAP Distinguished Names.
It provides local, partly schema-aware comparisons. Server-side comparison is
covered below.

Creating and normalizing a DN
-----------------------------

Constructing a ``DN`` parses the string and normalizes its formatting. The
object can then be safely passed to code that needs a structured DN instead
of repeatedly parsing a string.

.. code-block:: pycon

   >>> from freeiam.ldap.dn import DN
   >>> user_dn = 'uid = Max.Mustermann , cn = users , dc = freeiam, dc = org'
   >>> dn = DN(user_dn)
   >>> str(dn)
   'uid=Max.Mustermann,cn=users,dc=freeiam,dc=org'
   >>> repr(dn)
   'DN('uid=Max.Mustermann,cn=users,dc=freeiam,dc=org')'

Client-side DN comparison
--------------------------

:class:`~freeiam.ldap.dn.DN` can compare parsed DN objects locally. This is
useful for ordinary application logic, such as checking hierarchy membership or
deduplicating search results. The local rules do not contain the complete
schema of a connected server, so local equality is not a substitute for a
server-side authorization decision.

.. important::

   This is not safe for authorization, access control, identity matching, and
   other security-sensitive decisions.

.. code-block:: pycon
   :caption: Local DN comparison without schema awareness

   >>> a = DN(r'uid=Dirk T. Tree,cn=users,ou=Identity \+ Access Management,dc=freeiam,dc=org')
   >>> b = DN(r'UID  =  DIRK T. TREE  ,  CN  =  \55\53\65\52\53  ,  OU  =  IDENTITY \2B ACCESS MANAGEMENT  ,  DC  =  FREEIAM  ,  DC  =  ORG')
   >>> a == b
   True
   >>> c = DN(r'UID=DIRK T. TREE,commonName=\55\53\65\52\53,OU=IDENTITY \2B ACCESS MANAGEMENT,DC=FREEIAM,DC=ORG')
   >>> a == c
   False

Comparing DNs of existing objects
---------------------------------

``compare_dn()`` asks the LDAP server whether two DNs identify the same
object. This applies the server's schema-aware matching rules instead of
comparing the two input strings directly. The caller still needs compare access
to the relevant RDN attributes. This is the recommended operation for
correctness-sensitive comparisons. The result might be wrong for objects
having multi valued attributes as RDN.

.. literalinclude:: dn.py
   :language: python
   :caption: Comparing DNs of objects
   :start-after: start COMPARE EXISTS
   :end-before: end COMPARE EXISTS

Handling invalid user input
---------------------------

User-provided DN strings can be malformed. Constructing a ``DN`` raises
``InvalidDN`` for invalid syntax, which lets an application reject the input
before using it in an LDAP operation.

.. code-block:: pycon

   >>> import freeiam.errors
   >>> try:
   ...     DN('foo')  # not a DN at all
   ...
   ...     # Most often made mistakes: An unescaped comma, plus, equals sign,
   ...     # or backslash in an attribute value
   ...     DN('cn=%s,dc=freeiam,dc=org' % ('foo, (1 + 2) = 3, "bar"'))
   ...
   ...     # Legacy LDAPv2 DN syntax is not accepted by default
   ...     DN('OID.1.1=jsmith')  # uses an invalid attribute type name
   ...     DN('UID=jsmith;O=example;C=US')  # uses semicolons instead of RDN separators
   ...     DN('<UID=jsmith,O=example,C=US>')  # adds brackets that are not part of DN syntax
   ...     DN('CN="John Smith",O=example,C=US')  # LDAPv2 Quoted values
   ... except freeiam.errors.InvalidDN as exc:
   ...     print(exc)
   Malformed DN syntax: "foo"


Hierarchy and navigation
------------------------

DN objects expose their parent and support prefix and suffix checks. These
operations work on DN components, so they do not rely on naïve string
matching.

.. code-block:: pycon

   >>> DN(user_dn).parent
   DN('cn=users,dc=freeiam,dc=org')
   >>> DN('dc=org').parent is None
   True
   >>> DN('dc=freeiam,dc=org').get_parent('dc=freeiam,dc=org') is None  # get until certain base
   True
   >>> DN(user_dn).endswith('dc=freeiam,dc=org')
   True
   >>> DN(user_dn).startswith('uid=Max.Mustermann')
   True


Constructing new DNs
--------------------

Use ``DN.escape()`` for values that will be inserted into an RDN. ``DN.compose``
and DN concatenation then make it possible to construct a new DN while
preserving correct escaping and component boundaries.

.. code-block:: pycon

   >>> base = DN('dc=freeiam,dc=org')
   >>> DN.escape('#foo <+  ,=>"; bar#')
   '\\#foo \\<\\+  \\,\\=\\>\\"\\; bar#'
   >>> f'cn={DN.escape("admin")},dc=freeiam,dc=org'
   'cn=admin,dc=freeiam,dc=org'
   >>> str(DN.compose(('cn', 'admin'), 'ou=foo', base))
   'cn=admin,ou=foo,dc=freeiam,dc=org'
   >>> str(DN('cn=foo,cn=bar') + 'dc=freeiam,dc=org')
   'cn=foo,cn=bar,dc=freeiam,dc=org'


Working with DN sequences
-------------------------

DN objects behave like sequences of RDN components. Indexing selects a
component, and slicing returns a DN containing the selected part of the
hierarchy.

.. code-block:: pycon

   >>> len(dn)
   4
   >>> dn[2]
   DN('dc=freeiam')
   >>> dn[:-2]
   DN('uid=Max.Mustermann,cn=users')


Accessing attributes and values
--------------------------------

For a single-valued RDN, ``rdn``, ``attribute``, and ``value`` expose its
parsed attribute type and value without requiring the caller to split the
string manually.

.. code-block:: pycon

   >>> dn.rdn
   ('uid', 'Max.Mustermann')
   >>> dn.attribute
   'uid'
   >>> dn.value
   'Max.Mustermann'


Multi-Valued RDNs
-----------------

An RDN can contain multiple attribute-value assertions separated by ``+``.
The DN class exposes the complete RDN as well as its individual attribute
types and values.

.. code-block:: pycon

   >>> multi = DN('uid=foo+cn=bar,dc=freeiam,dc=org')
   >>> multi.multi_rdn
   (('uid', 'foo'), ('cn', 'bar'))
   >>> multi.attributes
   ('uid', 'cn')
   >>> multi.values
   ('foo', 'bar')


Checking membership
-------------------

Membership tests whether an RDN or a DN is a component of another DN. This is
useful for checking whether an entry belongs below a particular base DN.

.. code-block:: pycon

   >>> 'cn=users' in dn
   True
   >>> DN('cn=users') in dn
   True
   >>> 'cn=users,dc=freeiam' in dn
   False


Handling broken DNs
-------------------

Some directory integrations, including Samba 4, can return non-standard DN
escaping. The DN parser accepts this representation and produces a usable
normalized DN.

.. code-block:: pycon

   >>> str(DN(r'uid=foo\?bar,cn=users'))
   'uid=foo?bar,cn=users'


Inspecting RDNs
---------------

The ``rdns`` property returns all RDNs together with the type of each value.
This is useful when code needs to inspect the parsed structure rather than
only its string representation.

.. code-block:: pycon

   >>> from freeiam.ldap.constants import AVA
   >>> dn.rdns == [
   ...     [('uid', 'Max.Mustermann', AVA.String)],
   ...     [('cn', 'users', AVA.String)],
   ...     [('dc', 'freeiam', AVA.String)],
   ...     [('dc', 'org', AVA.String)],
   ... ]
   True


Traversing a DN
---------------

``walk()`` yields the base DN and each descendant DN up to the complete DN.
It is useful for traversing the hierarchy or checking each possible parent
entry.

.. code-block:: pycon

   >>> list(dn.walk('dc=freeiam,dc=org'))
   [DN('dc=freeiam,dc=org'),
    DN('cn=users,dc=freeiam,dc=org'),
    DN('uid=Max.Mustermann,cn=users,dc=freeiam,dc=org')]


Using DN as Dictionary Keys
---------------------------

DN objects are hashable and suitable for use as dictionary keys. Equivalent
DN representations resolve to the same key according to DN equality rules.

.. code-block:: pycon

   >>> {DN('UID = Administrator'): 1}[DN('uid=Administrator')]
   1


Utility methods
---------------

The utility methods normalize strings and convert either strings or existing
DN objects to a DN instance. They are useful at API boundaries where callers
may provide either representation.

.. code-block:: pycon

   >>> DN.normalize(user_dn)
   'uid=Max.Mustermann,cn=users,dc=freeiam,dc=org'
   >>> isinstance(DN.get('uid=foo'), DN)
   True
   >>> isinstance(DN.get(DN('uid=foo')), DN)
   True


Comparisons
-----------

DN comparisons apply LDAP-aware normalization, including attribute aliases,
case rules, escaped values, and multi-valued RDN ordering. The schema-specific
matching rules still determine whether two values are equivalent.

.. code-block:: pycon

   >>> DN('cn=foo,dc=freeiam,dc=org') == DN('cn=foo,dc=freeiam,dc=org')
   True
   >>> DN('cn=#666f6f') == DN('cn=foo')
   True
   >>> DN('cn=foo,dc=freeiam,dc=org') != DN('cn=bar,dc=freeiam,dc=org')
   True
   >>> DN('CN=foo,dc=freeiam,dc=org') == DN('cn=foo,dc=freeiam,dc=org')
   True
   >>> DN('uid=Administrator,dc=freeiam,dc=org') == DN('uid=administrator,dc=freeiam,dc=org')
   True
   >>> DN('cn=CN,dc=freeiam,dc=org') != DN('cn=cn,dc=freeiam,dc=org')
   True
   >>> DN('cn=foo+uid=bar,dc=freeiam,dc=org') == DN('cn=foo+uid=bar,dc=freeiam,dc=org')
   True
   >>> DN('uid=bar+cn=foo,dc=freeiam,dc=org') == DN('cn=foo+uid=bar,dc=freeiam,dc=org')
   True
   >>> DN(r'cn=\66o\6f,dc=freeiam,dc=org') == DN(r'cn=foo,dc=freeiam,dc=org')
   True


Removing duplicates
-------------------

``get_unique()`` removes equivalent DNs from a collection. The string variant
returns normalized strings, which is convenient when results must be serialized
or compared.

.. code-block:: pycon

   >>> DN.get_unique([
   ...     'CN=users,dc=freeiam,dc=org',
   ...     'cn=users,dc=freeiam,dc=org',
   ...     'cn = users,dc=freeiam,dc=org',
   ...     'CN=Users,dc=freeiam,dc=org',
   ... ])
   {DN('CN=users,dc=freeiam,dc=org')}

   >>> DN.get_unique_str(
   ...     DN.get_unique(['cn=foo', 'cn=bar']) - DN.get_unique(['cn = foo'])
   ... ) == {'cn=bar'}
   True
