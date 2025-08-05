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

   Alternatively, the entire attribute value can be enclosed in double quotes: ``cn="Mustermann,Max"``.
   Within quoted values, only the backslash and the quote character itself must be escaped.


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

   LDAP attributes may have aliases. For example, ``cn=foo`` is equivalent to ``commonName=foo``.
   It's also valid to specify attribute types using their object identifier (OID), making the DN ``2.5.4.3=foo`` also equivalent.

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

   - **User-Friendly Name (UFN)** (deprecated):  
     ``max.mustermann, Developers, freeiam.org``  
     A more human-readable form, not standardized in modern LDAP.

   - **DCE format** (Directory Cell Name / X.500 style):  
     ``/.../org/freeiam/Developers/max.mustermann``  
     Common in older X.500 or DCE environments.

   - **AD Canonical Name format** (used in Microsoft Active Directory):  
     ``freeiam.org/Developers/max.mustermann``  
     Often seen in UI contexts (e.g., PowerShell, admin consoles), but not a valid DN in protocol operations.

   - **URL notation** (LDAP URLs):  
     ``ldap://ldap.freeiam.org/uid=max.mustermann,ou=Developers,dc=freeiam,dc=org``  
     Used to specify DNs as part of a full LDAP URL, including host and options.

   Applications must normalize and convert these forms to proper LDAPv3 syntax before using them in directory operations.

7. **UTF-8 encoding**

   At least all LDAP DNs must be valid UTF-8 encoded strings :-).

Due to these many nuances, DNs should never be manually parsed, compared, or interpreted in security-sensitive contexts.
Always let the LDAP server handle DN logic and comparisons.

FreeIAM provides the following mechanisms to safely and reliably work with LDAP DNs:

.. literalinclude:: dn.py
   :language: python
   :linenos:
   :caption: LDAP DN handling
