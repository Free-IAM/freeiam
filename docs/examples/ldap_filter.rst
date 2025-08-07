Filter handling
===============
An LDAP filter can consist of 10 different components and is used in a search request to filter the result set.

+---------------------------+-------------------------------------------------------------+------------------------------------------+
| Filter Type               | Description                                                 | Example                                  |
+===========================+=============================================================+==========================================+
| Presence Filter           | Checks if an attribute is present.                          | ``(cn=*)``                               |
+---------------------------+-------------------------------------------------------------+------------------------------------------+
| Equality Match Filter     | Checks if an attribute equals a given value.                | ``(cn=John Doe)``                        |
+---------------------------+-------------------------------------------------------------+------------------------------------------+
| Substring Filter          | Checks if an attribute contains a substring pattern.        | ``(cn=Jo*n Do*)``                        |
+---------------------------+-------------------------------------------------------------+------------------------------------------+
| Greater or Equal Filter   | Checks if an attribute value is greater than or equal to a  | ``(age>=30)``                            |
|                           | specified value.                                            |                                          |
+---------------------------+-------------------------------------------------------------+------------------------------------------+
| Less or Equal Filter      | Checks if an attribute value is less than or equal to a     | ``(age<=40)``                            |
|                           | specified value.                                            |                                          |
+---------------------------+-------------------------------------------------------------+------------------------------------------+
| Approximate Match Filter  | Checks if an attribute approximately matches a given value. | ``(cn~=Jon Doe)``                        |
+---------------------------+-------------------------------------------------------------+------------------------------------------+
| AND Filter                | Combines multiple filters with a logical AND.               | ``(&(objectClass=person)(cn=John Doe))`` |
+---------------------------+-------------------------------------------------------------+------------------------------------------+
| OR Filter                 | Combines multiple filters with a logical OR.                | ``(|(sn=Smith)(sn=Johnson))``            |
+---------------------------+-------------------------------------------------------------+------------------------------------------+
| NOT Filter                | Negates a filter.                                           | ``(!(cn=John Doe))``                     |
+---------------------------+-------------------------------------------------------------+------------------------------------------+
| Extensible Match Filter   | Advanced filter allowing matching rules and DN attributes.  | ``(cn:caseIgnoreMatch:=john)``           |
|                           |                                                             | ``(sn:dn:2.5.13.3:=DOE)``                |
+---------------------------+-------------------------------------------------------------+------------------------------------------+


Filter escaping
---------------
When constructing LDAP filters in applications, all user-supplied input must be properly escaped.
Failing to do so can lead to LDAP filter injection, allowing attackers to alter the intended search query.

For example, building a filter like this:

.. code-block:: python

    filter_expr = '(&(objectClass=inetOrgPerson)(uid=' + username + '))'

If ``username`` is passed as ``*)(uid=Administrator`` the resulting filter (pretty-printed) becomes - which is a valid filter, but not the intended one:

.. code-block:: none

    (&
      (objectClass=inetOrgPerson)
      (uid=*)
      (uid=Administrator)
    )


Correct approach:
Always escape user input before inserting it into an LDAP filter.

.. literalinclude:: filter.py
   :language: python
   :caption: LDAP filter escaping
   :start-after: start FILTER ESCAPING
   :end-before: end FILTER ESCAPING

.. warning::

   Escaping filter characters (``\``, ``*``, ``(``, ``)``, ``\x00``) alone is not sufficient.  
   A filter starting with a leading space also becomes invalid.

.. warning::

   Attribute names cannot be escaped. They may only contain the characters ``a-zA-Z0-9;-`` or, if starting with a digit, must follow the OID format (e.g., ``1.3.6.1.4.1.64020``).  
   Allowing user input in attribute names can therefore produce an invalid or unparsable filter, or even turn it into an extensible match filter.


Pretty filters
--------------

LDAP filters can also be displayed in a tree-like, indented format that is easier for humans to read and understand.
In this form, the filter no longer strictly conforms to the LDAP standard syntax. However, some LDAP servers - such as OpenLDAP - can still parse and interpret it correctly.

To generate this representation, simply call:

.. code:: python

    >>> print(Filter(filter_expression).pretty())
    (&
      (|
        (cn=John Doe)
        (sn=*)
        (givenName=Jo*n*Do*)
        (uid>=1000)
        (uid<=2000)
        (mail~=j.doe@freeiam.org)
        (!(objectClass=inetOrgPerson))
      )
      (description=contains\28parentheses,spaces\20\29\5cand\2astars\2a)
      (objectClass:caseIgnoreMatch:=inetOrgPerson)
      (cn:dn:2.4.6.8.10:=John\20Doe)
    )

Filter transformations
----------------------

LDAP filters can be programmatically rewritten and transformed to fit specific use cases.  
This process allows you to adjust attribute names, normalize values, or even change the filter logic itself.

Example starting filter:

.. code-block:: none

   (&
     (&
       (objectClass=top)
       (objectClass=person)
       (objectClass=inetOrgPerson)
     )
     (alias=no)
     (fqdn=ldap.freeiam.org)
     (|
       (ip=127.0.0.1)
       (ip=0000:0000:0000:0000:0000:0000:0000:0001)
     )
     (unlocked=TRUE)
     (a=192.168.0.1)
     (birthdate=2025-07-04)
     (disabled=TRUE)
   )

Possible transformation steps
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~


1. **Replace an attribute name or value**

   e.g. for schema-aware rewriting.
   Automatically substitute deprecated attribute names with their current schema equivalents.

   Example: ``(surName=Smith)`` → ``(sn=Smith)``

2. **Split a pseudo-attribute into multiple real attributes**  

   Example: ``(fqdn=ldap.freeiam.org)``

   .. code-block:: none

      (&
        (cn=ldap)
        (associatedDomain=freeiam.org)
      )

   Another example: ``(a=192.168.0.1)``

   .. code-block:: none

      (|
        (aAAARecord=192.168.0.1)
        (a=192.168.0.1)
      )

3. **Remove redundant clauses**

   Eliminate expressions that are always true or always false, to simplify filters.

   Example:

.. code-block:: none

    (&
      (objectClass=top)
      (objectClass=person)
      (objectClass=inetOrgPerson)
    )

→ ``(objectClass=inetOrgPerson)``

4. **Merge duplicate conditions**

   Combine repeated attribute-value pairs into a single occurrence.

   Example:

.. code-block:: none

    (|
      (uid=alice)
      (uid=alice)
    )

→
   ``(uid=alice)``

5. **Expand wildcards or patterns**

   Replace a filter containing a broad wildcard with explicit value alternatives, or the other way around.

   Example: ``(cn=app*)`` →

.. code-block:: none

    (|
      (cn=app01)
      (cn=app02)
    )

6. **Matching rule injection**

   Add specific matching rules to attributes based on their type.

   Example: ``(mail=User@Example.com)`` → ``(mail:caseIgnoreMatch:=User@Example.com)``

7. **Value normalization**

   Apply canonical formatting to attribute values.

   Example: ``(ip=0000:0000:0000:0000:0000:0000:0000:0001)`` → ``(ip=::1)``

8. **Rename attributes based on their value, with normalization**

   Example: ``(ip=127.0.0.1)`` and ``(ip=0000:0000:0000:0000:0000:0000:0000:0001)``

   .. code-block:: none

      (|
        (aRecord=127.0.0.1)
        (aAAARecord=::1)
      )

9. **Negate the logic of an expression**

   Example: ``(unlocked=TRUE)`` → ``(!(locked=TRUE))``

10. **Convert an equality match to an extensible match with a specific matching rule**

    Example: ``(birthdate=2025-07-04)`` → ``(dateOfBirth:generalizedTimeMatch:=20250704000000Z)``

11. **Replace a simple expression with a compound operator-based condition**

    Example: ``(disabled=TRUE)``

    .. code-block:: none

      (&
        (shadowExpire=1)
        (krb5KDCFlags:1.2.840.113556.1.4.803:=128)
        (|
          (sambaAcctFlags=[UD       ])
          (sambaAcctFlags=[ULD       ])
        )
      )

12. **Switch the top-level logical operator**

    Change the entire filter from an AND condition to an OR condition (or vice versa) to broaden or narrow the search results.

Transformation implementation
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

All of these transformations can be applied using the following traversal code:

.. literalinclude:: filter.py
   :language: python
   :caption: LDAP filter transformation
   :start-after: start FILTER TRANSFORMATION
   :end-before: end FILTER TRANSFORMATION

Resulting transformed filter:

.. code-block:: none

   (|
     (&
       (cn=ldap)
       (associatedDomain=freeiam.org)
     )
     (resolved=yes)
     (|
       (aRecord=127.0.0.1)
       (aAAARecord=0000:0000:0000:0000:0000:0000:0000:0001)
     )
     (|
       (aAAARecord=192.168.0.1)
       (a=192.168.0.1)
     )
     (!(locked=TRUE))
     (&
       (shadowExpire=1)
       (krb5KDCFlags:1.2.840.113556.1.4.803:=128)
       (|
         (sambaAcctFlags=[UD       ])
         (sambaAcctFlags=[ULD       ])
       )
     )
     (dateOfBirth:generalizedTimeMatch:=20250704000000Z)
   )
