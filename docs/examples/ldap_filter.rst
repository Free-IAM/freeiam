Filter parsing and construction
===============================
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
|                           | If DN is specified, all RDNs of the DN are compared.        | ``(sn:dn:2.5.13.3:=DOE)``                |
+---------------------------+-------------------------------------------------------------+------------------------------------------+


Filter construction and escaping
--------------------------------
When constructing LDAP filters in applications, all user-supplied input must be properly escaped.
Failing to do so can lead to LDAP filter injection, allowing attackers to alter the intended search query.

For example, building a filter like this:

.. code-block:: python

    filter_expr = '(&(objectClass=inetOrgPerson)(uid=' + username + '))'

If ``username`` is passed as ``*)(uid=Administrator`` the resulting filter (pretty-printed) becomes - which is a valid filter, but not the intended one:

.. code-block:: bash

    (&
      (objectClass=inetOrgPerson)
      (uid=*)
      (uid=Administrator)
    )

Correct approach: Always escape user input before inserting it into an LDAP filter.

.. warning::

   Escaping filter characters (``\``, ``*``, ``(``, ``)``, ``\x00``) alone is not sufficient.  
   A filter starting with a leading space becomes broken.

.. warning::

   Attribute names cannot be escaped but must be validated or whitelisted.
   They may only contain the characters ``a-zA-Z0-9;-`` or, if starting with a digit, must follow the OID format (e.g., ``1.3.6.1.4.1.64020``).  
   Allowing user input in attribute names can therefore produce an invalid or unparsable filter, or even turn it into an extensible match filter.

.. warning::

   Allowing the wildcard character ``*`` in user input can be useful in some scenarios, but its usage should be limited.
   Excessive use of ``*`` has the potential to cause Denial of Service (DoS) attacks due to expensive filter evaluations.

You can use raw escaping methods to safely handle special characters in user input:

.. code:: pycon

    >>> from freeiam.ldap.filter import EscapeMode, Filter
    >>> user_input = ' hello (my friend), i am attacking * with \x00 or \\XX'
    >>> print(Filter.escape(user_input, EscapeMode.SPECIAL))
     hello \28my friend\29, i am attacking \2a with \00 or \5cXX
    >>> print(Filter.escape(user_input, EscapeMode.RESTRICTED))
    \20hello\20\28my\20friend\29\2c\20i\20am\20attacking\20\2a\20with\20\00\20or\20\5cXX
    >>> print(Filter.escape(user_input, EscapeMode.ALL))
    \20\68\65\6c\6c\6f\20\28\6d\79\20\66\72\69\65\6e\64\29\2c\20\69\20\61\6d\20\61\74\74\61\63\6b\69\6e\67\20\2a\20\77\69\74\68\20\00\20\6f\72\20\5c\58\58

Alternatively, automatic escaping makes filter construction easier and safer:

.. code:: pycon

    >>> def print_expr(expression):
    ...     print(expression, ' #', repr(expression))
    ...
    >>>
    >>> user_input = 'foo (bar)*'  # example input with characters needing escaping
    >>> cn = Filter.attr('cn')
    >>> print_expr(cn == '')  # noqa: PLC1901
    cn=*  # PresenceMatch(cn=*escape(''))
    >>> print_expr(cn == user_input)
    cn=foo \28bar\29\2a  # EqualityMatch(cn=escape('foo (bar)*'))
    >>> print_expr(cn != user_input)
    (!(cn=foo \28bar\29\2a))  # NOT( EqualityMatch(cn=escape('foo (bar)*')) )
    >>> print_expr(cn == ['', user_input, ''])  # prefix and suffix with *
    cn=foo \28bar\29\2a  # SubstringMatch(cn=escape('foo (bar)*'))
    >>> print_expr(cn == user_input.split('*'))  # allow '*' filtering in user input
    cn=foo \28bar\29  # SubstringMatch(cn=escape('foo (bar)'))
    >>> print_expr(cn > '1000')
    (!(cn<=1000))  # NOT( LessOrEqual(cn<=escape('1000')) )
    >>> print_expr(cn >= '1000')
    cn>=1000  # GreaterOrEqual(cn>=escape('1000'))
    >>> print_expr(cn < '1000')
    (!(cn>=1000))  # NOT( GreaterOrEqual(cn>=escape('1000')) )
    >>> print_expr(cn <= '1000')
    cn<=1000  # LessOrEqual(cn<=escape('1000'))
    >>> print_expr(cn > 1000)  # using real integers
    cn>=1001  # GreaterOrEqual(cn>=escape('1001'))
    >>> print_expr(cn >= 1000)
    cn>=1000  # GreaterOrEqual(cn>=escape('1000'))
    >>> print_expr(cn < 1000)
    cn<=999  # LessOrEqual(cn<=escape('999'))
    >>> print_expr(cn <= 1000)
    cn<=1000  # LessOrEqual(cn<=escape('1000'))
    >>> print_expr(cn.approx == user_input)
    cn~=foo \28bar\29\2a  # ApproximateMatch(cn~=escape('foo (bar)*'))
    >>> print_expr(cn.extensible(None, 'generalizedTimeMatch') == user_input)
    cn:generalizedTimeMatch:=foo \28bar\29\2a  # ExtensibleMatch(cn:generalizedTimeMatch:=escape('foo (bar)*'))
    >>> print_expr((cn == 'foo') | (cn == 'bar'))
    (|(cn=foo)(cn=bar))  # OR( EqualityMatch(cn=escape('foo')) | EqualityMatch(cn=escape('bar')) )
    >>> print_expr((cn != 'foo') & (cn != 'bar'))
    (&(!(cn=foo))(!(cn=bar)))  # AND( NOT( EqualityMatch(cn=escape('foo')) ) & NOT( EqualityMatch(cn=escape('bar')) ) )
    >>> print_expr(((cn == 'foo') | (cn == 'bar')).negate())
    (!(|(cn=foo)(cn=bar)))  # NOT( OR( EqualityMatch(cn=escape('foo')) | EqualityMatch(cn=escape('bar')) ) )

Or by using explicit method calls:

.. code:: pycon

    >>> Filter.get_pres('cn')
    PresenceMatch(cn=*escape(''))
    >>> Filter.get_eq('cn', user_input)
    EqualityMatch(cn=escape('foo (bar)*'))
    >>> Filter.get_approx('cn', user_input)
    ApproximateMatch(cn~=escape('foo (bar)*'))
    >>> Filter.get_substring('cn', *user_input.split('*'))
    SubstringMatch(cn=escape('foo (bar)'))
    >>> Filter.get_substring('cn', '', 'foo', '')
    SubstringMatch(cn=escape('foo'))
    >>> Filter.get_gt_eq('uidNumber', 1000)
    GreaterOrEqual(uidNumber>=escape('1000'))
    >>> Filter.get_gt_eq('uidNumber', 1000)
    GreaterOrEqual(uidNumber>=escape('1000'))
    >>> Filter.get_extensible('cn', None, 'generalizedTimeMatch', user_input)
    ExtensibleMatch(cn:generalizedTimeMatch:=escape('foo (bar)*'))
    >>> Filter.get_and(Filter.get_eq('objectClass', 'person'), Filter.get_eq('cn', user_input))
    AND( EqualityMatch(objectClass=escape('person')) & EqualityMatch(cn=escape('foo (bar)*')) )
    >>> ipv4 = '127.0.0.1'
    >>> ipv6 = '::1'
    >>> Filter.get_or(Filter.get_eq('aRecord', ipv4), Filter.get_eq('aAAARecord', ipv6))
    OR( EqualityMatch(aRecord=escape('127.0.0.1')) | EqualityMatch(aAAARecord=escape('::1')) )
    >>> Filter.get_not(Filter.get_eq('cn', user_input))
    NOT( EqualityMatch(cn=escape('foo (bar)*')) )

Pretty filters
--------------

LDAP filters can also be displayed in a tree-like, indented format that is easier for humans to read and understand.
In this form, the filter no longer strictly conforms to the LDAP standard syntax. However, some LDAP servers - such as OpenLDAP - can still parse and interpret it correctly.

To generate this representation, simply call:

.. code:: pycon

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

.. code-block:: bash

    (&
      (surName=Smith)
      (fqdn=ldap.freeiam.org)
      (a=192.168.0.1)
      (&
        (objectClass=top)
        (objectClass=person)
        (objectClass=inetOrgPerson)
      )
      (|
        (uid=alice)
        (uid=alice)
        (uid=alice)
      )
      (|
        (uid=alice)
        (uid=bob)
        (uid=alice)
      )
      (app=app*)
      (mail=User@Example.com)
      (|
        (ip=127.0.0.1)
        (ip=0000:0000:0000:0000:0000:0000:0000:0001)
      )
      (unlocked=TRUE)
      (birthdate=2025-07-04)
      (disabled=FALSE)
    )

Possible transformation steps
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~


1. **Replace an attribute name or value**

   e.g. for schema-aware rewriting.
   Automatically substitute deprecated attribute names with their current schema equivalents.

   Example: ``(surName=Smith)`` → ``(sn=Smith)``

2. **Split a pseudo-attribute into multiple real attributes**  

   Example: ``(fqdn=ldap.freeiam.org)``

   .. code-block:: bash

      (&
        (cn=ldap)
        (associatedDomain=freeiam.org)
      )

   Another example: ``(a=192.168.0.1)``

   .. code-block:: bash

      (|
        (aAAARecord=192.168.0.1)
        (a=192.168.0.1)
      )

3. **Rename attributes based on their value**

   Example: ``(ip=127.0.0.1)`` and ``(ip=0000:0000:0000:0000:0000:0000:0000:0001)``

   .. code-block:: bash

      (|
        (aRecord=127.0.0.1)
        (aAAARecord=::1)
      )

4. **Value normalization**

   Apply canonical formatting to attribute values.

   Example: ``(ip=0000:0000:0000:0000:0000:0000:0000:0001)`` → ``(ip=::1)``

5. **Matching rule injection**
   Convert an equality match to an extensible match with a specific matching rule.

   Example: ``(mail=User@Example.com)`` → ``(mail:caseIgnoreMatch:=User@Example.com)``

   Example: ``(birthdate=2025-07-04)`` → ``(dateOfBirth:generalizedTimeMatch:=20250704000000Z)``

6. **Negate the logic of an expression**

   Example: ``(unlocked=TRUE)`` → ``(!(locked=TRUE))``

7. **Remove redundant clauses**

   Eliminate expressions that are always true or always false, to simplify filters.

   Example:

   .. code-block:: bash

      (&
        (objectClass=top)
        (objectClass=person)
        (objectClass=inetOrgPerson)
      )

→ ``(objectClass=inetOrgPerson)``

8. **Merge duplicate conditions**

   Combine repeated attribute-value pairs into a single occurrence.

   Example:

   .. code-block:: bash

      (|
        (uid=alice)
        (uid=alice)
      )

   → ``(|(uid=alice))``

9. **Remove unneccesary groups**

   After certain transformations, you may end up with groups containing only a single expression.
   These redundant parentheses can be removed.

   Example: ``(|(uid=alice))`` → ``(uid=alice)``

10. **Expand wildcards or patterns**

    Replace a filter containing a broad wildcard with explicit value alternatives, or the other way around.
    Some attributes don't provide a substring matching rule.

    Example: ``(cn=app*)`` →

    .. code-block:: bash

      (|
        (cn=app01)
        (cn=app02)
      )

11. **Replace a simple expression with a compound operator-based condition**

    Example: ``(disabled=TRUE)``

    .. code-block:: bash

      (&
        (shadowExpire=1)
        (krb5KDCFlags:1.2.840.113556.1.4.803:=128)
        (|
          (sambaAcctFlags=[UD       ])
          (sambaAcctFlags=[ULD       ])
        )
      )

12. **Replace a ASCII representation to a binary attribute filter**

    For attributes with a binary blob syntax, support for string representations could be achieved:

    Example: ``(objectGUID=efbee1fe-ef4d-edac-dead-c0de87ea1337)`` → ``(objectGUID=\fe\e1\be\ef\4d\ef\ac\ed\de\ad\c0\de\87\ea\13\37)``

    (not included below, due to redundancy. Suitable Python code for the transformation could be):
    ``samba.ndr.ndr_pack(samba.dcerpc.misc.GUID('efbee1fe-ef4d-edac-dead-c0de87ea1337')).decode('ISO8859-1')``

Transformation implementation
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

All of these transformations can be applied using the following traversal code:

.. literalinclude:: filter.py
   :language: python
   :caption: LDAP filter transformation
   :start-after: start FILTER TRANSFORMATION
   :end-before: end FILTER TRANSFORMATION

Resulting transformed filter:

.. code-block:: bash

   (&
     (sn=Smith)
     (&
       (cn=ldap)
       (associatedDomain=freeiam.org)
     )
     (|
       (aRecord=192.168.0.1)
       (aAAARecord=192.168.0.1)
     )
     (objectClass=inetOrgPerson)
     (uid=alice)
     (|
       (uid=bob)
       (uid=alice)
     )
     (|
       (app=app01)
       (app=app02)
       (app=app03)
     )
     (mail:caseIgnoreMatch:=User@Example.com)
     (|
       (aRecord=127.0.0.1)
       (aAAARecord=::1)
     )
     (!(locked=TRUE))
     (dateOfBirth:generalizedTimeMatch:=20250704000000Z)
     (&
       (!(shadowExpire=1))
       (!(krb5KDCFlags:1.2.840.113556.1.4.803:=128))
       (&
         (!(sambaAcctFlags=[UD       ]))
         (!(sambaAcctFlags=[ULD       ]))
       )
     )
   )
