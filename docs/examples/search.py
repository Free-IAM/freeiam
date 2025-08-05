from freeiam import errors, ldap
from freeiam.ldap.constants import Scope


async def ldap_search_examples():
    async with ldap.Connection('ldap://localhost:389') as conn:
        ...  # do bind()

        # start SEARCH
        search_base = 'dc=freeiam,dc=org'

        # search for DN and attrs
        for entry in await conn.search(
            search_base, Scope.SUBTREE, '(&(uid=*)(objectClass=person))'
        ):
            print(entry.dn, entry.attr)
        # end SEARCH

        # start ITERSEARCH
        # search iterative for DN and attrs
        async for entry in conn.search_iter(
            search_base, Scope.SUBTREE, '(&(uid=*)(objectClass=person))'
        ):
            print(entry.dn, entry.attr)
        # end ITERSEARCH

        # start DNSEARCH
        # search for DN
        async for entry in conn.search_dn(
            search_base, Scope.SUBTREE, '(&(uid=*)(objectClass=person))'
        ):
            print(entry.dn)
        # end DNSEARCH

        # start PAGEDSEARCH
        # search paginated via SimplePagedResult
        async for entry in conn.search_paged(
            search_base,
            Scope.Subtree,
            '(&(uid=*)(objectClass=person))',
            page_size=10,
        ):
            print(entry.dn, entry.attr, entry.page)
        # end PAGEDSEARCH

        # start SORTSEARCH
        # all of the previous searches allow specifying the ServerSideSorting control:
        for entry in await conn.search(
            search_base,
            Scope.SUBTREE,
            '(&(uid=*)(objectClass=person))',
            sorting=[('uid', 'caseIgnoreOrderingMatch', False)],
        ):
            print(entry.dn, entry.attr)
        # end SORTSEARCH

        # start VLVSEARCH
        # search paginated via VirtualListView + ServerSideSorting
        async for entry in conn.search_paginated(
            search_base,
            Scope.Subtree,
            '(&(uid=*)(objectClass=person))',
            page_size=10,
            sorting=[('uid', 'caseIgnoreOrderingMatch', False)],
        ):
            print(entry.dn, entry.attr, entry.page)
        # end VLVSEARCH

        # start GETOBJ
        # get a certain object, and use its attributes
        obj = await conn.get('uid=max.mustermann,dc=freeiam,dc=org')
        print(obj.dn, obj.attr)
        print(obj.attr['cn'])
        print(obj.attr['CN'])  # yes, attribute names are case sensitive!
        print(obj.attr['commonName'])  # and there are even aliases!!!
        # end GETOBJ

        # start GETATTR
        # get a attribute of an object (even by alias!)
        cn = await conn.get_attr('uid=max.mustermann,dc=freeiam,dc=org', 'commonName')
        print(cn)
        # end GETATTR

        # start UNIQUE
        # find unique entry
        try:
            (_entry,) = await conn.search(
                search_base,
                Scope.SUBTREE,
                '(&(uid=max.mustermann)(objectClass=person))',
                unique=True,
            )
            ...  # do something, ensured to be only the unique entry
        except errors.NotUnique as exc:
            # otherwise we have this error here, containg all search results
            print('Bad member in', exc.results)
        # end UNIQUE

        # start ERRORS
        # don't forget to handle errors for not existing objects
        try:
            await conn.get('uid=max.mustermann,dc=freeiam,dc=org')
        except errors.NoSuchObject as exc:
            print(exc.description)
        # end ERRORS

        # start EXISTS
        # or if you just need to know whether a object exists
        await conn.exists('uid=max.mustermann,dc=freeiam,dc=org')
        # end EXISTS
