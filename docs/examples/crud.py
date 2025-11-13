from freeiam import errors, ldap
from freeiam.ldap.constants import Mod


base_dn = 'dc=freeiam,dc=org'


async def ldap_create_user_examples():
    async with ldap.Connection('ldap://localhost:389') as conn:
        ...  # do bind()

        # start CREATE
        # create a entry from dict attributes definition
        dn = f'uid=max.mustermann,{base_dn}'
        attrs = {
            'objectClass': [b'inetOrgPerson'],
            'uid': [b'max.mustermann'],
            'cn': [b'Max Mustermann'],
            'givenName': [b'Max'],
            'sn': [b'Mustermann'],
            'mail': [b'max.mustermann@freeiam.org'],
        }
        result = await conn.add(dn, attrs)
        print(result.dn, result.attrs)

        # create a entry from LDAP addlist
        dn = f'uid=max.mustermann,{base_dn}'
        add_list = [
            ('objectClass', [b'inetOrgPerson']),
            ('uid', [b'max.mustermann']),
            ('cn', [b'Max Mustermann']),
            ('givenName', [b'Max']),
            ('sn', [b'Mustermann']),
            ('mail', [b'max.mustermann@freeiam.org']),
        ]

        try:
            result = await conn.add_al(dn, add_list)
            print(result.dn, result.attrs)
        except errors.AlreadyExists:
            ...  # handle errors, you might want to modify?
        # end CREATE


async def ldap_modify_user_examples():
    async with ldap.Connection('ldap://localhost:389') as conn:
        ...  # do bind()

        # start MODIFY
        # modify a entry from old and new state dict attributes definition
        dn = f'uid=max.mustermann,{base_dn}'
        obj = await conn.get(dn)
        newattrs = (
            obj.attrs.copy()
        )  # or just use two dicts with a subset of these attributes
        newattrs.update({
            'givenName': [b'Erika'],  # change name
            'sn': [b'Musterfrau'],
            'mail': [],  # remove mail
            'title': [b'Dr.'],  # add attribute
        })
        await conn.modify(dn, obj.attrs, newattrs)

        # modify a entry from LDAP modlist definition
        ml = [
            # replace by removing any old values and add a new one
            (Mod.Delete, 'givenName', None),
            (Mod.Add, 'givenName', [b'Erika']),
            # replace via replace
            (Mod.Replace, 'sn', [b'Musterfrau']),
            # remove current value
            (Mod.Delete, 'mail', None),
            # add a new values
            (Mod.Add, 'title', [b'Dr.']),
        ]
        await conn.modify_ml(dn, ml)
        # end MODIFY


async def ldap_move_and_rename_user_examples():
    async with ldap.Connection('ldap://localhost:389') as conn:
        ...  # do bind()

        # start MOVE
        dn = f'uid=max.mustermann,{base_dn}'

        # rename a user via modify RDN
        obj = await conn.modrdn(dn, 'uid=erika.musterfrau')
        print(obj.dn)

        # rename a user by specifying the new DN
        new_dn = f'uid=erika.musterfrau,{base_dn}'
        obj = await conn.rename(dn, new_dn)
        print(obj.dn)

        # rename a user by changing the RDN values
        new_dn = f'cn=erika.musterfrau,{base_dn}'
        obj = await conn.rename(dn, new_dn, delete_old=False)
        print(obj.dn)

        # implicit rename by changing the RDN attribute
        obj = await conn.modify_ml(
            dn, [(Mod.Replace, 'uid', [b'erika.musterfrau'])]
        )  # fmt: skip
        print(obj.dn)

        # move a user, keep RDN
        new_position = f'ou=FreeIAM,{base_dn}'
        obj = await conn.move(dn, new_position)
        print(obj.dn)
        # end MOVE


async def ldap_remove_user_example():
    async with ldap.Connection('ldap://localhost:389') as conn:
        ...  # do bind()
        # start REMOVE
        dn = f'uid=max.mustermann,{base_dn}'
        try:
            await conn.delete(dn)
        except errors.AllowedOnNonleaf:
            ...  # sub objects exists
            ...  # you have to remove recursively
        # end REMOVE


async def ldap_remove_subtree_recursively_example():
    async with ldap.Connection('ldap://localhost:389') as conn:
        ...  # do bind()
        # start RECURSIVE REMOVE
        dn = f'ou=users,{base_dn}'
        await conn.delete_recursive(dn)
        # end RECURSIVE REMOVE
