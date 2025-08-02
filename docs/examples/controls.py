from ldap.controls.readentry import PostReadControl

from freeiam import ldap


base_dn = 'dc=freeiam,dc=org'


def decode(self, values, encoding='UTF-8'):
    return values[0].decode(encoding)


async def ldap_create_user_examples():
    async with ldap.Connection('ldap://localhost:389') as conn:
        ...  # do bind()

        post_read_control = PostReadControl(
            True,
            [
                '*',  # every regular attribute
                '+',  # every operational attribute (metadata)
            ],
        )
        # receive the e.g. entryUUID directly after creations
        dn = f'uid=max.mustermann,{base_dn}'
        attrs = {
            'objectClass': [b'inetOrgPerson'],
            'uid': [b'max.mustermann'],
            'cn': [b'Max Mustermann'],
            'givenName': [b'Max'],
            'sn': [b'Mustermann'],
            'mail': [b'max.mustermann@freeiam.org'],
        }
        result = await conn.add(dn, attrs, controls=[post_read_control])
        print(result.dn, result.attrs)

        entry = result.controls.get(post_read_control).entry
        print(decode(entry['entryUUID']))
        print(decode(entry['entryCSN']))
        print(decode(entry['creatorsName']))
        print(decode(entry['createTimestamp']))
        print(decode(entry['modifyTimestamp']))
        print(decode(entry['modifiersName']))
