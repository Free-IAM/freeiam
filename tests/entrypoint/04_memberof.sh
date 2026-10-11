#!/bin/bash
# SPDX-FileCopyrightText: 2025 Broadcom
# SPDX-License-Identifier: Apache-2.0
# Script to enable memberOf overlay in OpenLDAP
set -e

CONFIG_DIR=/opt/bitnami/openldap/etc/slapd.d

cat > /tmp/memberof-overlay.ldif << 'EOF'
dn: cn=module{4},cn=config
objectClass: olcModuleList
cn: module{4}
olcModuleLoad: memberof

dn: olcOverlay=memberof,olcDatabase={2}mdb,cn=config
objectClass: olcOverlayConfig
objectClass: olcMemberOf
olcOverlay: memberof
olcMemberOfDangling: ignore
olcMemberOfRefInt: TRUE
olcMemberOfGroupOC: posixGroup
olcMemberOfMemberAD: uniqueMember
olcMemberOfMemberOfAD: memberOf
# olcMemberOfDN
# olcMemberOfDanglingError
# olcMemberOfAddCheck
EOF

echo "Enabling memberOf overlay in OpenLDAP configuration..."
echo "Loading memberOf overlay with slapadd..."

if slapcat -F "$CONFIG_DIR" -b cn=config | grep -q memberof
then
    echo "MemberOf overlay is already configured."
    exit 0
else
    slapadd -F "$CONFIG_DIR" -b cn=config -l /tmp/memberof-overlay.ldif || {
        echo "NOTICE: slapadd failed to load memberOf overlay. Check the cn=module{N}"
        slapcat -F "$CONFIG_DIR" -b cn=config | grep cn=module
        exit 1
    }
fi

echo "MemberOf overlay has been configured."
