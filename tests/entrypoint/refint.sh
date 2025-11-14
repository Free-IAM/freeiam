#!/bin/bash
# SPDX-FileCopyrightText: 2025 Broadcom
# SPDX-License-Identifier: Apache-2.0
# Script to enable refint overlay in OpenLDAP
set -e

cat > /tmp/refint-overlay.ldif << 'EOF'
dn: cn=module{5},cn=config
objectClass: olcModuleList
cn: module{1}
olcModuleLoad: refint

dn: olcOverlay=refint,olcDatabase={2}mdb,cn=config
objectClass: olcOverlayConfig
objectClass: olcRefintConfig
olcOverlay: refint
olcRefintAttribute: uniqueMember
# olcRefintNothing
# olcRefintModifiersName
EOF

echo "Enabling refint overlay in OpenLDAP configuration..."
if slapcat -F /opt/bitnami/openldap/etc/slapd.d -b cn=config | grep -q refint
then
    echo "refint overlay is already configured."
    exit 0
else
    slapadd -F /opt/bitnami/openldap/etc/slapd.d -b cn=config -l /tmp/refint-overlay.ldif || {
        echo "NOTICE: slapadd failed to load refint overlay. Check the cn=module{N}"
        slapcat -F /opt/bitnami/openldap/etc/slapd.d -b cn=config | grep cn=module
        exit 1
    }
fi

echo "refint overlay has been configured."
