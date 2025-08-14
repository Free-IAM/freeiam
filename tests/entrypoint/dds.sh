#!/bin/bash
# SPDX-FileCopyrightText: 2025 Broadcom
# SPDX-License-Identifier: Apache-2.0
# Script to enable dds overlay in OpenLDAP
set -e

cat > /tmp/dds-overlay.ldif << 'EOF'
dn: cn=module{1},cn=config
objectClass: olcModuleList
cn: module{1}
olcModuleLoad: dds

dn: olcOverlay=dds,olcDatabase={2}mdb,cn=config
objectClass: olcOverlayConfig
objectClass: olcDDSconfig
olcOverlay: dds
olcDDSMaxTTL: 31536000
olcDDSMinTTL: 10
olcDDSDefaultTTL: 86400
EOF

echo "Enabling dds overlay in OpenLDAP configuration..."
if slapcat -F /opt/bitnami/openldap/etc/slapd.d -b cn=config | grep -q dds
then
    echo "DDS overlay is already configured."
    exit 0
else
    slapadd -F /opt/bitnami/openldap/etc/slapd.d -b cn=config -l /tmp/dds-overlay.ldif || {
        echo "NOTICE: slapadd failed to load dds overlay. Check the cn=module{N} with \"slapcat -F /opt/bitnami/openldap/etc/slapd.d -b cn=config |grep 'cn=module'\""
        exit 1
    }
fi

echo "DDS overlay has been configured."
