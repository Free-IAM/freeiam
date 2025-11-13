#!/bin/bash
# SPDX-FileCopyrightText: 2025 Broadcom
# SPDX-License-Identifier: Apache-2.0
# Script to enable sssvlv overlay in OpenLDAP
set -e

cat > /tmp/sssvlv-overlay.ldif << 'EOF'
dn: cn=module{6},cn=config
objectClass: olcModuleList
cn: module{1}
olcModuleLoad: sssvlv

dn: olcOverlay=sssvlv,olcDatabase={2}mdb,cn=config
objectClass: olcOverlayConfig
objectClass: olcSssVlvConfig
olcOverlay: sssvlv
olcSssVlvMax: 100
olcSssVlvMaxKeys: 20
olcSssVlvMaxPerConn: 5
EOF

echo "Enabling sssvlv overlay in OpenLDAP configuration..."
if slapcat -F /opt/bitnami/openldap/etc/slapd.d -b cn=config | grep -q sssvlv
then
    echo "SSS VLV overlay is already configured."
    exit 0
else
    slapadd -F /opt/bitnami/openldap/etc/slapd.d -b cn=config -l /tmp/sssvlv-overlay.ldif || {
        echo "NOTICE: slapadd failed to load sssvlv overlay. Check the cn=module{N}"
        slapcat -F /opt/bitnami/openldap/etc/slapd.d -b cn=config | grep cn=module
        exit 1
    }
fi

echo "SSS VLV overlay has been configured."
