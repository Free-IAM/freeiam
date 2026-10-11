#!/bin/bash
# SPDX-FileCopyrightText: 2025 Florian Best
# SPDX-License-Identifier: MIT OR Apache-2.0
set -Eeuo pipefail

CONFIG_DIR=/opt/bitnami/openldap/etc/slapd.d
SCRIPT_DIR=$(dirname "$0")
shopt -s nullglob

mapfile -t files < <(printf '%s\n' "$SCRIPT_DIR"/*.ldif)
total=${#files[@]}
configured=0
skipped=0

printf 'Configuring OpenLDAP overlays (%d LDIF files)\n' "$total"

for index in "${!files[@]}"; do
    file=${files[$index]}
    name=$(basename "$file")
    mapfile -t markers < <(grep -E '^olc(Overlay|ModuleLoad): ' "$file" || true)
    already_configured=true

    for marker in "${markers[@]}"; do
        if ! slapcat -F "$CONFIG_DIR" -b cn=config | grep -Fq "$marker"; then
            already_configured=false
            break
        fi
    done

    printf '[%d/%d] %-24s ' "$((index + 1))" "$total" "$name"
    if "$already_configured"; then
        printf 'already configured\n'
        ((skipped += 1))
        continue
    fi

    if slapadd -F "$CONFIG_DIR" -b cn=config -l "$file"; then
        printf 'configured\n'
        ((configured += 1))
    else
        printf 'FAILED\n' >&2
        printf '  Check module indexes and availability for %s.\n' "$name" >&2
        slapcat -F "$CONFIG_DIR" -b cn=config | grep 'cn=module' || true
        exit 1
    fi
done

printf 'Overlay configuration complete: %d configured, %d already configured.\n' "$configured" "$skipped"
