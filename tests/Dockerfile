# SPDX-FileCopyrightText: 2026 Florian Best
# SPDX-License-Identifier: CC0-1.0

FROM debian:bookworm-slim AS builder

ARG OPENLDAP_VERSION=2.6.10

RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential ca-certificates curl file libdb-dev libtool pkg-config \
    libltdl-dev groff-base \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /src
RUN curl --fail --location --show-error --silent \
      "https://www.openldap.org/software/download/OpenLDAP/openldap-release/openldap-${OPENLDAP_VERSION}.tgz" \
      --output openldap.tgz \
    && tar -xzf openldap.tgz \
    && mv "openldap-${OPENLDAP_VERSION}" openldap

WORKDIR /src/openldap
ENV CFLAGS="-O2 -fPIC -ffile-prefix-map=/build=/usr/src/openldap"
ENV SOURCE_DATE_EPOCH=0

# Fix USN schema definitions for OpenLDAP
RUN sed -i \
        -e 's/1\.2\.840\.113556\.1\.4\.906/1.3.6.1.4.1.1466.115.121.1.27/g' \
        -e 's/NO-USER-MODIFICATION )/NO-USER-MODIFICATION USAGE directoryOperation )/g' \
        contrib/slapd-modules/usn/usn.c

RUN ./configure \
        --enable-slapd \
        --enable-modules \
        --with-tls=no \
        --with-cyrus-sasl=no \
    && make -j2

ARG OVERLAYS="noopsrch usn"

RUN set -eu; \
    mkdir -p /out; \
    for overlay in $OVERLAYS; do \
        make -C "contrib/slapd-modules/$overlay"; \
        cp -L "contrib/slapd-modules/$overlay/.libs/$overlay.so" \
            "/out/$overlay.so"; \
        strip --strip-debug "/out/$overlay.so"; \
        file "/out/$overlay.so"; \
    done; \
    echo  # cp LICENSE /out/OLDAP-2.8.txt

FROM scratch AS artifact
COPY --from=builder /out/ /
