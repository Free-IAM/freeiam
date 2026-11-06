# SPDX-FileCopyrightText: 2026 Florian Best
# SPDX-License-Identifier: CC0-1.0

DOCKER ?= docker
OPENLDAP_VERSION ?= 2.6.10
CRUDEOAUTH_REF ?= master

OVERLAYS := noopsrch usn
OVERLAY_MODULES := $(addprefix entrypoint/,$(addsuffix .so,$(OVERLAYS)))
OAUTHBEARER_MODULE := entrypoint/liboauthbearer.so

.PHONY: all clean overlays oauthbearer

all: $(OVERLAY_MODULES) $(OAUTHBEARER_MODULE)

overlays: $(OVERLAY_MODULES)
oauthbearer: $(OAUTHBEARER_MODULE)

$(OVERLAY_MODULES) &: Dockerfile Makefile
	$(DOCKER) build \
	    --file Dockerfile \
	    --build-arg OPENLDAP_VERSION=$(OPENLDAP_VERSION) \
	    --target artifact \
	    --output type=local,dest=entrypoint .

$(OAUTHBEARER_MODULE): Dockerfile.crudeoauth Makefile
	$(DOCKER) build \
	    --file Dockerfile.crudeoauth \
	    --build-arg CRUDEOAUTH_REF=$(CRUDEOAUTH_REF) \
	    --target artifact \
	    --output type=local,dest=entrypoint .

clean:
	rm -f $(OVERLAY_MODULES) $(OAUTHBEARER_MODULE)
