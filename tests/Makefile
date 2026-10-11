# SPDX-FileCopyrightText: 2026 Florian Best
# SPDX-License-Identifier: CC0-1.0

DOCKER ?= docker
OPENLDAP_VERSION ?= 2.6.10

OVERLAYS := noopsrch
MODULES := $(addprefix entrypoint/,$(addsuffix .so,$(OVERLAYS)))

.PHONY: all clean

all: $(MODULES)

$(MODULES) &: Dockerfile Makefile
	$(DOCKER) build \
		--build-arg OPENLDAP_VERSION=$(OPENLDAP_VERSION) \
		--target artifact \
		--output type=local,dest=entrypoint .

clean:
	rm -f $(MODULES)
