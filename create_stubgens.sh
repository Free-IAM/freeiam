#!/bin/sh
# SPDX-FileCopyrightText: 2025 Florian Best
# SPDX-License-Identifier: CC0-1.0
# Create python-ldap stubs in a nice formatted and cleaned up fashion.

export PYTHONPATH="$HOME/git/python-ldap/build/lib.linux-x86_64-cpython-313/"

stubgen -o stubs -p ldap
ruff check --fix stubs
ruff format stubs

find stubs -type f -name '*.pyi' -exec sh -c 'for f do mv -- "$f" "${f%.pyi}.py"; done' sh {} +
ruff check --fixable PLC0414,E,I --fix stubs
ruff check --fixable F401 --fix stubs  # yes, let's remove unused imports. python-ldap should define __all__!
ruff check  --statistics stubs/
find stubs -type f -name '*.py' -exec sh -c 'for f do mv -- "$f" "${f}i"; done' sh {} +

cp "$PYTHONPATH/ldap/_ldap.pyi" stubs/ldap/

ruff check --fix stubs
ruff format stubs
