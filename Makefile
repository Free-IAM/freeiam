# SPDX-FileCopyrightText: 2025 Florian Best
# SPDX-License-Identifier: CC0-1.0

.PHONY: test docs docs-open lint format build upload changelog publish coverage benchmark copyright prek-install

test:
	-tox

docs:
	-tox -e docs

docs-open:
	-xdg-open docs/_build/html/index.html

testenv:
	-tox -e py311 --develop
	-. .tox/py311/bin/activate

lint:
	-prek run -a

lint-fix:
	-prek run -a --hook-stage manual ruff-fix

format:
	-prek run -a --hook-stage manual ruff-format

changelog:
	semantic-release version --no-push --skip-build --changelog

preview-changelog:
	semantic-release changelog
	git diff CHANGELOG.md
	git checkout CHANGELOG.md

publish:
	semantic-release publish

build:
	python -m build

upload:
	twine upload dist/*

coverage:
	-coverage html

benchmark:
	-pytest -m benchmark_only --benchmark-only --benchmark-save=ldap_run
	-pytest-benchmark compare --csv > benchmark.csv
	-pytest-benchmark compare --json > benchmark.json

copyright:
	-prek run -a --hook-stage manual reuse-annotate
	-prek run -a --hook-stage manual reuse-lint

prek-install:
	prek install
