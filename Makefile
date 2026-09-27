# SPDX-FileCopyrightText: 2025 Florian Best
# SPDX-License-Identifier: CC0-1.0

.PHONY: test docs docs-open build upload changelog publish coverage benchmark copyright prek-install lint lint-all clang clang-check ruff-check ruff-fix ruff-unsafe-fix ruff-statistics ruff-preview-statistics ruff-unsafe-preview-fix format-check format

PRE_COMMIT=prek

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
	{ git diff --name-only; git ls-files --others --exclude-standard; git diff --cached --name-only; } | xargs $(PRE_COMMIT) run --files

lint-all:
	$(PRE_COMMIT) run -a

clang:
	$(PRE_COMMIT) run -a --hook-stage manual clang-format-fix

clang-check:
	$(PRE_COMMIT) run -a clang-format-check

ruff-check:
	$(PRE_COMMIT) run -a ruff

ruff-fix:
	$(PRE_COMMIT) run -a --hook-stage manual ruff-fix

ruff-unsafe-fix:
	$(PRE_COMMIT) run -a --hook-stage manual ruff-unsafe-fix

ruff-statistics:
	$(PRE_COMMIT) run -a --hook-stage manual ruff-statistics

ruff-preview-statistics:
	$(PRE_COMMIT) run -a --hook-stage manual ruff-preview-statistics

ruff-unsafe-preview-fix:
	$(PRE_COMMIT) run -a --hook-stage manual ruff-unsafe-preview-fix

format-check:
	$(PRE_COMMIT) run -a ruff-format-check

format:
	$(PRE_COMMIT) run -a --hook-stage manual ruff-format-fix

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
