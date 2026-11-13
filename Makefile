# SPDX-FileCopyrightText: 2025 Florian Best
# SPDX-License-Identifier: CC0-1.0

.PHONY: test docs docs-open build upload changelog publish coverage benchmark benchmark-connection benchmark-filter benchmark-dn benchmark-readme copyright prek-install lint lint-all clang clang-check ruff-check ruff-fix ruff-unsafe-fix ruff-statistics ruff-preview-statistics ruff-unsafe-preview-fix format-check format

PRE_COMMIT=prek
UV=uv

test:
	-tox

docs:
	tox -e docs

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
	$(PRE_COMMIT) run -a --hook-stage manual ruff-fix || true
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
	$(PRE_COMMIT) run -a --hook-stage manual ruff-format-fix || true
	$(PRE_COMMIT) run -a --hook-stage manual ruff-format-fix

changelog:
	PREK_SKIP=ruff,mypy,ty $(UV) run semantic-release version --no-push --skip-build --changelog --commit

next-version:
	$(UV) run semantic-release version --no-push --skip-build --changelog --no-commit --no-tag

preview-changelog:
	$(UV) run semantic-release changelog
	git diff CHANGELOG.md
	git checkout CHANGELOG.md

publish:
	$(UV) run semantic-release publish

build:
	python -m build

upload:
	twine upload dist/*

coverage:
	-coverage html

benchmark:
	$(MAKE) benchmark-readme

benchmark-connection:
	$(UV) run --group test --group benchmark pytest -c pytest_benchmark.ini benchmarks/test_search.py --benchmark-only --benchmark-save=ldap_connection
	$(UV) run --group test --group benchmark pytest-benchmark compare --csv connection-benchmark.csv

benchmark-filter:
	$(UV) run --group test pytest --noconftest -c pytest_benchmark.ini benchmarks/test_filter.py --benchmark-only --benchmark-save=ldap_filter
	$(UV) run --group test pytest-benchmark compare --csv filter-benchmark.csv

benchmark-dn:
	$(UV) run --group test pytest --noconftest -c pytest_benchmark.ini benchmarks/test_dn.py --benchmark-only --benchmark-save=ldap_dn
	$(UV) run --group test pytest-benchmark compare --csv dn-benchmark.csv

benchmark-readme: benchmark-connection benchmark-filter benchmark-dn
	$(UV) run python benchmarks/update_readme_tables.py

copyright:
	-prek run -a --hook-stage manual reuse-annotate
	-prek run -a --hook-stage manual reuse-lint

prek-install:
	prek install
