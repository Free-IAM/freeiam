.PHONY: test docs docs-open lint format build upload changelog publish coverage benchmark pre-commit-install

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
	-pre-commit run -a

lint-fix:
	-pre-commit run -a --hook-stage manual ruff-fix

format:
	-pre-commit run -a --hook-stage manual ruff-format

changelog:
	-semantic-release version

publish:
	-semantic-release publish

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

pre-commit-install:
	pre-commit install
