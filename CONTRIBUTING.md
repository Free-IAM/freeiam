# Contributing

Thank you for your interest in contributing to FreeIAM!

We welcome contributions of all kinds — bug reports, feature ideas, code, documentation, and tests.

---

## Prerequisites

Before contributing, please make sure you have the following installed:

- Python ≥ 3.10
- [`uv`](https://github.com/astral-sh/uv) for environment management
- [`prek`](https://prek.j178.dev/)
- Git configured to use [Conventional Commits](https://www.conventionalcommits.org/)
- [`tox`](https://tox.readthedocs.io/)
- [`reuse`](https://reuse.software/)

---

## Setup

```bash
# Clone the repository
git clone https://github.com/Free-IAM/freeiam.git
cd freeiam

# Set up the environment
uv venv
source .venv/bin/activate

# Install development dependencies
uv pip install -r requirements-dev.txt

# Set up prek hooks
prek install
prek run --all-files
```

---

## Commit conventions

We follow the [Conventional Commits](https://www.conventionalcommits.org/) specification:

```
<type>(<scope>): <description>
```

---

## Pull Requests

- Apply principles of Clean Code.
- Include a clear description of _what_ you changed and _why_.
- Link any related issues.
- All prek pre-commit checks and tox test environments should pass.

---

## Style & Linting

We use [`ruff`](https://docs.astral.sh/ruff/) for linting and formatting.

It is automatically run via `prek`. You can also run it manually:

```bash
ruff check .
ruff format .
```

---

## Testing

We use `pytest`, managed via `tox`.

Run all tests:

```bash
tox
```

Run a specific environment (e.g. Python 3.11):

```bash
tox -e py311
```

Check coverage:

```bash
pytest --cov
```

---

## Documentation

Documentation is written in reStructuredText using Sphinx and hosted on Read the Docs.

To build the docs locally:

```bash
tox -e docs
```

The output will be available under `docs/_build/html/index.html`.

---

## Licensing

We use the [REUSE specification](https://reuse.software/) for license compliance.

To check compliance:

```bash
reuse lint
```

To add copyright/license:

```bash
reuse annotate <filename>
```

Make sure all contributions are REUSE-compliant before submission.

By submitting a pull request, you agree to license your contributions under the project's license.

---
