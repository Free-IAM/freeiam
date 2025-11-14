# Developer Guide

This document provides development-focused notes and references for contributors working on FreeIAM.

---

## Overview

FreeIAM uses a Makefile to streamline common development tasks. Instead of memorizing long commands, you can rely on concise `make` targets during development, testing, building, and releasing.

All commands can also be executed directly (e.g. via `tox`, `pre-commit`, or `semantic-release`), but the Makefile serves as a convenient shortcut.

---

## Makefile Targets

Below is an overview of the most relevant development commands defined in the Makefile.

### Testing

* **`make test`**
  Runs the full test suite using `tox`.

* **`make testenv`**
  Creates a tox development environment (`py311`) and activates it.

### Documentation

* **`make docs`**
  Builds the documentation.

* **`make docs-open`**
  Opens the HTML documentation in the browser.

### Linting & Formatting

* **`make lint`**
  Runs all linters via `pre-commit`.

* **`make lint-fix`**
  Automatically fixes issues using the `ruff-fix` hook.

* **`make format`**
  Applies formatting with the `ruff-format` hook.

### Release Management

FreeIAM uses **semantic-release** to automate versioning and publishing.

* **`make changelog`**
  Creates a new version, updates the changelog, creates a commit, and tags the release locally.
  The commit includes the marker `[create-release!]`, which triggers the GitHub Actions workflow responsible for publishing the release to PyPI.

* **`make preview-changelog`**
  Generates a preview of how the changelog would look without modifying the repository.

### Build & Upload

* **`make build`**
  Builds source and wheel distributions using `python -m build`.

* **`make upload`**
  Uploads distribution artifacts to PyPI via `twine`.

### Coverage

* **`make coverage`**
  Generates an HTML coverage report.

### Benchmarking

* **`make benchmark`**
  Runs benchmarks and creates both CSV and JSON outputs for comparison.

### Copyright & Licensing

* **`make copyright`**
  Runs REUSE annotation and linting via `pre-commit`.

### Pre-commit Hooks

* **`make pre-commit-install`**
  Installs all configured `pre-commit` hooks locally.

---

## Release Workflow

To create a new release:

1. Run:

   ```sh
   make changelog
   ```
2. This command:

   * Computes the next semantic version
   * Updates `CHANGELOG.md`
   * Updates version number in `pyproject.toml`
   * Commits the changelog update with `[create-release!]` in the message
   * Creates a version tag
3. The GitHub Actions pipeline sees the `[create-release!]` marker and publishes the new version to PyPI.

---

## Additional Notes

For information on project setup, coding conventions, style rules, and how to contribute patches, see **`CONTRIBUTING.md`**.
