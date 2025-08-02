# SPDX-FileCopyrightText: 2025 Florian Best
# SPDX-License-Identifier: MIT OR Apache-2.0
"""FreeIAM version."""

__all__ = ['__version__', '__version_tuple__', 'version', 'version_tuple']

from importlib.metadata import version as get_version


def _parse_version_tuple(ver: str) -> tuple[int, ...]:
    return tuple(int(part) for part in ver.split('.') if part.isdigit())


__version__ = version = get_version(__package__)
__version_tuple__ = version_tuple = _parse_version_tuple(__version__)
