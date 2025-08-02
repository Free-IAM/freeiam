import datetime
import pathlib
import sys

from setuptools_scm import get_version


sys.path.insert(0, str((pathlib.Path.cwd() / '..').resolve()))

START = 2025
year = datetime.datetime.now(tz=datetime.UTC).date().year

project = 'FreeIAM'
copyright = str(year) if year == START else f'2025-{year}'
author = 'Florian Best'
release = get_version(root='../', relative_to=__file__)
version = '.'.join(release.split('.')[:2])


extensions = [
    'sphinx.ext.autodoc',
    'sphinx.ext.napoleon',
    'sphinx.ext.viewcode',
]

templates_path = ['_templates']
exclude_patterns = []

html_theme = 'furo'  # 'sphinx_rtd_theme'
html_static_path = ['_static']
