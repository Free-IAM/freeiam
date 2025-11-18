import datetime
import pathlib
import sys


sys.path.insert(0, str((pathlib.Path.cwd() / '..').resolve()))
from freeiam._version import version


START = 2025
year = datetime.datetime.now(tz=datetime.UTC).date().year

project = 'FreeIAM'
copyright = str(year) if year == START else f'2025-{year}'
author = 'Florian Best'
version = '.'.join(version.split('.')[:2])


extensions = [
    'sphinx.ext.autodoc',
    'sphinx.ext.doctest',
    'sphinx.ext.napoleon',
    'sphinx.ext.viewcode',
]

templates_path = ['_templates']
exclude_patterns = []

html_theme = 'furo'  # 'sphinx_rtd_theme'
html_static_path = ['_static']
pygments_style = 'sphinx'

html_theme_options = {
    # 'navigation_depth': 4,
    'sidebar_hide_name': False,
}
