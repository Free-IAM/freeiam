import pathlib
import sys


sys.path.insert(0, str((pathlib.Path.cwd() / '..').resolve()))

project = 'FreeIAM'
copyright = '2025'
author = 'Florian Best'
release = '0.1.0'

extensions = [
    'sphinx.ext.autodoc',
    'sphinx.ext.napoleon',
    'sphinx.ext.viewcode',
]

templates_path = ['_templates']
exclude_patterns = []

html_theme = 'furo'  # 'sphinx_rtd_theme'
html_static_path = ['_static']
