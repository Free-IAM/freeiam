from collections.abc import Sequence
from typing import Any

from _typeshed import Incomplete

class Constant:
    c_template: str | None
    name: Incomplete
    requirements: Incomplete
    doc: Incomplete
    def __init__(self, name: str, optional: bool = ..., requirements: Sequence[str] = ..., doc: str | None = ...) -> None: ...

class Error(Constant):
    c_template: str

class Int(Constant):
    c_template: str

class TLSInt(Int):
    def __init__(self, *args: Any, **kwargs: Any) -> None: ...

class Feature(Constant):
    c_template: Incomplete
    c_feature: Incomplete
    def __init__(self, name: str, c_feature: str, **kwargs: Any) -> None: ...

class Str(Constant):
    c_template: str

API_2004: str
CONSTANTS: Incomplete

def print_header() -> None: ...
