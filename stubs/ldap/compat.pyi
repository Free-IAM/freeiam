from collections import UserDict
from types import TracebackType
from typing import NoReturn

IterableUserDict = UserDict

def reraise(exc_type: type[BaseException], exc_value: BaseException, exc_traceback: TracebackType | None) -> NoReturn: ...
