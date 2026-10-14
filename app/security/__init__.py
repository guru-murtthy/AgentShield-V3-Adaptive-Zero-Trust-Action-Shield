"""Bridge package to expose security as app.security."""
from security import *  # noqa: F401, F403
import security as _sec

__all__ = _sec.__all__
