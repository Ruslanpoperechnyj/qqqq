"""Small adapters for migrated settings-aware callbacks and legacy test/plugins."""
from __future__ import annotations

import inspect


def call_with_settings(fn, *args, settings=None, **kwargs):
    """Pass ``settings`` only when a legacy callable accepts it.

    Production consumers receive the immutable Settings snapshot. Older injected
    callbacks with their pre-migration signature continue to work unchanged.
    """
    if settings is None:
        return fn(*args, **kwargs)
    try:
        parameters = inspect.signature(fn).parameters.values()
        accepts_settings = any(
            item.name == "settings" or item.kind is inspect.Parameter.VAR_KEYWORD
            for item in parameters
        )
    except (TypeError, ValueError):
        accepts_settings = True
    if accepts_settings:
        kwargs["settings"] = settings
    return fn(*args, **kwargs)
