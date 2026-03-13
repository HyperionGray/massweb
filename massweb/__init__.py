"""MassWeb package compatibility helpers."""

import builtins


# The original codebase expects Python 2's ``unicode`` type to exist.
# Provide a small compatibility shim so the package can run under Python 3.
if not hasattr(builtins, "unicode"):
    builtins.unicode = str
