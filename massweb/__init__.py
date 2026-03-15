"""MassWeb package compatibility helpers."""

import builtins


# The original codebase expects Python 2's ``unicode`` type to exist.
# Provide a small compatibility shim so the package can run under Python 3.
if not hasattr(builtins, "unicode"):
    # Local module-level alias for Python 3 compatibility
    # Note: This is a temporary shim; proper fix is to use 'str' directly
    unicode = str
else:
    unicode = builtins.unicode
