Version 3.0.0
-------------

Released 2024-08-07

-   Support Python 3.13 and its experimental free-threaded build. :pr:`461`
-   Drop support for Python 3.7 and 3.8.
-   Use modern packaging metadata with ``pyproject.toml`` instead of ``setup.cfg``.
    :pr:`348`
-   Change ``distutils`` imports to ``setuptools``. :pr:`399`
-   Use deferred evaluation of annotations. :pr:`400`
-   Update signatures for ``Markup`` methods to match ``str`` signatures. Use
    positional-only arguments. :pr:`400`
-   Some ``str`` methods on ``Markup`` no longer escape their argument:
    ``strip``, ``lstrip``, ``rstrip``, ``removeprefix``, ``removesuffix``,
    ``partition``, and ``rpartition``; ``replace`` only escapes its ``new``
    argument. These methods are conceptually linked to search methods such as
    ``in``, ``find``, and ``index``, which already do not escape their argument.
    :issue:`401`
-   The ``__version__`` attribute is deprecated. Use feature detection, or
    ``importlib.metadata.version("markupsafe")``, instead. :pr:`402`
-   Speed up escaping plain strings by 40%. :pr:`434`
-   Simplify speedups implementation. :pr:`437`


Version 2.1.5
-------------

