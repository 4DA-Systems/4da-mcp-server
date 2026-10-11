.. currentmodule:: werkzeug

Version 3.0.0
-------------

Released 2023-09-30

-   Remove previously deprecated code. :pr:`2768`
-   Deprecate the ``__version__`` attribute. Use feature detection, or
    ``importlib.metadata.version("werkzeug")``, instead. :issue:`2770`
-   ``generate_password_hash`` uses scrypt by default. :issue:`2769`
-   Add the ``"werkzeug.profiler"`` item to the  WSGI ``environ`` dictionary
    passed to `ProfilerMiddleware`'s `filename_format` function. It contains
    the ``elapsed`` and ``time`` values for the profiled request. :issue:`2775`
-   Explicitly marked the PathConverter as non path isolating. :pr:`2784`


Version 2.3.8
-------------

