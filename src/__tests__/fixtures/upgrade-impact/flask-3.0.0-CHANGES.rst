Version 3.0.0
-------------

Released 2023-09-30

-   Remove previously deprecated code. :pr:`5223`
-   Deprecate the ``__version__`` attribute. Use feature detection, or
    ``importlib.metadata.version("flask")``, instead. :issue:`5230`
-   Restructure the code such that the Flask (app) and Blueprint
    classes have Sans-IO bases. :pr:`5127`
-   Allow self as an argument to url_for. :pr:`5264`
-   Require Werkzeug >= 3.0.0.


Version 2.3.3
-------------

Released 2023-08-21

-   Python 3.12 compatibility.
-   Require Werkzeug >= 2.3.7.
-   Use ``flit_core`` instead of ``setuptools`` as build backend.
-   Refactor how an app's root and instance paths are determined. :issue:`5160`


Version 2.3.2
-------------

Released 2023-05-01

-   Set ``Vary: Cookie`` header when the session is accessed, modified, or refreshed.
-   Update Werkzeug requirement to >=2.3.3 to apply recent bug fixes.


Version 2.3.1
-------------

Released 2023-04-25

-   Restore deprecated ``from flask import Markup``. :issue:`5084`


Version 2.3.0
-------------

Released 2023-04-25
