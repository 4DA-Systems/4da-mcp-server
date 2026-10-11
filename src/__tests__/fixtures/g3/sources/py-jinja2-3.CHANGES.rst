.. currentmodule:: jinja2

Version 3.0.0
-------------

Released 2021-05-11

-   Drop support for Python 2.7 and 3.5.
-   Bump MarkupSafe dependency to >=1.1.
-   Bump Babel optional dependency to >=2.1.
-   Remove code that was marked deprecated.
-   Add type hinting. :pr:`1412`
-   Use :pep:`451` API to load templates with
    :class:`~loaders.PackageLoader`. :issue:`1168`
-   Fix a bug that caused imported macros to not have access to the
    current template's globals. :issue:`688`
-   Add ability to ignore ``trim_blocks`` using ``+%}``. :issue:`1036`
-   Fix a bug that caused custom async-only filters to fail with
    constant input. :issue:`1279`
-   Fix UndefinedError incorrectly being thrown on an undefined variable
    instead of ``Undefined`` being returned on
    ``NativeEnvironment`` on Python 3.10. :issue:`1335`
-   Blocks can be marked as ``required``. They must be overridden at
    some point, but not necessarily by the direct child. :issue:`1147`
-   Deprecate the ``autoescape`` and ``with`` extensions, they are
    built-in to the compiler. :issue:`1203`
-   The ``urlize`` filter recognizes ``mailto:`` links and takes
    ``extra_schemes`` (or ``env.policies["urlize.extra_schemes"]``) to
    recognize other schemes. It tries to balance parentheses within a
    URL instead of ignoring trailing characters. The parsing in general
    has been updated to be more efficient and match more cases. URLs
    without a scheme are linked as ``https://`` instead of ``http://``.
    :issue:`522, 827, 1172`, :pr:`1195`
-   Filters that get attributes, such as ``map`` and ``groupby``, can
    use a false or empty value as a default. :issue:`1331`
-   Fix a bug that prevented variables set in blocks or loops from
    being accessed in custom context functions. :issue:`768`
-   Fix a bug that caused scoped blocks from accessing special loop
    variables. :issue:`1088`
-   Update the template globals when calling
    ``Environment.get_template(globals=...)`` even if the template was
    already loaded. :issue:`295`
-   Do not raise an error for undefined filters in unexecuted
    if-statements and conditional expressions. :issue:`842`
-   Add ``is filter`` and ``is test`` tests to test if a name is a
    registered filter or test. This allows checking if a filter is
    available in a template before using it. Test functions can be
    decorated with ``@pass_environment``, ``@pass_eval_context``,
    or ``@pass_context``. :issue:`842`, :pr:`1248`
-   Support ``pgettext`` and ``npgettext`` (message contexts) in i18n
    extension. :issue:`441`
-   The ``|indent`` filter's ``width`` argument can be a string to
    indent by. :pr:`1167`
-   The parser understands hex, octal, and binary integer literals.
    :issue:`1170`
-   ``Undefined.__contains__`` (``in``) raises an ``UndefinedError``
    instead of a ``TypeError``. :issue:`1198`
-   ``Undefined`` is iterable in an async environment. :issue:`1294`
-   ``NativeEnvironment`` supports async mode. :issue:`1362`
-   Template rendering only treats ``\n``, ``\r\n`` and ``\r`` as line
    breaks. Other characters are left unchanged. :issue:`769, 952, 1313`
-   ``|groupby`` filter takes an optional ``default`` argument.
    :issue:`1359`
-   The function and filter decorators have been renamed and unified.
    The old names are deprecated. :issue:`1381`

    -   ``pass_context`` replaces ``contextfunction`` and
        ``contextfilter``.
    -   ``pass_eval_context`` replaces ``evalcontextfunction`` and
        ``evalcontextfilter``
    -   ``pass_environment`` replaces ``environmentfunction`` and
        ``environmentfilter``.

-   Async support no longer requires Jinja to patch itself. It must
    still be enabled with ``Environment(enable_async=True)``.
    :issue:`1390`
-   Overriding ``Context.resolve`` is deprecated, override
    ``resolve_or_missing`` instead. :issue:`1380`


Version 2.11.3
--------------

