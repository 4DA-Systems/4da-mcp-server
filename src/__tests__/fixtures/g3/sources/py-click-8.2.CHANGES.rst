.. currentmodule:: click

Version 8.2.0
-------------

Released 2025-05-10

-   Drop support for Python 3.7, 3.8, and 3.9. :pr:`2588` :pr:`2893`
-   Use modern packaging metadata with ``pyproject.toml`` instead of ``setup.cfg``.
    :pr:`2438`
-   Use ``flit_core`` instead of ``setuptools`` as build backend. :pr:`2543`
-   Deprecate the ``__version__`` attribute. Use feature detection, or
    ``importlib.metadata.version("click")``, instead. :issue:`2598`
-   ``BaseCommand`` is deprecated. ``Command`` is the base class for all
    commands. :issue:`2589`
-   ``MultiCommand`` is deprecated. ``Group`` is the base class for all group
    commands. :issue:`2590`
-   The current parser and related classes and methods, are deprecated.
    :issue:`2205`

    -   ``OptionParser`` and the ``parser`` module, which is a modified copy of
        ``optparse`` in the standard library.
    -   ``Context.protected_args`` is unneeded. ``Context.args`` contains any
        remaining arguments while parsing.
    -   ``Parameter.add_to_parser`` (on both ``Argument`` and ``Option``) is
        unneeded. Parsing works directly without building a separate parser.
    -   ``split_arg_string`` is moved from ``parser`` to ``shell_completion``.

-   Enable deferred evaluation of annotations with
    ``from __future__ import annotations``. :pr:`2270`
-   When generating a command's name from a decorated function's name, the
    suffixes ``_command``, ``_cmd``, ``_group``, and ``_grp`` are removed.
    :issue:`2322`
-   Show the ``types.ParamType.name`` for ``types.Choice`` options within
    ``--help`` message if ``show_choices=False`` is specified.
    :issue:`2356`
-   Do not display default values in prompts when ``Option.show_default`` is
    ``False``. :pr:`2509`
-   Add ``get_help_extra`` method on ``Option`` to fetch the generated extra
    items used in ``get_help_record`` to render help text. :issue:`2516`
    :pr:`2517`
-   Keep stdout and stderr streams independent in ``CliRunner``. Always
    collect stderr output and never raise an exception. Add a new
    output stream to simulate what the user sees in its terminal. Removes
    the ``mix_stderr`` parameter in ``CliRunner``. :issue:`2522` :pr:`2523`
-   ``Option.show_envvar`` now also shows environment variable in error messages.
    :issue:`2695` :pr:`2696`
-   ``Context.close`` will be called on exit. This results in all
    ``Context.call_on_close`` callbacks and context managers added via
    ``Context.with_resource`` to be closed on exit as well. :pr:`2680`
-   Add ``ProgressBar(hidden: bool)`` to allow hiding the progressbar. :issue:`2609`
-   A ``UserWarning`` will be shown when multiple parameters attempt to use the
    same name. :issue:`2396`
-   When using ``Option.envvar`` with ``Option.flag_value``, the ``flag_value``
    will always be used instead of the value of the environment variable.
    :issue:`2746` :pr:`2788`
-   Add ``Choice.get_invalid_choice_message`` method for customizing the
    invalid choice message. :issue:`2621` :pr:`2622`
-   If help is shown because ``no_args_is_help`` is enabled (defaults to ``True``
    for groups, ``False`` for commands), the exit code is 2 instead of 0.
    :issue:`1489` :pr:`1489`
-   Contexts created during shell completion are closed properly, fixing
    a ``ResourceWarning`` when using ``click.File``. :issue:`2644` :pr:`2800`
    :pr:`2767`
-   ``click.edit(filename)`` now supports passing an iterable of filenames in
    case the editor supports editing multiple files at once. Its return type
    is now also typed: ``AnyStr`` if ``text`` is passed, otherwise ``None``.
    :issue:`2067` :pr:`2068`
-   Specialized typing of ``progressbar(length=...)`` as ``ProgressBar[int]``.
    :pr:`2630`
-   Improve ``echo_via_pager`` behaviour in face of errors.
    :issue:`2674`

    -   Terminate the pager in case a generator passed to ``echo_via_pager``
        raises an exception.
    -   Ensure to always close the pipe to the pager process and wait for it
        to terminate.
    -   ``echo_via_pager`` will not ignore ``KeyboardInterrupt`` anymore. This
        allows the user to search for future output of the generator when
        using less and then aborting the program using ctrl-c.

-   ``deprecated: bool | str`` can now be used on options and arguments. This
    previously was only available for ``Command``. The message can now also be
    customised by using a ``str`` instead of a ``bool``. :issue:`2263` :pr:`2271`

    -   ``Command.deprecated`` formatting in ``--help`` changed from
        ``(Deprecated) help`` to ``help (DEPRECATED)``.
    -   Parameters cannot be required nor prompted or an error is raised.
    -   A warning will be printed when something deprecated is used.

-   Add a ``catch_exceptions`` parameter to ``CliRunner``. If
    ``catch_exceptions`` is not passed to ``CliRunner.invoke``, the value
    from ``CliRunner`` is used. :issue:`2817` :pr:`2818`
-   ``Option.flag_value`` will no longer have a default value set based on
    ``Option.default`` if ``Option.is_flag`` is ``False``. This results in
    ``Option.default`` not needing to implement `__bool__`. :pr:`2829`
-   Incorrect ``click.edit`` typing has been corrected. :pr:`2804`
-   ``Choice`` is now generic and supports any iterable value.
    This allows you to use enums and other non-``str`` values. :pr:`2796`
    :issue:`605`
-   Fix setup of help option's defaults when using a custom class on its
    decorator. Removes ``HelpOption``. :issue:`2832` :pr:`2840`

Version 8.1.8
-------------

