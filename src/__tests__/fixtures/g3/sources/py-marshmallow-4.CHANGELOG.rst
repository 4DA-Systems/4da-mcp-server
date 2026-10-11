---------

4.0.0 (2025-04-16)
******************

See :ref:`upgrading_4_0` for a guide on updating your code.

Features:

- Typing: Add types to all `Field <marshmallow.fields.Field>` constructor kwargs (:issue:`2285`).
  Thanks :user:`navignaw` for the suggestion.
- `DateTime <marshmallow.fields.DateTime>`, `Date <marshmallow.fields.Date>`, `Time <marshmallow.fields.Time>`,
  `TimeDelta <marshmallow.fields.TimeDelta>`, and `Enum <marshmallow.fields.Enum>`
  accept their internal value types as valid input (:issue:`1415`).
  Thanks :user:`bitdancer` for the suggestion.
- `@validates <marshmallow.validates>` accepts multiple field names (:issue:`1960`).
  *Backwards-incompatible*: Decorated methods now receive ``data_key`` as a keyword argument.
  Thanks :user:`dpriskorn` for the suggestion and :user:`dharani7998` for the PR.

Other changes:

- Typing: `Field <marshmallow.fields.Field>` is now a generic type with a type argument for the internal value type.
- `marshmallow.fields.UUID` no longer subclasses `marshmallow.fields.String`.
- *Backwards-incompatible*: Use `datetime.date.fromisoformat`, `datetime.time.fromisoformat`, and `datetime.datetime.fromisoformat` from the standard library to deserialize dates, times and datetimes (:pr:`2078`).
- `marshmallow.Schema.load` no longer silently fails to call schema validators when a generator is passed (:issue:`1898`). 
  The typing of `data` is also updated to be more accurate.
  Thanks :user:`ziplokk1` for reporting.

As a consequence of this change:
  - Time with time offsets are now supported.
  - YYYY-MM-DD is now accepted as a datetime and deserialized as naive 00:00 AM.
  - `from_iso_date`, `from_iso_time` and `from_iso_datetime` are removed from `marshmallow.utils`.

- Remove `isoformat`, `to_iso_time` and `to_iso_datetime` from `marshmallow.utils` (:pr:`2766`).
- Remove `from_rfc`, and `rfcformat` from `marshmallow.utils` (:pr:`2767`).
- Remove `is_keyed_tuple` from `marshmallow.utils` (:pr:`2768`).
- Remove `get_fixed_timezone` from `marshmallow.utils` (:pr:`2773`).

- *Backwards-incompatible*: `marshmallow.fields.Boolean` no longer serializes non-boolean values (:pr:`2725`).
- *Backwards-incompatible*: Rename ``schema`` parameter to ``parent`` in `marshmallow.fields.Field._bind_to_schema` (:issue:`1360`).
- *Backwards-incompatible*: Rename ``pass_many`` parameter to ``pass_collection`` in pre/post processing methods (:issue:`1369`).
- *Backwards-incompatible*: `marshmallow.fields.TimeDelta` no longer truncates float values when
  deserializing (:pr:`2654`). This allows microseconds to be preserved, e.g.

.. code-block:: python

    from marshmallow import fields

    field = fields.TimeDelta()

    # Before
    field.deserialize(12.9)
    datetime.timedelta(seconds=12)
    # datetime.timedelta(seconds=12)

    # After
    field.deserialize(12.9)
    # datetime.timedelta(seconds=12, microseconds=900000)

- Improve performance and minimize float precision loss of `marshmallow.fields.TimeDelta` serialization (:pr:`2654`).
- *Backwards-incompatible*: Remove ``serialization_type`` parameter from
  `marshmallow.fields.TimeDelta` (:pr:`2654`).

Thanks :user:`ddelange` for the PR.

- *Backwards-incompatible*: Remove `Schema <marshmallow.schema.Schema>`'s ``context`` attribute (deprecated since 3.24.0). Passing a context
  should be done using `contextvars.ContextVar` (:issue:`1826`).
  marshmallow 4 provides an experimental `Context <marshmallow.experimental.context.Context>`
  manager class that can be used to both set and retrieve context.

.. code-block:: python

    import typing

    from marshmallow import Schema, fields
    from marshmallow.experimental.context import Context


    class UserContext(typing.TypedDict):
        suffix: str


    class UserSchema(Schema):
        name_suffixed = fields.Function(
            lambda obj: obj["name"] + Context[UserContext].get()["suffix"]
        )


    with Context[UserContext]({"suffix": "bar"}):
        UserSchema().dump({"name": "foo"})
        # {'name_suffixed': 'foobar'}

- Methods decorated with `marshmallow.pre_load`, `marshmallow.post_load`, `marshmallow.validates_schema`,
  receive ``unknown`` as a keyword argument (:pr:`1632`).
  Thanks :user:`jforand` for the PR.
- *Backwards-incompatible*: Arguments to `decorators <marshmallow.decorators>` are keyword-only arguments.
- *Backwards-incompatible*: Rename ``json_data`` parameter of `marshmallow.Schema.loads` to ``s``
  for compatibility with most render module implementations (`json`, ``simplejson``, etc.) (:pr:`2764`).
  Also make it a positional-only argument.
- Incorrectly declaring a field using a field class rather than instance
  errors at class declaration time (previously happended when the schema was instantiated) (:pr:`2772`).
- Passing invalid values for ``unknown`` will cause an error in type checkers (:pr:`2771`).

Deprecations/Removals:

- *Backwards-incompatible*: Remove implicit field creation, i.e. using the ``fields`` or ``additional`` class Meta options with undeclared fields (:issue:`1356`).
- The `ordered` class Meta option is removed  (:issue:`2146`). Field order is already preserved by default.
  Set `Schema.dict_class` to `OrderedDict` to maintain the previous behavior.
- The `marshmallow.base` module is removed (:pr:`2722`).

Previously-deprecated APIs have been removed, including:

- The ``ordered`` `class Meta <marshmallow.Schema.Meta>` option is removed  (:issue:`2146`) (deprecated in 3.26.0).
- *Backwards-incompatible*: `marshmallow.fields.Number` is no longer usable as a field in a schema (deprecated in 3.24.0).
  Use `marshmallow.fields.Integer`, `marshmallow.fields.Float`, or `marshmallow.fields.Decimal` instead.
- *Backwards-incompatible*: `marshmallow.fields.Mapping` is no longer usable as a field in a schema (deprecated in 3.24.0).
- *Backwards-incompatible*: Custom validators must raise a `ValidationError <marshmallow.exceptions.ValidationError>` for invalid values (deprecated in 3.24.0).
  Returning `False` is no longer supported (:issue:`1775`).
  Use `marshmallow.fields.Dict` instead.
- Remove ``__version__``, ``__parsed_version__``, and ``__version_info__`` attributes (deprecated in 3.21.0).
- `default` and `missing` parameters, which were replaced by `dump_default` and `load_default` in 3.13.0 (:pr:`1742`, :pr:`2700`).
- Passing field metadata via keyword arguments (deprecated in 3.10.0). Use the explicit ``metadata=...``
  argument instead (:issue:`1350`).
- `marshmallow.utils.pprint` (deprecated in 3.7.0). Use `pprint.pprint` instead.
- Passing `"self"` to `fields.Nested` (deprecated in 3.3.0). Use a callable instead.
- ``Field.fail``, which was replaced by ``Field.make_error`` in 3.0.0.
- `json_module` class Meta option (deprecated in 3.0.0b3). Use `render_module` instead.

3.26.1 (2025-02-03)
*******************

