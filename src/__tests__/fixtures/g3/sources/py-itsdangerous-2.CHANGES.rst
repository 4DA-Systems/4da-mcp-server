Version 2.0.0
-------------

Released 2021-05-11

-   Drop support for Python 2 and 3.5.
-   JWS support (``JSONWebSignatureSerializer``,
    ``TimedJSONWebSignatureSerializer``) is deprecated. Use a dedicated
    JWS/JWT library such as authlib instead. :issue:`129`
-   Importing ``itsdangerous.json`` is deprecated. Import Python's
    ``json`` module instead. :pr:`152`
-   Simplejson is no longer used if it is installed. To use a different
    library, pass it as ``Serializer(serializer=...)``. :issue:`146`
-   ``datetime`` values are timezone-aware with ``timezone.utc``. Code
    using ``TimestampSigner.unsign(return_timestamp=True)`` or
    ``BadTimeSignature.date_signed`` may need to change. :issue:`150`
-   If a signature has an age less than 0, it will raise
    ``SignatureExpired`` rather than appearing valid. This can happen if
    the timestamp offset is changed. :issue:`126`
-   ``BadTimeSignature.date_signed`` is always a ``datetime`` object
    rather than an ``int`` in some cases. :issue:`124`
-   Added support for key rotation. A list of keys can be passed as
    ``secret_key``, oldest to newest. The newest key is used for
    signing, all keys are tried for unsigning. :pr:`141`
-   Removed the default SHA-512 fallback signer from
    ``default_fallback_signers``. :issue:`155`
-   Add type information for static typing tools. :pr:`186`


Version 1.1.0
-------------

