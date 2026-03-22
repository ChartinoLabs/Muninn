"""Documentation metadata for :func:`typing.Annotated` parser types.

Schema generators and IDEs can inspect these markers without treating every
dynamic key or string field as an undifferentiated ``str``.
"""


class SchemaDoc:
    """Human-readable documentation attached via :class:`typing.Annotated`.

    This class is only metadata for static and dynamic tooling; it is not
    consulted by parser implementations at runtime.
    """

    __slots__ = ("text",)

    def __init__(self, text: str) -> None:
        """Initialize with documentation text for schema tooling."""
        self.text: str = text

    def __repr__(self) -> str:
        """Return a debug representation."""
        return f"{type(self).__name__}({self.text!r})"
