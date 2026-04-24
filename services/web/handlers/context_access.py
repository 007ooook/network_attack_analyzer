"""Mixin: `ctx` property for API handlers."""


class ContextAccessMixin:
    """Host class must define class attr `application_context`."""

    @property
    def ctx(self):
        ac = getattr(type(self), "application_context", None)
        if ac is None:
            raise RuntimeError("application_context is not set on the request handler class")
        return ac
