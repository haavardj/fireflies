from zope.interface import Interface  # pyright: ignore[reportMissingTypeStubs]


class IIdentifiableObject(Interface):  # pyright: ignore[reportGeneralTypeIssues, reportUntypedBaseClass]  # zope interfaces are not classes to pyright
    """Interface for object that have identities."""
    
    def identity(self) -> str:
        """Unique object itentity."""
        ...
