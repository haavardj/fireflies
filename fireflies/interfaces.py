from zope.interface import Interface


class IIdentifiableObject(Interface):  # pyright: ignore[reportGeneralTypeIssues]  # zope interfaces are not classes to pyright
    """Interface for object that have identities."""
    
    def identity(self):
        """Unique object itentity."""
