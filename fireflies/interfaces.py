from zope.interface import Interface


class IIdentifiableObject(Interface):
    """Interface for object that have identities."""
    
    def identity(self):
        """Unique object itentity."""
