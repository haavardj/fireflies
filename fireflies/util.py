######################################################################
## Filename:      crypto.py
## Description:   Utility functions and classes.
## Author:        Håvard Dagenborg Johansen <haavardj@cs.uit.no>
## Modified at:   Mon Jan 23 20:29:49 2006
## Modified by:   Håvard Dagenborg Johansen <haavardj@cs.uit.no>
## Licence:       GPL (see the LICENSE file).
##  
##         Copyright© 2006, Håvard Johansen (Norway)
##                
## $Id: util.py,v 1.1 2007/07/17 13:42:53 haavardj Exp $
##                
######################################################################

"""Utility functions and classes."""

class TimestampMixin:
    """Provides time-stamping functionality to an object."""
    
    def getTimestamp(self):
        """Returns the time-stamp, or 0 if no time-stamp is set."""
        try:
            return self._timestamp
        except AttributeError:
            pass
        return 0

    def setTimestamp(self):
        """Set time-stamp according to the time returned by
        fireflies.time.time."""
        self._timestamp = fireflies.time.time()

