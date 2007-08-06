######################################################################
## Filename:      crypto.py
## Description:   Utility functions and classes.
## Author:        Haavard Dagenborg Johansen <haavardj@cs.uit.no>
## Modified at:   Mon Jan 23 20:29:49 2006
## Modified by:   Haavard Dagenborg Johansen <haavardj@cs.uit.no>
## Licence:       GPL (see the LICENSE file).
##  
##         Copyright 2006, Haavard Johansen (Norway)
##                
## $Id: util.py,v 1.2 2007/08/06 12:43:47 haavardj Exp $
##                
######################################################################

"""Utility functions and classes."""

from scipy.stats import binom

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


def minMajority(pByz, size, e=1.0):
    """Compute the minimum t such that the probability of more than t out of
    2t+1 monitors are correct with probability e/size given the uniform
    probability pByz that a monitor is Byzantine.
    
    @return: t
    @raise e: ValueError if t cannot be computed with the given parameters.
    """
    
    pTarget = float(e) / float(size)
    for t in range(1, 10000):
        pf = 1.0 - binom(2*t+1,pByz).cdf(t)
        if pTarget >= pf: return t

    raise ValueError, "Cannot compute number if rings from pByz=%f" % pByz