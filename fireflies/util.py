######################################################################
## Filename:      util.py
## Description:   Utility functions and classes.
## Author:        Håvard Dagenborg <havard.dagenborg@outlook.com>
## Modified at:   Mon Jan 23 20:29:49 2006
## Modified by:   Håvard Dagenborg <havard.dagenborg@outlook.com>
## Licence:       MIT (see the LICENCE file).
##  
##         Copyright© 2006, Håvard Dagenborg
##                
## $Id: util.py,v 1.7 2014/06/16 07:49:47 haavardj Exp $
##                
######################################################################

"""Utility functions and classes."""


import math
import twisted.internet


#
# Binomial distribution. Log-space, so large n does not overflow.
#

def binomialP(k, n, p):
    """Probability of exactly k successes in n trials with success probability p."""
    if p == 0.0:
        return 1.0 if k == 0 else 0.0
    if p == 1.0:
        return 1.0 if k == n else 0.0
    logC = math.lgamma(n + 1) - math.lgamma(k + 1) - math.lgamma(n - k + 1)
    return math.exp(logC + k * math.log(p) + (n - k) * math.log1p(-p))

binomialp = binomialP


def binomialc(k, n, p):
    """Probability of at most k successes in n trials."""
    return sum(binomialP(i, n, p) for i in range(k + 1))


def binomial_list(n, p):
    """Probabilities of 0..n successes in n trials."""
    return [binomialP(k, n, p) for k in range(n + 1)]


def long_to_bytes(n, blocksize=0):
    """Convert a non-negative integer to a big-endian byte string.

    If blocksize is greater than zero, pad the front with zero bytes so
    that the length is a multiple of blocksize. Zero encodes as b'\x00'.
    """
    n = int(n)
    s = n.to_bytes(max(1, (n.bit_length() + 7) // 8), "big")
    if blocksize > 0 and len(s) % blocksize:
        s = (blocksize - len(s) % blocksize) * b"\x00" + s
    return s

def bytes_to_long(s):
    """Convert a big-endian byte string to an integer. Inverse of long_to_bytes()."""
    return int.from_bytes(s, "big")


class TimeoutMixin:
    
    timeout = 30
    timer = None
    
    def startTimer(self):        
        if self.timer: raise ValueError("Timer already started")

        def _d():
            self.timer = None
            self.timedOut()
        
        self.timer = twisted.internet.reactor.callLater(self.timeout, _d)

    def cancelTimer(self):
        self.timer.cancel()
        self.timer = None

    def hasTimer(self):
        if self.timer: assert self.timer.active()
        return bool(self.timer)
    
    def timedOut(self): pass
        
        
class ObserveableMixin:
    
    _observers = None
    
    def registerObserver(self, o, *args, **kwargs):
        if self._observers == None:
            self._observers = {}
        self._observers[o] = (args, kwargs)

    def deregisterObserver(self, o):
        del self._observers[o]
        
    def notify(self, *args, **kwargs):
        for o in list(self._observers):
            o(*args, **kwargs)
        

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
        import fireflies
        self._timestamp = fireflies.time.time()
        

binomCDF = binomialc

import math
from math import log, sqrt


def YmirCalc(pcorr, N, eps=0.5, c = 0.5):
    t1 = log(N / c)
    t2 = (2*pcorr + eps) / (2 * eps**2)   
    return t1 * t2 - 1/2

def hdjCalc1(pcorr, N, c=1.0):
    t1 = log(N / c)    
    t2 = (4*pcorr + 2) / (2*pcorr-1)**2
    return t1 * t2

def hdjCalc2(pcorr, N, c=1.0):
    t1 = log(N / c)    
    t2 = (2.0) / ((1-2*pcorr)**2)
    return t1 * t2

def proofv4(pcorr, N, c=1.0):
    t1 = log(1.0 - (c / N))
    t2 = 2.0 / log(2.0-2*pcorr) + 2*pcorr - 1
    return t1 * t2

    
def minmajority(num):
    # Should always be odd
    assert num % 2 == 1    
    return (num - 1) // 2
    
def numMembershipRings(pByz, N, epsilon=0.99, maxSize=1000):
    """Compute the minimum k=2t+1 such that the probability of more than t out of
    2t+1 monitors are correct with probability epsilon given the uniform
    probability pByz that a monitor is Byzantine.
    
    @return: k
    @raise e: ValueError if t cannot be computed with the given parameters.
    """    
    return 2*numHalfMembershipRings(pByz, N, epsilon, maxSize) + 1

def numHalfMembershipRings(pByz, N, epsilon=0.99, maxSize=1000):
    """Compute the minimum t such that the probability of more than t out of
    2t+1 monitors are correct with probability epsilon given the uniform
    probability pByz that a monitor is Byzantine.
    
    @return: t
    @raise e: ValueError if t cannot be computed with the given parameters.
    """
    
    for t in range(1, maxSize):
        if epsilon <= binomCDF(t, 2*t+1, pByz)**N: 
            return t

    raise ValueError("Cannot compute number if rings from pByz=%f" % pByz)

def numGossipRings(pByz, N, epsilon=0.99):
    
    n = (1.0 - pByz) * N
    return math.ceil( (N / (2*n)) * (log(-n / log(epsilon)) + 1))
    
    