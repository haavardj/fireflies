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
## $Id: util.py,v 1.7 2014/06/16 07:49:47 haavardj Exp $
##                
######################################################################

"""Utility functions and classes."""


###################################
## statistical distributions
## 10/2004 Wolfgang.Urban@schule.at
###################################
import math
import twisted.internet

# #######################
# binomial distribution #
# ##################### #

# straightforward calculation
#
def binomial_1(k,n,p):
    ## special cases
    if p==0.0:
        if k==0: return 1.0
        else: return 0.0
    if p==1.0:
        if k==n: return 1.0
        else: return 0.0
        
    if k<=n/2: k1=k                                 
    else: k1=n-k                                    # fewer calculations
    ## binomial coefficient
    fact = 1.0                                  
    for i in range(0,k1): fact = fact*(n-i)/(k1-i)
    ## probability
    return fact*p**k*(1.0-p)**(n-k)                 # binomial probability


# using recursion b(k,n,p)=b(k-1,n,p)*(n-k+1)/i*p/q
# special cases omitted
#
def binomial_2(k,n,p):
    prob = (1.0-p)**n

    for i in range(1,k+1):
        prob = prob*(n-i+1)/i*p/(1.0-p)

    return prob


# to avoid overflow with large n or underflow with small p
# e.g. 0.5**1075 = 0 (large n gives result 0), we use logarithms
#
def binomial_1a(k,n,p):
    ## special cases
    if p==0.0:
        if k==0: return 1.0
        else: return 0.0
    if p==1.0:
        if k==n: return 1.0
        else: return 0.0

    if k<=n/2: k1=k
    else: k1=n-k

    fact = 0.0
    for i in range(0,k1): fact += math.log(float(n-i)/(k1-i))

    result_log = fact+k*math.log(p)+(n-k)*math.log(1.0-p)
    return math.exp(result_log)


# we can do the same with version 2
# p must not be 0 or 1
#
def binomial_2a(k,n,p):
    q = 1.0-p
    m = float(n+1)
    r = math.log(p/q)
    prob = n*math.log(q)
    for i in range(1,k+1):
        prob = prob + r + math.log(m/i-1.0)
    return math.exp(prob)

# we prefer version 1a to calculate binomial probabilities.
#
binomialp = binomial_1a

# cumulative probability
# version 2a is easily adapted
#
def binomialc(k,n,p):
    ## special cases
    if p==0.0:
        return 1.0
    if p==1.0:
        if k==n: return 1.0
        else: return 0.0

    q = 1.0-p
    m = float(n+1)
    r = math.log(p/q)
    prob = n*math.log(q)
    cum = math.exp(prob)
    for i in range(1,k+1):
        prob += r + math.log(m/i-1.0)
        cum += math.exp(prob)
    return cum


# ####################################################
# probabilities
# a single event X has probability p
# calculate prob. of k occurrences X within n events
#

def binomialP(k,n,p):
    return binomialp(k,n,p)



########################################################
# return probabilities k=0..n,n,p  as list
#

def binomial_list(n,p):
    prob = float(1-p)**n
    cum = [prob]

    for i in range(1,n+1):
        prob = prob*(n-i+1)/i*p/(1.0-p)
        cum.append(prob)
    return cum


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
        

try:
    from scipy.stats import binom as _binom
    def binomCDF(k, n, p):
        return _binom(n, p).cdf(k)
except ImportError as why:
    print("Cannot find scipy. Using alternative binom calculation.")
    def binomCDF(k,n,p):
        return binomialc(k,n,p)

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
    
    