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
## $Id: util.py,v 1.5 2011/03/18 11:17:05 haavardj Exp $
##                
######################################################################

"""Utility functions and classes."""





###################################
## statistical distributions
## 10/2004 Wolfgang.Urban@schule.at
###################################
import math, struct
from twisted.internet import reactor

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
    """long_to_bytes(n:long, blocksize:int) : string
    Convert a long integer to a byte string.

    If optional blocksize is given and greater than zero, pad the front of the
    byte string with binary zeros so that the length is a multiple of
    blocksize.
    """
    # after much testing, this algorithm was deemed to be the fastest
    s = ''
    n = long(n)
    pack = struct.pack
    while n > 0:
        s = pack('>I', n & 0xffffffffL) + s
        n = n >> 32
    # strip off leading zeros
    for i in range(len(s)):
        if s[i] != '\000':
            break
    else:
        # only happens when n == 0
        s = '\000'
        i = 0
    s = s[i:]
    # add back some pad bytes.  this could be done more efficiently w.r.t. the
    # de-padding being done above, but sigh...
    if blocksize > 0 and len(s) % blocksize:
        s = (blocksize - len(s) % blocksize) * '\000' + s
    return s

def bytes_to_long(s):
    """bytes_to_long(string) : long
    Convert a byte string to a long integer.

    This is (essentially) the inverse of long_to_bytes().
    """
    acc = 0L
    unpack = struct.unpack
    length = len(s)
    if length % 4:
        extra = (4 - length % 4)
        s = '\000' * extra + s
        length = length + extra
    for i in range(0, length, 4):
        acc = (acc << 32) + unpack('>I', s[i:i+4])[0]
    return acc



class TimeoutMixin:
    
    timeout = 30
    timer = None
    
    def startTimer(self):        
        if self.timer: raise ValueError("Timer already started")

        def _d():
            self.timer = None
            self.timedOut()
        
        self.timer = reactor.callLater(self.timeout, _d)

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
        self._observers.append[o] = (args, kwargs)

    def deregisterObserver(self, o):
        del self._observers[o]
        
    def notify(self, *args, **kwargs):
        for o, oArgs, oKwargs, in self._observers.items():
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
        self._timestamp = fireflies.time.time()




try:
    from scipy.stats import binom as _binom
    def binomCDF(k, n, p):
        return _binom(n, p).cdf(k)
except ImportError, why:
    print "Cannot find scipy. Using alternative binom calculation."
    def binomCDF(k,n,p):
        return binomialc(k,n,p)

def minMajority(pByz, size, e=1.0):
    """Compute the minimum t such that the probability of more than t out of
    2t+1 monitors are correct with probability e/size given the uniform
    probability pByz that a monitor is Byzantine.
    
    @return: t
    @raise e: ValueError if t cannot be computed with the given parameters.
    """
    
    pTarget = float(e) / float(size)
    for t in range(1, 10000):
        pf = 1.0 - binomCDF(t, 2*t+1,pByz)
        if pTarget >= pf: return t

    raise ValueError, "Cannot compute number if rings from pByz=%f" % pByz