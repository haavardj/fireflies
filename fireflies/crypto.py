# -*- coding: iso-8859-1 -*-
######################################################################
## Filename:      crypto.py
## Description:   Fireflies crypto functions.
## Author:        Håvard Dagenborg Johansen <haavardj@cs.uit.no>
## Modified at:   Mon Jan 23 20:29:49 2006
## Modified by:   Håvard Dagenborg Johansen <haavardj@cs.uit.no>
## Licence:       GPL (see the LICENSE file).
##  
##         Copyright© 2006, University of Tromsø (Norway)
##                
## $Id: crypto.py,v 1.3 2007/06/21 06:35:14 haavardj Exp $
##                
######################################################################


"""Cryptographic stuff.

Each member that participates in the group is represented by a
PublicCertificate.

Use the generateKey function to create a CA key. This key can then be
used in the createCertificate function to make the member's
PublicCertificates.

"""

from Crypto.Hash import SHA
from Crypto.PublicKey import RSA
from Crypto.Util.randpool import RandomPool
from Crypto.Util.number import long_to_bytes, bytes_to_long
import random


# Encrypts this with public key to make a host id.
IDMAGIC = "idmagic" 

RSASIZE = 1024

def sHashDict(d):
    """Make a hash of the dictionary d. Returns the digest."""

    if not isinstance(d, dict):
        raise TypeError
    h = SHA.new()
    ks = d.keys()
    ks.sort()
    for k in ks:
        h.update("%s=%s," %(str(k), str(d[k])))
    return h.digest()

def serialSize():
    """Returns the size (in bytes) of serial numbers."""    
    return SHA.digest_size

def keyToSerial(key):
    """Maps a Crypto.RSA key onto a member serial number."""    
    return SHA.new(key.encrypt(IDMAGIC, None)[0]).digest()

__randomGen = RandomPool().get_bytes

def generateKey(size=RSASIZE):
    """Returns a new RSA key."""
    return RSA.generate(size, __randomGen)


class ImmutableMixin:
    """Mixin for immutable classes."""
    def __setattr_im__(self, k, v):
        raise RuntimeError("immutable error")

    def makeImmutable(self):
        self.__setattr__ = self.__setattr_im__
  
        
class RSASignable:
    """Mixin for classes that are signable. Use in compination with
    RSAVerifyingKey and RSASigningKey.

    Subclasses needs to implement the uidstr method.
    
    Warning: The computed hash will be cached. If the object changes and the
    hash must reflect these changes, the shashClear method will force the hash
    to be recomputed."""

    signature = ""

    def uidstr(self):
        """Return a unique string identifier for this object.

        The returned string is needed when signing the object. This
        method needs to be implemented in subclasses."""
        
        raise NotImplementedError
    
    def shash(self):
        """Return a secure hash of this object."""

        # Since computing hashes are expensive, we only do it once.
        try:
            return self.__shash
        except AttributeError:
            self.__shash = SHA.new(self.uidstr()).digest()
        return self.__shash

    def shashClear(self):
        """Recompute the hash on the next call to shash.""" 
        del self.__shash


class RSAVerifyingKey:
    
    key = None

    def verify(self, object):
        """Returns True if the object has been correctly signed."""
        
        return self.key.verify(object.shash(), (object.signature,))

class RSASigningKey:
    """Mixin for classes that can sign and verify.

    Subclasses ned to provide a key attribute. The signature will be
    stored in the signature attribute.
    """
    
    key = None

    def sign(self, object):
        """Sign the object."""
        object.signature = self.key.sign(object.shash(), None)[0]
    
    def canSign(self):
        """Return True if the class can sign objects."""
        return self.key.cansign()

    hasPrivate = canSign
                

class MemberCertificate(object, ImmutableMixin, RSASignable, RSAVerifyingKey):
    """A Fireflies member's certificate."""
    
    def __init__(self, key, address, signature=0):
        self.key = key
        self.address = address
        self.signature = signature
        self.serial = keyToSerial(self.key)

    def __str__(self):
        return "MemberCertificate:%s" % (self.address)
        
    def __cmp__(self, other):
        try:
            return cmp(self.shash(), other.shash())
        except AttributeError:
            return -1

    def uidstr(self):
        return "MemberCertificate:%s-%s" % (self.address,
                                            self.serial)
    
    def __getstate__(self):
        return {"key": self.key,
                "address": self.address,
                "signature": self.signature
                }
    
    def __setstate__(self, data):
        for k,v in data.items():
            setattr(self, k, v)
        self.serial = keyToSerial(self.key)


class CACertificate(object, RSASignable, RSAVerifyingKey):
    """A Fireflies CA certificate."""
    
    def __init__(self, key, name, config, signature=0):
        self.name, self.key, self.config, self.signature = name, key, config, signature
        self.serial = keyToSerial(self.key)

    def uidstr(self):        
        return "CACertificate-%s-%s%s" %(str(self.serial),
                                         str(self.name),
                                         str(sHashDict(self.config)))
                                         
    def __cmp__(self, other):
        try:
            return cmp(self.serial, other.serial)
        except AttributeError:
            return -1

    def __str__(self):
        return "CACertificate:%s" % (self.name)


class MemberKey(object, RSASigningKey, RSAVerifyingKey):
    """The private key of a Fireflies members."""

    def __init__(self, address, size=1024):
        self.address = address
        self.key = generateKey(size)
        self.serial = keyToSerial(self.key)

    def __str__(self):
        return "MemberKey:%s@%s" % (self.address, self.serial)
        
    def __cmp__(self, other):
        try:
            return cmp(self.serial, other.serial)
        except AttributeError:
            return -1

    def getCertificate(self):
        c = MemberCertificate(self.key.publickey(), self.address)
        return c


class CAKey(object, RSASigningKey, RSAVerifyingKey):
    """Private key of a CA."""
    
    def __init__(self, name, config, size=1024):
        self.name, self.config = name, config
        self.key = generateKey(size)
        self.serial = keyToSerial(self.key)

    def __str__(self):
        return "CAKey:%s@%s" % (self.name, self.serial)
        
    def __cmp__(self, other):
        try:
            return cmp(self.serial, other.serial)
        except AttributeError:
            return -1

    def getCertificate(self):
        c = CACertificate(self.key.publickey(), self.name, self.config)
        self.sign(c)
        return c


class SignableString(RSASignable):
    """A signable string."""

    
    def __init__(self, string):
        self.string = string
        
    def uidstr(self):
        return self.string

