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
## $Id: crypto.py,v 1.8 2007/08/14 07:47:12 haavardj Exp $
##                
######################################################################


"""Cryptographic stuff."""

from Crypto.Hash import SHA
from Crypto.PublicKey import RSA
from Crypto.Util.randpool import RandomPool
from Crypto.Util.number import long_to_bytes, bytes_to_long
import random
from zope.interface import Interface
import M2Crypto, glob

# Encrypts this with public key to make a host id.
IDMAGIC = "idmagic" 

RSASIZE = 1024


def sHashDict(d):
    """Compute a deterministic secure hash from a dictionary.
    Because dictinaries elements are unordered, a deterministic hash cannot be computed directly.
    This function will produce a hash of a dictionary by sorting the keys. 

    @param d: Dictionary to be hashed.
    @type d: dict
    @return: Hash value
    @rtype: str
    @raise e: TypeError if d is not a dictionary.
    """

    if not isinstance(d, dict):
        raise TypeError
    h = SHA.new()
    ks = d.keys()
    ks.sort()
    for k in ks:
        h.update("%s=%s," %(str(k), str(d[k])))
    return h.digest()

def identitySize():
    """Returns the size (in bytes) of identity numbers."""    
    return SHA.digest_size

def keyToIdentity(key):
    """Maps a Crypto.RSA key onto a member identity number."""    
    return SHA.new(key.encrypt(IDMAGIC, None)[0]).digest()

__randomGen = RandomPool().get_bytes

def generateKey(size=RSASIZE):
    """Returns a new RSA key."""
    return RSA.generate(size, __randomGen)


def identityFromCertificate(cert):
    return cert.get_ext("subjectKeyIdentifier").get_value()

class ImmutableMixin:
    """Mixin for immutable classes."""
    def __setattr_im__(self, k, v):
        raise RuntimeError("immutable error")

    def makeImmutable(self):
        self.__setattr__ = self.__setattr_im__
  
import os

M2Crypto


class PKIStore:    
    
    def __init__(self, path, nodsa=False):        
        self.path = path
        self.certPath = os.path.join(path, "certs")
        self.keyPath = os.path.join(path, "private")
        self.notesPath = os.path.join(path, "notes")
        self.accusationsPath = os.path.join(path, "accusations")
        self.ensurePaths()
        
    def ensurePaths(self):
        for path in [self.path, self.certPath, self.keyPath, self.notesPath, self.accusationsPath]: 
            if not os.path.exists(path):
                os.mkdir(path)
            elif not os.path.isdir(path):
                raise RuntimeError, "Path exist " + path                
            elif not os.access(path, os.R_OK | os.W_OK):
                print "%s access error.", path
                raise RuntimeError, "Path access error " + path                

    def newCA(self):
        self.clear()
        p = os.path.join(self.path, "serial")
        file(p, "w").write("00")
        p = os.path.join(self.path, "index.txt")
        file(p, "w")
        
        
        

    def loadCACertificate(self):
        path = os.path.join(self.path, "cacert.pem")
        
        return M2Crypto.X509.load_cert(path)

    def hasCAKey(self):
        path = os.path.join(self.keyPath, "cakey.pem")
        return os.path.exists(path)
    
    def loadCAKey(self):
        path = os.path.join(self.keyPath, "cakey.pem")
        return M2Crypto.EVP.load_key(path)

    def loadMemberCertificates(self):
        files = glob.glob(os.path.join(self.certPath, "*"))
        return map(lambda x: M2Crypto.X509.load_cert(x), files)

    def loadNotes(self):
        files = glob.glob(os.path.join(self.notesPath, "*"))
        return map(lambda x: pickle.load(file(x)), files)
    
    def loadAccusations(self):
        files = glob.glob(os.path.join(self.accusationsPath, "*"))
        return map(lambda x: pickle.load(file(x)), files)

    def saveMemberCertificate(self, cert):
        isinstance(cert, M2Crypto.X509.X509)
        path = os.path.join(self.certPath, cert.get_fingerprint())
        cert.save_pem(path)

    def saveNote(self, note):
        isinstance(note, fireflies.state.Note)
        path = os.path.join(self.notesPath, note.get_fingerprint())
        pickle.dump(note, file(path, "w"))

    def saveAccusation(self, accusation):
        isinstance(accusation, fireflies.state.Accusation)
        path = os.path.join(self.notesPath, note.get_fingerprint())
        pickle.dump(accusation, file(path, "w"))

    def hasPrivateKey(self):
        path = os.path.join(self.keyPath, "key.pem")
        if not os.path.exists(path): return False

    def hasPrivateCertificate(self):
        path = os.path.join(self.keyPath, "cert.pem")
        if not os.path.exists(path): return False        
        
    def savePrivateKey(self, key):
        isinstance(key, M2Crypto.EVP.PKey)
        path = os.path.join(self.keyPath, "key.pem")
        key.save_key(path)
    
    def loadPrivateKey(self): 
        path = os.path.join(self.keyPath, "key.pem")
        return M2Crypto.EVP.load_key(path)
    
    def savePrivateCertificate(self, cert):
        isinstance(cert, M2Crypto.X509.X509)
        path = os.path.join(self.path, "cert.pem")
        cert.save_pem(path)
    
    def loadPrivateCertificate(self): 
        path = os.path.join(self.path, "cert.pem")
        return M2Crypto.X509.load_cert(path)
    
    def savePrivateNote(self, note):
        path = os.path.join(self.path, "note")
        pickle.dump(note, file(path, "w"))
    
    def loadPrivateNote(self): 
        path = os.path.join(self.path, "note")
        return pickle.load(file(path))
                
    def clearAccusations(self):
        for f in glob.glob(os.path.join(self.accusationsPath, "*")):
            os.remove(f)

    def clearNotes(self):
        for f in glob.glob(os.path.join(self.notesPath, "*")):
            os.remove(f)

    def clearCertificates(self):
        for f in glob.glob(os.path.join(self.certPath, "*.pem")):
            os.remove(f)

    def saveGroup(self, group):
        isinstance(group, fireflies.group.Group)
        self.clear()
        for member in group.getView().getAllMembers():
            isinstance(member, fireflies.state.Member)
            self.saveMemberCertificate(member.getCertificate())
            self.saveNote(member.getNote())
            for acc in member.getAccusations():
                self.saveAccusation(acc)
        me = group.getMe()
        self.savePrivateNote(me.getNote())

    def clear(self):
        self.clearAccusations()
        self.clearNotes()
        self.clearCertificates()
  
  

class Signable:
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
    
    def sign(self, pKey):
        isinstance(pKey, M2Crypto.EVP.PKey)        
        pKey.sign_init()
        pKey.update(self.uidstr())
        self.signature = pKey.sign_final()
        #pKey.reset_context()

    def verify(self, pKey):
        isinstance(pKey, M2Crypto.EVP.PKey)        
        pKey.verify_init()
        pKey.verify_update(self.uidstr())
        result = pKey.verify_final(self.signature)
        #pKey.reset_context()
        return result

    def get_fingerprint(self):
        dig = M2Crypto.EVP.MessageDigest("sha1")
        dig.update(self.uidstr())
        return dig.final()


class SignableString(Signable):
    """A signable string."""
    
    signature = ""
    
    def __init__(self, string):
        self.string = string
        
    def uidstr(self):
        return self.string
