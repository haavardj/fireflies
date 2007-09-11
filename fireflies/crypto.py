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
## $Id: crypto.py,v 1.13 2007/09/11 14:11:06 haavardj Exp $
##                
######################################################################

"""Cryptographic stuff."""

import fireflies
import glob, pickle, os, random, M2Crypto, struct
from os.path import join
from zope.interface import Interface


DIGESTALG="sha1"
DIGESTSIZE=160


def fingerprint(data, outputbinary=False):
    h = M2Crypto.EVP.MessageDigest(DIGESTALG)
    h.update(data)
    digest = h.final()
    if not outputbinary: 
        digest = hex(M2Crypto.util.octx_to_num(digest))[2:-1]
    return digest



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

def generatePrivateKey(size=1024):
    rsa = M2Crypto.RSA.gen_key(size, M2Crypto.m2.RSA_F4)
    pkey = M2Crypto.EVP.PKey()
    pkey.assign_rsa(rsa)
    return pkey
    
def makeRequest(address, pkey, nickname=None):
    """Create X509 certificate request.
    
    @param address: IP:port tuble containing the contact address.
    @type address: str
    @param pkey: Private key of requester.
    @type pkey: L{M2Crypto.EVP.PKey}
    @param nicname: Alternative member name.
    @type nicname: str
    @return: Certificate request.
    @rtype: L{M2Crypto.X590.X590Request}
    """
    if nickname==None: nickname=address
    req = M2Crypto.X509.Request()
    req.set_pubkey(pkey)
    subject = M2Crypto.X509.X509_Name()
    subject.commonName = nickname
    subject.localityName = address    
    req.set_subject_name(subject)
    req.sign(pkey, DIGESTALG)
    return req

def makeCert(req, caCert, caPkey, sn=0, notBefore=0, notAfter=60*60*24*30):
    """Create a X509 member certificate.
    @param req: X509 request.
    @type req: L{M2Crypto.X509.X509Request}
    @param sn: serial number.
    @param caCert: CA's certificate
    @type caCert: L{M2Crypto.X509.X509}
    @param caPkey: CA's private key.
    @type caPkey: L{M2Crypto.EVP.PKey}
    @return: Member certificate.
    @rtype: L{M2Crypto.X509.X509}
    """
    
    pkey = req.get_pubkey()
    if not req.verify(pkey):
        raise ValueError, 'Error verifying request.'
    
    sub = req.get_subject()
    cert = M2Crypto.X509.X509()
    cert.set_serial_number(sn)
    cert.set_version(2)
    cert.set_subject(sub)
    cert.set_issuer(caCert.get_subject())
    cert.set_pubkey(pkey)    
    
    M2Crypto.m2.x509_gmtime_adj(M2Crypto.m2.x509_get_not_before(cert.x509), notBefore)
    M2Crypto.m2.x509_gmtime_adj(M2Crypto.m2.x509_get_not_after(cert.x509), notAfter)

    newid = M2Crypto.Rand.rand_bytes(20)
    newid = hex(M2Crypto.util.octx_to_num(newid))[2:-1]
    extId = M2Crypto.X509.new_extension('subjectKeyIdentifier', newid ,critical=1)
    cert.add_ext(extId)
    cert.sign(caPkey, DIGESTALG)

    return cert

def newCA(name, maxGroupSize=1000, pByz=0.20, toleranceLevel=1.0, keySize=1024, notBefore=0, notAfter=60*60*24*30):
    """Create a new CA.
    @return: CA's certificate and private key.
    @rtype: (L{M2Crypto.X509.X509}, L{M2Crypto.EVP.PKey})
    """
    privKey = generatePrivateKey()
    
    issuer = M2Crypto.X509.X509_Name()
    issuer.CN = name
    issuer.O = "%d %f %f" % (maxGroupSize, pByz, toleranceLevel)
    cert = M2Crypto.X509.X509()
    cert.set_subject(issuer)
    cert.set_issuer(issuer)
    cert.set_pubkey(privKey)

    M2Crypto.m2.x509_gmtime_adj(M2Crypto.m2.x509_get_not_before(cert.x509), notBefore)
    M2Crypto.m2.x509_gmtime_adj(M2Crypto.m2.x509_get_not_after(cert.x509), notAfter)
    cert.sign(privKey, DIGESTALG)
    return cert, privKey

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
    h = M2Crypto.EVP.MessageDigest(DIGESTALG)
    
    ks = d.keys()
    ks.sort()
    for k in ks:
        h.update("%s=%s," %(str(k), str(d[k])))
    return h.final()

def identitySize():
    """Returns the size (in bytes) of identity numbers."""    
    return DIGESTSIZE/8



def identityFromCertificate(cert):
    return cert.get_ext("subjectKeyIdentifier").get_value()

class ImmutableMixin:
    """Mixin for immutable classes."""
    def __setattr_im__(self, k, v):
        raise RuntimeError("immutable error")

    def makeImmutable(self):
        self.__setattr__ = self.__setattr_im__
  



def noteFileName(note):
    return "%s-%d" % (note.identity, note.epoch)




class PKIStore:    
  
    def __init__(self, dirRoot):        
        self.dirRoot = dirRoot
        self.dirCert = join(dirRoot, "certs")
        self.dirNote = join(dirRoot, "notes")
        self.dirAccu = join(dirRoot, "accusations")
        self.dirPriv = join(dirRoot, "private")
        self.fileCAPriv = join(self.dirPriv, "cakey.pem") 
        self.fileCaCert = join(self.dirRoot, "cacert.pem")   
        self.fileSerial = join(self.dirRoot, "serial")

        self.ensurePaths()   
      
    def ensurePaths(self):
        for path in [self.dirRoot, self.dirCert, self.dirPriv, self.dirNote, self.dirAccu]: 
            if not os.path.exists(path):
                os.mkdir(path)
            elif not os.path.isdir(path):
                raise RuntimeError, "Path exist " + path                
            elif not os.access(path, os.R_OK | os.W_OK):
                print "%s access error.", path
                raise RuntimeError, "Path access error " + path                
        if not os.path.exists(self.fileSerial):
            file(self.fileSerial, "w").write("0")
        

    def newMemberCertificate(self, req, callback=M2Crypto.util.passphrase_callback):
        sn = int(file(self.fileSerial, "r").readline())
        sn += 1        
        caCert = self.loadCACertificate()
        caPKey = self.loadCAKey(callback)        
        cert = makeCert(req, caCert, caPKey, sn=sn)
        file(self.fileSerial, "w").write(str(sn))
        self.saveMemberCertificate(cert)
        return cert

    def saveCACert(self, caCert):
        isinstance(caCert, M2Crypto.X509.X509)
        caCert.save(self.fileCaCert)

    def saveCaPrivKey(self, pkey, callback=M2Crypto.util.passphrase_callback):
        isinstance(pkey, M2Crypto.EVP.PKey)
        pkey.save_key(self.fileCAPriv, callback=callback)        
        
    def nameToKeyPath(self, name):
        return join(self.dirPriv, name + ".pem")
                
    def loadCACertificate(self):
        return M2Crypto.X509.load_cert(self.fileCaCert)

    def hasCAKey(self):
        return os.path.exists(self.fileCAPriv)
    
    def loadCAKey(self, callback=M2Crypto.util.passphrase_callback):
        return M2Crypto.EVP.load_key(self.fileCAPriv, callback=callback)

    def hasMemberCertificateWithAddress(self, address):
        try:
            self.loadMemberCertificateByAddress(address)
        except KeyError:
            return False
        return True

    def hasKeyForCertificate(self, cert):
        try:
            self.loadPrivateForCert(cert)
        except KeyError:
            return False
        return True

    def loadMemberCertificates(self):
        files = glob.glob(os.path.join(self.dirCert, "*"))
        return map(lambda x: M2Crypto.X509.load_cert(x), files)

    def loadMemberCertificateByAddress(self, address):
        for f in glob.glob(os.path.join(self.dirCert, "*")):
            cert = M2Crypto.X509.load_cert(f)
            if cert.get_subject().L == address:
                return cert
        raise KeyError, "No certificate matching L=%s found" % address  

    def loadMemberCertificateByName(self, name):
        for f in glob.glob(os.path.join(self.dirCert, "*")):
            cert = M2Crypto.X509.load_cert(f)
            if cert.get_subject().CN == name:
                return cert
        raise KeyError, "No certificate matching L=%s found" % name 

    def loadNotes(self):
        files = glob.glob(os.path.join(self.dirNote, "*"))
        return map(lambda x: pickle.load(file(x)), files)
    
    def loadAccusations(self):
        files = glob.glob(os.path.join(self.dirAccu, "*"))
        return map(lambda x: pickle.load(file(x)), files)

    def saveMemberCertificate(self, cert):
        isinstance(cert, M2Crypto.X509.X509)
        path = os.path.join(self.dirCert, identityFromCertificate(cert))
        cert.save_pem(path)

    def saveNote(self, note):
        isinstance(note, fireflies.state.Note)
        path = os.path.join(self.dirNote, noteFileName(note))
        pickle.dump(note, file(path, "w"))

    def saveAccusation(self, accusation):
        isinstance(accusation, fireflies.state.Accusation)
        path = os.path.join(self.dirAccu, accusation.get_fingerprint())
        pickle.dump(accusation, file(path, "w"))

    def hasPrivateKey(self):
        path = os.path.join(self.dirPriv, "key.pem")
        if not os.path.exists(path): return False

    def hasPrivateCertificate(self):
        path = os.path.join(self.dirPriv, "cert.pem")
        if not os.path.exists(path): return False        
        

    def savePrivateKey(self, pkey, cert, callback=M2Crypto.util.passphrase_callback):
        isinstance(pkey, M2Crypto.EVP.PKey)
        fn = join(self.dirPriv, identityFromCertificate(cert))
        pkey.save_key(fn, callback=callback)
        
        
    def loadPrivateKeyForCert(self, cert, callback=M2Crypto.util.passphrase_callback):
        isinstance(cert, M2Crypto.X509.X509)
        data = "signthis."

        for f in glob.glob(os.path.join(self.dirPriv, "*")):            
            # Checks that public key in cert match a private key by 
            # signing and verifying some data. This is probably not that efficient but there seems not
            # to be any other way of doing this. 
            key = M2Crypto.EVP.load_key(f, callback)
            key.sign_init()
        
            key2 = cert.get_pubkey()
            key2.verify_init()
        
            key.sign_update(data)
            key2.verify_update(data)
            
            if key2.verify_final(key.sign_final()):
                return key

        raise KeyError, "Unable to find correct key"
       
    def loadNoteFromCert(self, cert):
        isinstance(cert, M2Crypto.X509.X509)
        for f in glob.glob(os.path.join(self.dirNote, "*")):
            note = pickle.load(file(f))
            if not isinstance(note, fireflies.state.Note): raise ValueError
            if note.identity == identityFromCertificate(cert):
                return note

        raise KeyError, "No matching note found."
                
    def clearAccusations(self):
        for f in glob.glob(os.path.join(self.dirAccu, "*")):
            os.remove(f)

    def clearNotes(self):
        for f in glob.glob(os.path.join(self.dirNote, "*")):
            os.remove(f)

    def clearCertificates(self):
        for f in glob.glob(os.path.join(self.dirCert, "*.pem")):
            os.remove(f)

    def saveGroup(self, group):
        isinstance(group, fireflies.group.Group)
        self.clear()
        for member in group.getView().getAllMembers():
            isinstance(member, fireflies.state.Member)
            self.saveMemberCertificate(member.getCertificate())
            n = member.getNote()
            if n: self.saveNote(n)
            for acc in member.getAccusations():
                self.saveAccusation(acc)

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
