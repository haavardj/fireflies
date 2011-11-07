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
## $Id: crypto.py,v 1.26 2011/11/07 13:27:31 haavardj Exp $
##                
######################################################################

"""Cryptographic stuff."""

import fireflies, M2Crypto, struct, hashlib

DIGESTALG="sha1"
DIGESTSIZE=160

class GroupCertificate(M2Crypto.X509.X509):
    
    def uidstr(self):
        return "GroupCertificate:%d" % (self.get_fingerprint())
    
    def maxSize(self):        
        return int(self.get_subject().organizationName.split()[0])

    def pByz(self):
        return float(self.get_subject().organizationName.split()[1])
            
    def faultToleranceLevel(self):
        return float(self.get_subject().organizationName.split()[2])

    def name(self):
        self.get_subject().commonName
        
    def nrRings(self):
        return fireflies.util.minMajority(self.pByz(), self.maxSize(), self.faultToleranceLevel()) * 2 + 1

    def identity(self):
        return self.get_fingerprint()

class MemberCertificate(M2Crypto.X509.X509):
    
    def __getstate__(self):
        return self.x509.as_der()
    
    def __setstate__(self, data):        
        bio = M2Crypto.BIO.MemoryBuffer(data) 
        self.x509 = M2Crypto.m2.d2i_x509(bio._ptr())
        assert M2Crypto.m2.x509_type_check(self.x509)
        self._pyfree = 1
        
    def uidstr(self):
        return "Certificate:%s" % self.get_fingerprint()
    
    def identity(self):
        return self.get_fingerprint()


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

def makePrivateKey(size=1024, callback=M2Crypto.RSA.keygen_callback):     
    rsa = M2Crypto.RSA.gen_key(size, M2Crypto.m2.RSA_F4, callback)
    pkey = M2Crypto.EVP.PKey()
    pkey.assign_rsa(rsa)

    return pkey

def makeCACert(pkey, groupName, maxGroupSize, pByz=0.10, faultTolerance=0.10):

    name = M2Crypto.X509.X509_Name()
    name.CN = groupName
    name.O = "%d %f %f" % (maxGroupSize, pByz, faultTolerance)
    
    cert = GroupCertificate()
 
    cert.set_serial_number(0)
    cert.set_version(0)
    cert.set_subject(name)
    cert.set_issuer(name)
    cert.set_pubkey(pkey)
    notBefore = M2Crypto.m2.x509_get_not_before(cert.x509)
    notAfter  = M2Crypto.m2.x509_get_not_after(cert.x509)
    M2Crypto.m2.x509_gmtime_adj(notBefore, 0)
    days = 30
    M2Crypto.m2.x509_gmtime_adj(notAfter, 60*60*24*days)    
    
    kid = computeSubjectKeyIdentifier(pkey)
    ext = M2Crypto.X509.new_extension('subjectKeyIdentifier', kid, 0)
    cert.add_ext(ext)       

    ext = M2Crypto.X509.new_extension('basicConstraints', 'CA:TRUE')    
    cert.add_ext(ext)      
    
    # Does not work yet due to M2Crypto issues
    #ext3 = M2Crypto.X509.new_extension('authorityKeyIdentifier', 'keyid,issuer:always', 0)
    #cert.add_ext(ext3)       

    cert.sign(pkey, 'sha1')
    assert cert.check_ca() != 0    
    return cert

def makeRequest(address, pkey, version=0, nickname=None):
    """Create X509 certificate request.
    
    @param address: IP:port tuble containing the contact address.
    @type address: str
    @param pkey: Private key of requester.
    @type pkey: L{M2Crypto.EVP.PKey}
    @param nicname: Alternative member name.
    @type nicname: str
    @return: Certificate request.
    @rtype: L{M2Crypto.X509.Request}
    """
    if nickname==None: nickname=address
    req = M2Crypto.X509.Request()
    req.set_pubkey(pkey)
    subject = M2Crypto.X509.X509_Name()
    subject.commonName = nickname
    subject.localityName = address    
    req.set_subject_name(subject)
    req.set_version(version)
    req.sign(pkey, DIGESTALG)
    assert req.verify(pkey)
    return req


def makeCert(req, caCert, caPkey, sn=0, notBefore=0, notAfter=60*60*24*30):
    """Create a X509 member certificate.
    @param req: X509 request.
    @type req: L{M2Crypto.X509.Request}
    @param sn: serial number.
    @param caCert: CA's certificate
    @type caCert: L{M2Crypto.X509.X509}
    @param caPkey: CA's private key.
    @type caPkey: L{M2Crypto.EVP.PKey}
    @return: Member certificate.
    @rtype: L{M2Crypto.X509.X509}
    """
    
    isinstance(caCert, M2Crypto.X509.X509)
    pkey = req.get_pubkey()
    if not req.verify(pkey):
        raise ValueError, 'Error verifying request.'
    
    sub = req.get_subject()
    cert = M2Crypto.X509.X509()
    cert.set_serial_number(sn)
    cert.set_version(req.get_version())
    cert.set_subject(sub)
    cert.set_issuer(caCert.get_subject())
    cert.set_pubkey(pkey)    
    
    M2Crypto.m2.x509_gmtime_adj(M2Crypto.m2.x509_get_not_before(cert.x509), notBefore)
    M2Crypto.m2.x509_gmtime_adj(M2Crypto.m2.x509_get_not_after(cert.x509), notAfter)
    
    ext = M2Crypto.X509.new_extension('subjectKeyIdentifier',  computeSubjectKeyIdentifierFromCertificate(cert), critical=0)    
    cert.add_ext(ext)
    
    # Does not work due to M2Crypto issues
    #ext = M2Crypto.X509.new_extension('authorityKeyIdentifier',  "keyid,issuer", critical=0)    
    #cert.add_ext(ext)

    cert.sign(caPkey, DIGESTALG)
    
    try:
        identityFromCertificate(cert)
    except LookupError:
        print "subjectKeyIdentifier missing", newid, ext1.get_name(), ext1.get_value()
        raise

    return cert

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

def computeSubjectKeyIdentifierFromCertificate(cert):
    if not isinstance(cert, M2Crypto.X509.X509): raise ValueError
    return computeSubjectKeyIdentifier(cert.get_pubkey())

def computeSubjectKeyIdentifier(pkey):
    if not isinstance(pkey, M2Crypto.EVP.PKey): raise ValueError
    client_serial = hashlib.new("sha1", pkey.as_der() ).hexdigest().upper()
    client_serial_hex = ''
    
    for byte in xrange(20):
        client_serial_hex += client_serial[byte*2] + client_serial[byte*2+1]
        if byte < 19:
            client_serial_hex += ':'            
    return client_serial_hex

def identityFromCertificate(cert):
    if not isinstance(cert, M2Crypto.X509.X509): raise TypeError
    try:
        ext = cert.get_ext("subjectKeyIdentifier")
    except LookupError, why:
        raise LookupError("No subjectKeyIdentifier in %s" % cert.as_text())
    
    return subjectKeyIdentifierToID(ext.get_value())

def subjectKeyIdentifierToID(s):
    return s.replace(":","")
    #return s#int(s.replace(":",""), 16)

class ImmutableMixin:
    """Mixin for immutable classes."""
    def __setattr_im__(self, k, v):
        raise RuntimeError("immutable error")

    def makeImmutable(self):
        self.__setattr__ = self.__setattr_im__
  

class Signable:
    """Mixin for classes that are signable. Use in compination with
    RSAVerifyingKey and RSASigningKey.

    Subclasses needs to implement the uidstr method.
    
    Warning: The computed hash will be cached. If the object changes and the
    hash must reflect these changes, the shashClear method will force the hash
    to be recomputed."""

    signature = ""
    _fingerprint = None

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
        if not self._fingerprint:       
            dig = M2Crypto.EVP.MessageDigest("sha1")
            dig.update(self.uidstr())
            self._fingerprint = dig.final()
        return self._fingerprint


class SignableString(Signable):
    """A signable string."""
    
    signature = ""
    
    def __init__(self, string):
        self.string = string
        
    def uidstr(self):
        return self.string
