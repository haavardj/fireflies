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
## $Id: crypto.py,v 1.10 2007/08/20 07:47:57 haavardj Exp $
##                
######################################################################


"""Cryptographic stuff."""
import fireflies
from Crypto.Hash import SHA
from Crypto.PublicKey import RSA
from Crypto.Util.randpool import RandomPool
from Crypto.Util.number import long_to_bytes, bytes_to_long
import random
from zope.interface import Interface
import M2Crypto, glob, pickle

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
from os.path import join


opensslConfig = """
HOME			= .
RANDFILE		= $ENV::HOME/.rnd
oid_section		= new_oids
[ new_oids ]

[ ca ]
default_ca	= CA_default		# The default ca section

[ CA_default ]

dir		= %s		        # Where everything is kept
certs		= $dir/certs		# Where the issued certs are kept
crl_dir		= $dir/crl		# Where the issued crl are kept
database	= $dir/index.txt	# database index file.
new_certs_dir	= $dir/newcerts		# default place for new certs.
certificate	= $dir/cacert.pem 	# The CA certificate
serial		= $dir/serial 		# The current serial number
crlnumber	= $dir/crlnumber	# the current crl number
					# must be commented out to leave a V1 CRL
crl		= $dir/crl.pem 		# The current CRL
private_key	= $dir/private/cakey.pem# The private key
RANDFILE	= $dir/private/.rand	# private random number file

x509_extensions	= usr_cert		# The extentions to add to the cert

name_opt 	= ca_default		# Subject Name options
cert_opt 	= ca_default		# Certificate field options

default_days	= 365			# how long to certify for
default_crl_days= 30			# how long before next CRL
default_md	= sha1			# which md to use.
preserve	= no			# keep passed DN ordering


policy		= policy_anything

[ policy_anything ]
localityName		= optional
commonName		= supplied
organizationName	= optional

[ req ]
default_bits		= 1024
default_keyfile 	= privkey.pem
distinguished_name	= req_distinguished_name
attributes		= req_attributes
x509_extensions	        = v3_ca	   # The extentions to add to the self signed cert
encrypt_key		= no

string_mask = nombstr


[ req_distinguished_name ] 

localityName			= Network Address (IP port)
localityName_default		= 127.0.0.1:14850
commonName			= Common Name (eg, YOUR name)
commonName_max			= 256
organizationName 		= Parameters: size pByz ftL
organizationName_default	= 1000 0.20 1.0 

[ req_attributes]

[ usr_cert ]

basicConstraints=CA:FALSE
subjectKeyIdentifier=hash
authorityKeyIdentifier=keyid,issuer

[ v3_req ]

basicConstraints = CA:FALSE

[ v3_ca ]
subjectKeyIdentifier=hash
authorityKeyIdentifier=keyid:always,issuer:always
basicConstraints = CA:true

[ crl_ext ]

# CRL extensions.
# Only issuerAltName and authorityKeyIdentifier make any sense in a CRL.

# issuerAltName=issuer:copy
authorityKeyIdentifier=keyid:always,issuer:always
"""


def noteFileName(note):
    return "%s-%d" % (note.identity, note.epoch)



class PKIStore:    
  
    def __init__(self, path):        
        self.path = path
        self.certPath = join(path, "certs")
        self.newcertsPath = join(path, "newcerts")
        self.keyPath = join(path, "private")
        self.notesPath = join(path, "notes")
        self.accusationsPath = join(path, "accusations")
        self.caKeyPath = join(self.keyPath, "cakey.pem") 
        self.caCertPath = join(self.path, "cacert.pem")         
        self.configFile = join(self.path, "config")
        self.ensurePaths()   
      
    def ensurePaths(self):
        for path in [self.path, self.certPath, self.keyPath, self.notesPath, self.accusationsPath, self.newcertsPath]: 
            if not os.path.exists(path):
                os.mkdir(path)
            elif not os.path.isdir(path):
                raise RuntimeError, "Path exist " + path                
            elif not os.access(path, os.R_OK | os.W_OK):
                print "%s access error.", path
                raise RuntimeError, "Path access error " + path                
        if not os.path.exists(self.configFile):
            file(self.configFile, "w").write(opensslConfig % self.path)

    def newCA(self, name, maxGroupSize=1000, pByz=0.20,  toleranceLevel=1.0):
        self.clear()
        p = join(self.path, "serial")
        file(p, "w").write("00")
        p = join(self.path, "index.txt")
        file(p, "w")
        opts = "-config " + self.configFile 
        subj = "/CN=%s/organizationName=%d\ %f\ %f" % (name, maxGroupSize, pByz, toleranceLevel)
        tf = os.tempnam()                
        args = (self.configFile, subj, self.caKeyPath, tf)
        os.system("openssl req -config %s -subj %s -new -keyout %s -out %s" % args)
        args = (self.configFile, self.caKeyPath, self.caCertPath, tf)
        os.system("openssl ca -config %s -selfsign -batch -keyfile %s -out %s -infiles %s" % args)
        os.remove(tf)
        
    def nameToKeyPath(self, name):
        return join(self.keyPath, name + ".pem")
        
    def newMember(self, address, name=None):
        if not name: name=address
        opts = "-config " + self.configFile  
        tf = os.tempnam()
        if not name: name = address
        subj = "/L=%s/CN=%s" % (address, name)        
        args = (self.configFile, subj, self.nameToKeyPath(name), tf)
        os.system("openssl req -batch -config %s -subj %s -new -keyout %s -out %s" % args)
        args = (self.configFile, tf)
        os.system("openssl ca -batch -config %s -policy policy_anything -infiles %s" % args)
        os.remove(tf)
        
    def loadCACertificate(self):
        return M2Crypto.X509.load_cert(self.caCertPath)

    def hasCAKey(self):
        return os.path.exists(self.caKeyPath)
    
    def loadCAKey(self):
        return M2Crypto.EVP.load_key(self.caKeyPath)

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
        files = glob.glob(os.path.join(self.certPath, "*"))
        return map(lambda x: M2Crypto.X509.load_cert(x), files)

    def loadMemberCertificateByAddress(self, address):
        for f in glob.glob(os.path.join(self.newcertsPath, "*.pem")):
            cert = M2Crypto.X509.load_cert(f)
            if cert.get_subject().L == address:
                return cert
        raise KeyError, "No certificate matching L=%s found" % address  

    def loadMemberCertificateByName(self, name):
        for f in glob.glob(os.path.join(self.newcertsPath, "*.pem")):
            cert = M2Crypto.X509.load_cert(f)
            if cert.get_subject().CN == name:
                return cert
        raise KeyError, "No certificate matching L=%s found" % name 

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
        path = os.path.join(self.notesPath, noteFileName(note))
        pickle.dump(note, file(path, "w"))

    def saveAccusation(self, accusation):
        isinstance(accusation, fireflies.state.Accusation)
        path = os.path.join(self.accusationsPath, accusation.get_fingerprint())
        pickle.dump(accusation, file(path, "w"))

    def hasPrivateKey(self):
        path = os.path.join(self.keyPath, "key.pem")
        if not os.path.exists(path): return False

    def hasPrivateCertificate(self):
        path = os.path.join(self.keyPath, "cert.pem")
        if not os.path.exists(path): return False        
        
    
    def loadPrivateKeyForCert(self, cert):
        isinstance(cert, M2Crypto.X509.X509)
        data = "signthis."

        for f in glob.glob(os.path.join(self.keyPath, "*.pem")):            
            # Checks that public key in cert match a private key by 
            # signing and verifying some data. This is probably not that efficient but there seems not
            # to be any other way of doing this. 
            key = M2Crypto.EVP.load_key(f)
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
        for f in glob.glob(os.path.join(self.notesPath, "*")):
            note = pickle.load(file(f))
            print f
            if not isinstance(note, fireflies.state.Note): raise ValueError
            if note.identity == identityFromCertificate(cert):
                return note

        raise KeyError, "No matching note found."
                
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
