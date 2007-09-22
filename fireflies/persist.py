# -*- coding: iso-8859-1 -*-
######################################################################
## Filename:      persist.py
## Description:   Fireflies persistence.
## Author:        Håvard Dagenborg Johansen <haavardj@cs.uit.no>
## Modified at:   Mon Jan 23 20:29:49 2006
## Modified by:   Håvard Dagenborg Johansen <haavardj@cs.uit.no>
## Licence:       GPL (see the LICENSE file).
##  
##         Copyright© 2006, University of Tromsø (Norway)
##                
## $Id: persist.py,v 1.1 2007/09/22 17:45:21 haavardj Exp $
##                
######################################################################

"""Classes for making a Fireflies group peristent."""

import fireflies, glob, pickle, os, random, M2Crypto, struct
from fireflies.crypto import identityFromCertificate, makeCert, fingerprint
from os.path import join, exists, isdir



class Store:    
  
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
            if not exists(path):
                os.mkdir(path)
            elif not isdir(path):
                raise RuntimeError, "Path exist " + path                
            elif not os.access(path, os.R_OK | os.W_OK):
                print "%s access error.", path
                raise RuntimeError, "Path access error " + path                
        if not exists(self.fileSerial):
            file(self.fileSerial, "w").write("0")
        
    def newMemberCertificate(self, req, cakey):
        sn = int(file(self.fileSerial, "r").readline())
        sn += 1        
        caCert = self.loadCACertificate()
        cert = fireflies.crypto.makeCert(req, caCert, cakey, sn=sn)
        file(self.fileSerial, "w").write(str(sn))
        self.saveMemberCertificate(cert)
        return cert

    def saveCACert(self, caCert):
        if not isinstance(caCert, M2Crypto.X509.X509): raise ValueError
        caCert.save_pem(self.fileCaCert)

    def loadCACertificate(self):
        return M2Crypto.X509.load_cert(self.fileCaCert, format=M2Crypto.X509.FORMAT_PEM)

    def saveCaPrivKey(self, pkey, cipher='aes_128_cbc', callback=M2Crypto.util.passphrase_callback):
        return pkey.get_rsa().save_key(self.fileCAPriv, cipher=cipher, callback=callback)                
                
    def hasCAKey(self):
        return exists(self.fileCAPriv)
    
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

    def filenameCertificate(self, cert):
        if not isinstance(cert, M2Crypto.X509.X509): raise ValueError
        return join(self.dirCert, cert.get_subject().L + ".pem")

    def filenameAccusation(self, accusation):
        if not isinstance(accusation, fireflies.state.Accusation): raise ValueError
        name1 = self.loadMemberCertificateByIdentity(accusation.accused).get_subject().L
        name2 = self.loadMemberCertificateByIdentity(accusation.accuser).get_subject().L
        d = (name1, name2, accusation.epoch, accusation.nr)
        return join(self.dirAccu, "%s-%s-%d-%d" %d)

    def filenameNote(self, note):
        if not isinstance(note, fireflies.state.Note): raise ValueError
        cert = self.loadMemberCertificateByIdentity(note.identity)
        name = cert.get_subject().L
        return join(self.dirNote, "%s-%d.pem" % (name, note.epoch))
    
    def filenameKey(self, pkey):
        isinstance(pkey, M2Crypto.EVP.PKey)        
        name = fingerprint(str(pkey.get_modulus()))
        return join(self.dirPriv, name + ".pem")   

    def loadMemberCertificates(self):
        files = glob.glob(os.path.join(self.dirCert, "*"))
        return map(lambda x: M2Crypto.X509.load_cert(x), files)

    def loadMemberCertificateByIdentity(self, id):                
        for f in glob.glob(os.path.join(self.dirCert, "*")):
            cert = M2Crypto.X509.load_cert(f)
            if identityFromCertificate(cert) == id:
                return cert
        raise KeyError, "No certificate matching L=%s found" % address  

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
        files = glob.glob(join(self.dirNote, "*"))
        return map(lambda x: pickle.load(file(x)), files)
    
    def loadAccusations(self):
        files = glob.glob(join(self.dirAccu, "*"))
        return map(lambda x: pickle.load(file(x)), files)

    def saveMemberCertificate(self, cert):
        if not isinstance(cert, M2Crypto.X509.X509): raise ValueError
        cert.save_pem(self.filenameCertificate(cert))

    def saveNote(self, note):
        if 0: isinstance(note, fireflies.state.Note)
        path = self.filenameNote(note)
        pickle.dump(note, file(path, "w"))

    def saveAccusation(self, accusation):
        if 0: isinstance(accusation, fireflies.state.Accusation)

        path = self.filenameAccusation(accusation)
        pickle.dump(accusation, file(path, "w"))      
        
    def savePrivateKey(self, pkey, cipher='aes_128_cbc', callback=M2Crypto.util.passphrase_callback):
        pkey.save_key(self.filenameKey(pkey), cipher=cipher, callback=callback)                    

    def loadPrivateKeyForCert(self, cert, callback=M2Crypto.util.passphrase_callback):
        isinstance(cert, M2Crypto.X509.X509)
        name = self.filenameKey(cert.get_pubkey())
        return M2Crypto.EVP.load_key(name, callback)
       
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
        for f in glob.glob(os.path.join(self.dirCert, "*")):
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
  