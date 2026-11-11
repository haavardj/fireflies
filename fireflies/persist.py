# -*- coding: utf-8 -*-
######################################################################
## Filename:      persist.py
## Description:   Fireflies persistence.
## Author:        Håvard Dagenborg <havard.dagenborg@outlook.com>
## Licence:       MIT (see the LICENCE file).
##
##         Copyright© 2006, Håvard Dagenborg
##
######################################################################

"""Classes for making a Fireflies group peristent.

Private keys are stored as PKCS#8 PEM, encrypted when a password is
given. Notes and accusations are pickled."""

import glob
import os
import pickle
from os.path import join, exists, isdir

import fireflies
import fireflies.state
from fireflies import crypto
from fireflies.crypto import identityFromCertificate


def printIdentity(id):
    return id


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
                raise RuntimeError("Path exist " + path)
            elif not os.access(path, os.R_OK | os.W_OK):
                raise RuntimeError("Path access error " + path)
        if not exists(self.fileSerial):
            with open(self.fileSerial, "w") as f:
                f.write("0")

    def newMemberCertificate(self, req, cakey):
        with open(self.fileSerial) as f:
            sn = int(f.readline())
        sn += 1
        caCert = self.loadCACertificate()
        cert = crypto.makeCert(req, caCert, cakey, sn=sn)
        with open(self.fileSerial, "w") as f:
            f.write(str(sn))
        self.saveMemberCertificate(cert)
        return cert

    def saveCACert(self, caCert):
        if not isinstance(caCert, crypto.Certificate): raise ValueError(caCert)
        caCert.save(self.fileCaCert)

    def loadCACertificate(self):
        return crypto.Certificate.load(self.fileCaCert)

    def saveCaPrivKey(self, pkey, password=None):
        pkey.save(self.fileCAPriv, password)

    def hasCACertificate(self):
        return exists(self.fileCaCert)

    def hasCAKey(self):
        return exists(self.fileCAPriv)

    def loadCAKey(self, password=None):
        return crypto.PrivateKey.load(self.fileCAPriv, password)

    def hasMemberCertificateWithAddress(self, address):
        try:
            self.loadMemberCertificateByAddress(address)
        except KeyError:
            return False
        return True

    def hasKeyForCertificate(self, cert):
        return exists(self.filenameKey(cert.get_pubkey()))

    def hasMemberCertificate(self, cert):
        return exists(self.filenameCertificate(cert))

    def hasNote(self, note):
        return exists(self.filenameNote(note))

    def hasAccusation(self, accusation):
        return exists(self.filenameAccusation(accusation))

    def filenameCertificate(self, cert):
        if not isinstance(cert, crypto.Certificate): raise ValueError(cert)
        name = cert.address()
        if os.name == "nt":
            # A colon in a Windows file name opens an NTFS data stream.
            name = name.replace(":", "_")
        return join(self.dirCert, name + ".pem")

    def filenameAccusation(self, accusation):
        if not isinstance(accusation, fireflies.state.Accusation): raise ValueError
        d = (printIdentity(accusation.accused),
             printIdentity(accusation.accuser),
             accusation.epoch)
        return join(self.dirAccu, "%s-%s-%d" % d)

    def filenameNote(self, note):
        if not isinstance(note, fireflies.state.Note): raise ValueError
        return join(self.dirNote, "%s-%d.pem" % (printIdentity(note.identity),
                                                 note.epoch))

    def filenameKey(self, pkey):
        if not isinstance(pkey, (crypto.PublicKey, crypto.PrivateKey)): raise ValueError(pkey)
        name = crypto.computeSubjectKeyIdentifier(pkey)
        name = crypto.subjectKeyIdentifierToID(name)
        return join(self.dirPriv, name + ".pem")

    def _certFiles(self):
        return glob.glob(join(self.dirCert, "*"))

    def loadMemberCertificates(self):
        return [crypto.Certificate.load(x) for x in self._certFiles()]

    def loadMemberCertificateByIdentity(self, iid):
        for f in self._certFiles():
            cert = crypto.Certificate.load(f)
            if identityFromCertificate(cert) == iid:
                return cert
        raise KeyError("No certificate matching ID=%s found" % iid)

    def loadMemberCertificateByAddress(self, address):
        for f in self._certFiles():
            cert = crypto.Certificate.load(f)
            if cert.get_subject().L == address:
                return cert
        raise KeyError("No certificate matching Address=%s found" % address)

    def loadMemberCertificateByName(self, name):
        for f in self._certFiles():
            cert = crypto.Certificate.load(f)
            if cert.get_subject().CN == name:
                return cert
        raise KeyError("No certificate matching Name=%s found" % name)

    @staticmethod
    def _unpickle(path):
        with open(path, "rb") as f:
            return pickle.load(f)

    @staticmethod
    def _pickle(obj, path):
        with open(path, "wb") as f:
            pickle.dump(obj, f)

    def loadNotes(self):
        return [self._unpickle(x) for x in glob.glob(join(self.dirNote, "*"))]

    def loadAccusations(self):
        return [self._unpickle(x) for x in glob.glob(join(self.dirAccu, "*"))]

    def saveMemberCertificate(self, cert):
        if not isinstance(cert, crypto.Certificate): raise ValueError(cert)
        cert.save(self.filenameCertificate(cert))

    def saveNote(self, note):
        if not isinstance(note, fireflies.state.Note): raise ValueError
        self._pickle(note, self.filenameNote(note))

    def saveAccusation(self, accusation):
        if not isinstance(accusation, fireflies.state.Accusation): raise ValueError
        self._pickle(accusation, self.filenameAccusation(accusation))

    def savePrivateKey(self, pkey, password=None):
        pkey.save(self.filenameKey(pkey), password)

    def loadPrivateKeyForCert(self, cert, password=None):
        name = self.filenameKey(cert.get_pubkey())
        if not exists(name):
            raise KeyError("No private key for certificate: %s" % name)
        return crypto.PrivateKey.load(name, password)

    def loadNoteFromCert(self, cert):
        identity = identityFromCertificate(cert)
        for f in glob.glob(join(self.dirNote, "*")):
            note = self._unpickle(f)
            if not isinstance(note, fireflies.state.Note): raise ValueError
            if note.identity == identity:
                return note
        raise KeyError("No matching note found.")

    def clearAccusations(self):
        for f in glob.glob(join(self.dirAccu, "*")):
            os.remove(f)

    def clearNotes(self):
        for f in glob.glob(join(self.dirNote, "*")):
            os.remove(f)

    def clearCertificates(self):
        for f in self._certFiles():
            os.remove(f)

    def saveGroup(self, group):
        for member in group.getView().getAllMembers():
            self.saveMemberCertificate(member.getCertificate())
            n = member.getNote()
            if n: self.saveNote(n)

            for acc in member.getAccusations():
                self.saveAccusation(acc)

    def clear(self):
        self.clearAccusations()
        self.clearNotes()
        self.clearCertificates()
