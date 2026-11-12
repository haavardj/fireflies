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
from typing import TYPE_CHECKING, Any

from fireflies import crypto
from fireflies.crypto import identityFromCertificate
from fireflies.state import Accusation, Note

if TYPE_CHECKING:
    from fireflies.group import Group


def printIdentity(id: str) -> str:
    return id


class Store:

    def __init__(self, dirRoot: str) -> None:
        self.dirRoot = dirRoot
        self.dirCert = join(dirRoot, "certs")
        self.dirNote = join(dirRoot, "notes")
        self.dirAccu = join(dirRoot, "accusations")
        self.dirPriv = join(dirRoot, "private")
        self.fileCAPriv = join(self.dirPriv, "cakey.pem")
        self.fileCaCert = join(self.dirRoot, "cacert.pem")
        self.fileSerial = join(self.dirRoot, "serial")
        self.ensurePaths()

    def ensurePaths(self) -> None:
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

    def newMemberCertificate(self, req: crypto.CertificateRequest, cakey: crypto.PrivateKey) -> crypto.Certificate:
        with open(self.fileSerial) as f:
            sn = int(f.readline())
        sn += 1
        caCert = self.loadCACertificate()
        cert = crypto.makeCert(req, caCert, cakey, sn=sn)
        with open(self.fileSerial, "w") as f:
            f.write(str(sn))
        self.saveMemberCertificate(cert)
        return cert

    def saveCACert(self, caCert: crypto.Certificate) -> None:
        caCert.save(self.fileCaCert)

    def loadCACertificate(self) -> crypto.Certificate:
        return crypto.Certificate.load(self.fileCaCert)

    def saveCaPrivKey(self, pkey: crypto.PrivateKey, password: crypto.Password = None) -> None:
        pkey.save(self.fileCAPriv, password)

    def hasCACertificate(self) -> bool:
        return exists(self.fileCaCert)

    def hasCAKey(self) -> bool:
        return exists(self.fileCAPriv)

    def loadCAKey(self, password: crypto.Password = None) -> crypto.PrivateKey:
        return crypto.PrivateKey.load(self.fileCAPriv, password)

    def hasMemberCertificateWithAddress(self, address: str) -> bool:
        try:
            self.loadMemberCertificateByAddress(address)
        except KeyError:
            return False
        return True

    def hasKeyForCertificate(self, cert: crypto.Certificate) -> bool:
        return exists(self.filenameKey(cert.get_pubkey()))

    def hasMemberCertificate(self, cert: crypto.Certificate) -> bool:
        return exists(self.filenameCertificate(cert))

    def hasNote(self, note: Note) -> bool:
        return exists(self.filenameNote(note))

    def hasAccusation(self, accusation: Accusation) -> bool:
        return exists(self.filenameAccusation(accusation))

    def filenameCertificate(self, cert: crypto.Certificate) -> str:
        name = cert.address()
        if os.name == "nt":
            # A colon in a Windows file name opens an NTFS data stream.
            name = name.replace(":", "_")
        return join(self.dirCert, name + ".pem")

    def filenameAccusation(self, accusation: Accusation) -> str:
        d = (printIdentity(accusation.accused),
             printIdentity(accusation.accuser),
             accusation.epoch)
        return join(self.dirAccu, "%s-%s-%d" % d)

    def filenameNote(self, note: Note) -> str:
        return join(self.dirNote, "%s-%d.pem" % (printIdentity(note.identity),
                                                 note.epoch))

    def filenameKey(self, pkey: "crypto.PublicKey | crypto.PrivateKey") -> str:
        name = crypto.computeSubjectKeyIdentifier(pkey)
        name = crypto.subjectKeyIdentifierToID(name)
        return join(self.dirPriv, name + ".pem")

    def _certFiles(self) -> list[str]:
        return glob.glob(join(self.dirCert, "*"))

    def loadMemberCertificates(self) -> list[crypto.Certificate]:
        return [crypto.Certificate.load(x) for x in self._certFiles()]

    def loadMemberCertificateByIdentity(self, iid: str) -> crypto.Certificate:
        for f in self._certFiles():
            cert = crypto.Certificate.load(f)
            if identityFromCertificate(cert) == iid:
                return cert
        raise KeyError("No certificate matching ID=%s found" % iid)

    def loadMemberCertificateByAddress(self, address: str) -> crypto.Certificate:
        for f in self._certFiles():
            cert = crypto.Certificate.load(f)
            if cert.get_subject().L == address:
                return cert
        raise KeyError("No certificate matching Address=%s found" % address)

    def loadMemberCertificateByName(self, name: str) -> crypto.Certificate:
        for f in self._certFiles():
            cert = crypto.Certificate.load(f)
            if cert.get_subject().CN == name:
                return cert
        raise KeyError("No certificate matching Name=%s found" % name)

    @staticmethod
    def _unpickle(path: str) -> Any:
        with open(path, "rb") as f:
            return pickle.load(f)

    @staticmethod
    def _pickle(obj: object, path: str) -> None:
        with open(path, "wb") as f:
            pickle.dump(obj, f)

    def loadNotes(self) -> list[Note]:
        return [self._unpickle(x) for x in glob.glob(join(self.dirNote, "*"))]

    def loadAccusations(self) -> list[Accusation]:
        return [self._unpickle(x) for x in glob.glob(join(self.dirAccu, "*"))]

    def saveMemberCertificate(self, cert: crypto.Certificate) -> None:
        cert.save(self.filenameCertificate(cert))

    def saveNote(self, note: Note) -> None:
        self._pickle(note, self.filenameNote(note))

    def saveAccusation(self, accusation: Accusation) -> None:
        self._pickle(accusation, self.filenameAccusation(accusation))

    def savePrivateKey(self, pkey: crypto.PrivateKey, password: crypto.Password = None) -> None:
        pkey.save(self.filenameKey(pkey), password)

    def loadPrivateKeyForCert(self, cert: crypto.Certificate, password: crypto.Password = None) -> crypto.PrivateKey:
        name = self.filenameKey(cert.get_pubkey())
        if not exists(name):
            raise KeyError("No private key for certificate: %s" % name)
        return crypto.PrivateKey.load(name, password)

    def loadNoteFromCert(self, cert: crypto.Certificate) -> Note:
        identity = identityFromCertificate(cert)
        for f in glob.glob(join(self.dirNote, "*")):
            note = self._unpickle(f)
            if not isinstance(note, Note): raise ValueError
            if note.identity == identity:
                return note
        raise KeyError("No matching note found.")

    def clearAccusations(self) -> None:
        for f in glob.glob(join(self.dirAccu, "*")):
            os.remove(f)

    def clearNotes(self) -> None:
        for f in glob.glob(join(self.dirNote, "*")):
            os.remove(f)

    def clearCertificates(self) -> None:
        for f in self._certFiles():
            os.remove(f)

    def saveGroup(self, group: "Group") -> None:
        for member in group.getView().getAllMembers():
            self.saveMemberCertificate(member.getCertificate())
            n = member.getNote()
            if n: self.saveNote(n)

            for acc in member.getAccusations():
                self.saveAccusation(acc)

    def clear(self) -> None:
        self.clearAccusations()
        self.clearNotes()
        self.clearCertificates()
