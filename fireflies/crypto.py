# -*- coding: utf-8 -*-
######################################################################
## Filename:      crypto.py
## Description:   Fireflies crypto functions.
## Author:        Håvard Dagenborg Johansen <haavardj@cs.uit.no>
## Licence:       MIT (see the LICENCE file).
##
##         Copyright© 2006, Håvard Dagenborg
##
######################################################################

"""Cryptographic stuff: keys, X509 certificates and requests, signing.

Built on the `cryptography` package. The classes below wrap its objects
and keep the method names the rest of Fireflies used with M2Crypto
(get_subject, get_pubkey, verify, as_der, ...).

Signatures use SHA-256: PKCS#1 v1.5 for RSA keys, ECDSA for EC keys.
"""

import datetime
import hashlib

from cryptography import x509
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, padding, rsa
from cryptography.x509.oid import NameOID

DIGESTALG = "sha256"
DIGESTSIZE = 256
KEYSIZE = 2048
SIGNATURESIZE = KEYSIZE // 8

# TLS 1.3 only allows ECDSA on P-256, P-384 and P-521, so P-224
# (secp224r1, used before the Python 3 port) is no longer an option.
ECCURVE = ec.SECP256R1

_HASH = hashes.SHA256


def _toBytes(data):
    if isinstance(data, str):
        return data.encode("utf-8")
    return bytes(data)


def _now():
    return datetime.datetime.now(datetime.timezone.utc)


#
# Keys
#

class PublicKey:
    """A public RSA or EC key."""

    def __init__(self, key):
        self.key = key

    def as_der(self):
        """Return the key as DER-encoded SubjectPublicKeyInfo."""
        return self.key.public_bytes(serialization.Encoding.DER,
                                     serialization.PublicFormat.SubjectPublicKeyInfo)

    def verify(self, signature, data, hashAlgorithm=None):
        """Return True if signature is a valid signature of data."""
        if not signature:
            return False
        h = hashAlgorithm or _HASH()
        try:
            if isinstance(self.key, rsa.RSAPublicKey):
                self.key.verify(bytes(signature), _toBytes(data), padding.PKCS1v15(), h)
            elif isinstance(self.key, ec.EllipticCurvePublicKey):
                self.key.verify(bytes(signature), _toBytes(data), ec.ECDSA(h))
            else:
                raise TypeError("Unsupported key type %s" % type(self.key))
        except InvalidSignature:
            return False
        return True

    def public_key(self):
        return self

    def __eq__(self, other):
        return isinstance(other, PublicKey) and self.as_der() == other.as_der()

    def __hash__(self):
        return hash(self.as_der())


class PrivateKey:
    """A private RSA or EC key."""

    def __init__(self, key):
        self.key = key

    @classmethod
    def generateRSA(cls, size=KEYSIZE):
        return cls(rsa.generate_private_key(public_exponent=65537, key_size=size))

    @classmethod
    def generateEC(cls, curve=ECCURVE):
        return cls(ec.generate_private_key(curve()))

    @classmethod
    def fromPEM(cls, data, password=None):
        """Load a PEM key. password is a string, bytes, None, or a
        callable returning one; it is only used if the key is encrypted."""
        data = _toBytes(data)
        try:
            return cls(serialization.load_pem_private_key(data, None))
        except TypeError:
            # The key is encrypted.
            pw = _password(password)
            if pw is None:
                raise ValueError("Private key is encrypted; a password is needed.")
            return cls(serialization.load_pem_private_key(data, pw))

    @classmethod
    def load(cls, path, password=None):
        with open(path, "rb") as f:
            return cls.fromPEM(f.read(), password)

    def as_pem(self, password=None):
        pw = _password(password)
        if pw:
            enc = serialization.BestAvailableEncryption(pw)
        else:
            enc = serialization.NoEncryption()
        return self.key.private_bytes(serialization.Encoding.PEM,
                                      serialization.PrivateFormat.PKCS8, enc)

    def save(self, path, password=None):
        with open(path, "wb") as f:
            f.write(self.as_pem(password))

    def public_key(self):
        return PublicKey(self.key.public_key())

    def as_der(self):
        """Return the public part as DER-encoded SubjectPublicKeyInfo.

        Matches M2Crypto's EVP.PKey.as_der(), which identities are derived from."""
        return self.public_key().as_der()

    def sign(self, data):
        data = _toBytes(data)
        if isinstance(self.key, rsa.RSAPrivateKey):
            return self.key.sign(data, padding.PKCS1v15(), _HASH())
        if isinstance(self.key, ec.EllipticCurvePrivateKey):
            return self.key.sign(data, ec.ECDSA(_HASH()))
        raise TypeError("Unsupported key type %s" % type(self.key))

    def verify(self, signature, data):
        return self.public_key().verify(signature, data)


def _password(password):
    if callable(password):
        password = password()
    if password is None or password == b"" or password == "":
        return None
    return _toBytes(password)


def passwordPrompt(prompt="Password: "):
    """Return a callable that asks for a password on the terminal.
    Use it as the password argument to load or save keys."""
    import getpass
    def ask():
        return getpass.getpass(prompt)
    return ask


def _publicKey(key):
    """Accept a PublicKey, PrivateKey or certificate and return a PublicKey."""
    if isinstance(key, Certificate):
        return key.get_pubkey()
    if isinstance(key, (PublicKey, PrivateKey)):
        return key.public_key()
    raise TypeError("Not a key: %r" % (key,))


def makePrivateECKey(curve=ECCURVE, md=DIGESTALG):
    return PrivateKey.generateEC(curve)


def makePrivateRSAKey(size=KEYSIZE, callback=None, md=DIGESTALG):
    return PrivateKey.generateRSA(size)


def makePrivateKey(ecc=False):
    return makePrivateECKey() if ecc else makePrivateRSAKey()


#
# Names, certificates and requests
#

class Subject:
    """X509 name with the attribute names M2Crypto used."""

    def __init__(self, name):
        self.name = name

    def _get(self, oid):
        attrs = self.name.get_attributes_for_oid(oid)
        return attrs[0].value if attrs else None

    @property
    def CN(self):
        return self._get(NameOID.COMMON_NAME)

    @property
    def O(self):
        return self._get(NameOID.ORGANIZATION_NAME)

    @property
    def L(self):
        return self._get(NameOID.LOCALITY_NAME)

    commonName = CN
    organizationName = O
    localityName = L

    def __str__(self):
        return self.name.rfc4514_string()


def _makeName(CN=None, O=None, L=None):
    attrs = []
    if CN is not None:
        attrs.append(x509.NameAttribute(NameOID.COMMON_NAME, CN))
    if O is not None:
        attrs.append(x509.NameAttribute(NameOID.ORGANIZATION_NAME, O))
    if L is not None:
        attrs.append(x509.NameAttribute(NameOID.LOCALITY_NAME, L))
    return x509.Name(attrs)


class Certificate:
    """An X509 certificate (group CA or member)."""

    def __init__(self, cert):
        if not isinstance(cert, x509.Certificate):
            raise TypeError(cert)
        self.x509 = cert

    @classmethod
    def fromDER(cls, data):
        return cls(x509.load_der_x509_certificate(bytes(data)))

    @classmethod
    def fromPEM(cls, data):
        return cls(x509.load_pem_x509_certificate(_toBytes(data)))

    @classmethod
    def load(cls, path):
        with open(path, "rb") as f:
            data = f.read()
        if data.lstrip().startswith(b"-----BEGIN"):
            return cls.fromPEM(data)
        return cls.fromDER(data)

    def as_der(self):
        return self.x509.public_bytes(serialization.Encoding.DER)

    def as_pem(self):
        return self.x509.public_bytes(serialization.Encoding.PEM)

    def save(self, path):
        with open(path, "wb") as f:
            f.write(self.as_pem())

    save_pem = save

    def get_subject(self):
        return Subject(self.x509.subject)

    def get_issuer(self):
        return Subject(self.x509.issuer)

    def get_pubkey(self):
        return PublicKey(self.x509.public_key())

    def get_serial_number(self):
        return self.x509.serial_number

    def digest(self):
        """SHA-256 digest of the DER encoding."""
        return hashlib.sha256(self.as_der()).digest()

    def get_fingerprint(self, md=DIGESTALG):
        return hashlib.new(md, self.as_der()).hexdigest().upper()

    def verify(self, key=None):
        """Return True if the certificate is signed by key.

        key can be a public key, a private key or the issuer's
        certificate. Without key, check that the certificate is self-signed."""
        pub = self.get_pubkey() if key is None else _publicKey(key)
        return pub.verify(self.x509.signature,
                          self.x509.tbs_certificate_bytes,
                          self.x509.signature_hash_algorithm)

    def check_ca(self):
        try:
            bc = self.x509.extensions.get_extension_for_class(x509.BasicConstraints)
        except x509.ExtensionNotFound:
            return False
        return bc.value.ca

    @property
    def identity(self):
        return identityFromCertificate(self)

    def name(self):
        return self.get_subject().CN

    def nrMonitoringRings(self):
        return int(self.get_subject().O.split()[0])

    def nrGossipingRings(self):
        return int(self.get_subject().O.split()[1])

    def uidstr(self):
        return self.get_fingerprint()

    def as_text(self):
        c = self.x509
        try:
            ski = identityFromCertificate(self)
        except LookupError:
            ski = "-"
        return "\n".join([
            "Certificate:",
            "    Serial:      %d" % c.serial_number,
            "    Subject:     %s" % c.subject.rfc4514_string(),
            "    Issuer:      %s" % c.issuer.rfc4514_string(),
            "    Not before:  %s" % c.not_valid_before_utc,
            "    Not after:   %s" % c.not_valid_after_utc,
            "    CA:          %s" % self.check_ca(),
            "    Identity:    %s" % ski,
            "    Fingerprint: %s" % self.get_fingerprint(),
        ])

    def __eq__(self, other):
        return isinstance(other, Certificate) and self.as_der() == other.as_der()

    def __hash__(self):
        return hash(self.as_der())

    def __repr__(self):
        return "<Certificate %s>" % self.get_subject()


# Kept for code that refers to the old names.
GroupCertificate = Certificate
MemberCertificate = Certificate


class CertificateRequest:
    """An X509 certificate signing request."""

    def __init__(self, csr):
        self.csr = csr

    @classmethod
    def fromPEM(cls, data):
        return cls(x509.load_pem_x509_csr(_toBytes(data)))

    @classmethod
    def load(cls, path):
        with open(path, "rb") as f:
            return cls.fromPEM(f.read())

    def as_pem(self):
        return self.csr.public_bytes(serialization.Encoding.PEM)

    def save(self, path):
        with open(path, "wb") as f:
            f.write(self.as_pem())

    def get_subject(self):
        return Subject(self.csr.subject)

    def get_pubkey(self):
        return PublicKey(self.csr.public_key())

    def verify(self, key=None):
        """True if the request's signature is valid and, if key is given,
        the request holds that key."""
        if not self.csr.is_signature_valid:
            return False
        if key is not None and _publicKey(key) != self.get_pubkey():
            return False
        return True

    def as_text(self):
        return "\n".join([
            "Certificate request:",
            "    Subject:     %s" % self.csr.subject.rfc4514_string(),
            "    Key ID:      %s" % computeSubjectKeyIdentifier(self.get_pubkey()),
        ])


def makeCACert(pkey, groupName, mRings, gRings, days=30):
    """Create a self-signed group CA certificate.

    The number of monitoring and gossip rings is stored in the subject's
    O attribute as "<mRings> <gRings>"."""
    name = _makeName(CN=groupName, O="%d %d" % (mRings, gRings))
    now = _now()
    pub = pkey.public_key()
    cert = (x509.CertificateBuilder()
            .subject_name(name)
            .issuer_name(name)
            .public_key(pub.key)
            .serial_number(1)
            .not_valid_before(now)
            .not_valid_after(now + datetime.timedelta(days=days))
            .add_extension(x509.SubjectKeyIdentifier(_skiDigest(pub)), critical=False)
            .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
            .add_extension(x509.KeyUsage(digital_signature=True, content_commitment=False,
                                         key_encipherment=False, data_encipherment=False,
                                         key_agreement=False, key_cert_sign=True,
                                         crl_sign=True, encipher_only=False,
                                         decipher_only=False), critical=True)
            .sign(pkey.key, _HASH()))
    cert = Certificate(cert)
    assert cert.check_ca()
    return cert


def makeRequest(address, pkey, version=0, nickname=None):
    """Create an X509 certificate request.

    @param address: "IP:port" contact address. Stored in the L attribute.
    @param pkey: Private key of the requester.
    @param nickname: Member name for the CN attribute. Defaults to address.
    @rtype: L{CertificateRequest}
    """
    if nickname is None:
        nickname = address
    csr = (x509.CertificateSigningRequestBuilder()
           .subject_name(_makeName(CN=nickname, L=address))
           .sign(pkey.key, _HASH()))
    req = CertificateRequest(csr)
    assert req.verify(pkey)
    return req


def makeCert(req, caCert, caPkey, sn=1, notBefore=0, notAfter=60*60*24*30):
    """Create an X509 member certificate from a request.

    @param req: Certificate request.
    @param caCert: The CA's certificate.
    @param caPkey: The CA's private key.
    @param sn: Serial number (must be positive).
    @param notBefore: Start of validity, in seconds relative to now.
    @param notAfter: End of validity, in seconds relative to now.
    @rtype: L{Certificate}
    """
    if not req.verify():
        raise ValueError("Error verifying request.")
    pub = req.get_pubkey()
    now = _now()
    cert = (x509.CertificateBuilder()
            .subject_name(req.csr.subject)
            .issuer_name(caCert.x509.subject)
            .public_key(pub.key)
            .serial_number(sn)
            .not_valid_before(now + datetime.timedelta(seconds=notBefore))
            .not_valid_after(now + datetime.timedelta(seconds=notAfter))
            .add_extension(x509.SubjectKeyIdentifier(_skiDigest(pub)), critical=False)
            # Copy the CA's own key identifier. from_issuer_public_key()
            # would compute a SHA-1 one that does not match it.
            .add_extension(x509.AuthorityKeyIdentifier.from_issuer_subject_key_identifier(
                caCert.x509.extensions.get_extension_for_class(x509.SubjectKeyIdentifier).value),
                critical=False)
            .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
            .sign(caPkey.key, _HASH()))
    cert = Certificate(cert)
    identityFromCertificate(cert)
    return cert


def loadCertificate(path):
    return Certificate.load(path)


def loadRequest(path):
    return CertificateRequest.load(path)


def loadPrivateKey(path, password=None):
    return PrivateKey.load(path, password)


#
# Hashing and identities
#

def fingerprint(data, outputbinary=False):
    digest = hashlib.new(DIGESTALG, _toBytes(data))
    if outputbinary:
        return digest.digest()
    return digest.hexdigest()


def sHashDict(d):
    """Compute a deterministic hash of a dictionary by hashing its
    items sorted by key.

    @raise TypeError: if d is not a dictionary.
    """
    if not isinstance(d, dict):
        raise TypeError
    h = hashlib.new(DIGESTALG)
    for k in sorted(d, key=str):
        h.update(("%s=%s," % (k, d[k])).encode("utf-8"))
    return h.digest()


def identitySize():
    """Returns the size (in bytes) of identity numbers."""
    return DIGESTSIZE // 8


def _skiDigest(pkey):
    return hashlib.new(DIGESTALG, _publicKey(pkey).as_der()).digest()


def computeSubjectKeyIdentifierFromCertificate(cert):
    if not isinstance(cert, Certificate):
        raise ValueError(cert)
    return computeSubjectKeyIdentifier(cert.get_pubkey())


def computeSubjectKeyIdentifier(pkey):
    """Return the key identifier as colon-separated upper-case hex."""
    if not isinstance(pkey, (PublicKey, PrivateKey)):
        raise ValueError(pkey)
    return ":".join("%02X" % b for b in _skiDigest(pkey))


def identityFromCertificate(cert):
    """Return the member identity: the subjectKeyIdentifier as upper-case hex."""
    if not isinstance(cert, Certificate):
        raise TypeError(cert)
    try:
        ext = cert.x509.extensions.get_extension_for_class(x509.SubjectKeyIdentifier)
    except x509.ExtensionNotFound:
        raise LookupError("No subjectKeyIdentifier in %s" % cert.as_text())
    return ext.value.digest.hex().upper()


def shortIdentity(identity):
    return identity[-4:-1]


def subjectKeyIdentifierToID(s):
    return s.replace(":", "")


#
# Signed objects
#

class ImmutableMixin:
    """Mixin for immutable classes."""
    def __setattr_im__(self, k, v):
        raise RuntimeError("immutable error")

    def makeImmutable(self):
        self.__setattr__ = self.__setattr_im__


class Signable:
    """Mixin for signable objects.

    Subclasses implement uidstr(), which returns the string that is signed.

    The fingerprint is cached. If the object changes, clear
    _fingerprint to have it recomputed."""

    signature = b""
    _fingerprint = None

    def uidstr(self):
        """Return a unique string identifying this object. This is what is signed."""
        raise NotImplementedError

    def uidbytes(self):
        return _toBytes(self.uidstr())

    def sign(self, pKey):
        self.signature = pKey.sign(self.uidbytes())

    def verify(self, pKey):
        return _publicKey(pKey).verify(self.signature, self.uidbytes())

    def get_fingerprint(self):
        if not self._fingerprint:
            self._fingerprint = hashlib.new(DIGESTALG, self.uidbytes()).digest()
        return self._fingerprint


class SignableString(Signable):
    """A signable string."""

    def __init__(self, string):
        self.string = string

    def uidstr(self):
        return self.string
