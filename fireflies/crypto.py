######################################################################
## Filename:      crypto.py
## Description:   Fireflies crypto functions.
## Author:        Håvard Dagenborg <havard.dagenborg@outlook.com>
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

from __future__ import annotations

import datetime
import hashlib
from collections.abc import Callable
from typing import Union

from cryptography import x509
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, padding, rsa
from cryptography.hazmat.primitives.asymmetric.types import (
    CertificateIssuerPrivateKeyTypes,
    CertificatePublicKeyTypes,
    PrivateKeyTypes,
)
from cryptography.x509.oid import NameOID

DIGESTALG = "sha256"
DIGESTSIZE = 256
KEYSIZE = 2048
SIGNATURESIZE = KEYSIZE // 8

# TLS 1.3 only allows ECDSA on P-256, P-384 and P-521, so P-224
# (secp224r1, used before the Python 3 port) is no longer an option.
ECCURVE = ec.SECP256R1

_HASH = hashes.SHA256

# Data that can be signed or hashed. Strings are encoded as UTF-8.
Data = str | bytes | bytearray | memoryview

# A password, or a callable that returns one when it is needed.
Password = str | bytes | Callable[[], str | bytes | None] | None

# Anything a public key can be taken from.
KeySource = Union["PublicKey", "PrivateKey", "Certificate"]


def _toBytes(data: Data) -> bytes:
    if isinstance(data, str):
        return data.encode("utf-8")
    return bytes(data)


def _now() -> datetime.datetime:
    return datetime.datetime.now(datetime.timezone.utc)


#
# Keys
#

class PublicKey:
    """A public RSA or EC key."""

    def __init__(self, key: CertificatePublicKeyTypes) -> None:
        self.key = key

    def as_der(self) -> bytes:
        """Return the key as DER-encoded SubjectPublicKeyInfo."""
        return self.key.public_bytes(serialization.Encoding.DER,
                                     serialization.PublicFormat.SubjectPublicKeyInfo)

    def verify(self, signature: bytes | None, data: Data,
               hashAlgorithm: hashes.HashAlgorithm | None = None) -> bool:
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

    def public_key(self) -> PublicKey:
        return self

    def __eq__(self, other: object) -> bool:
        return isinstance(other, PublicKey) and self.as_der() == other.as_der()

    def __hash__(self) -> int:
        return hash(self.as_der())


class PrivateKey:
    """A private RSA or EC key."""

    def __init__(self, key: PrivateKeyTypes) -> None:
        self.key = key

    @classmethod
    def generateRSA(cls, size: int = KEYSIZE) -> PrivateKey:
        return cls(rsa.generate_private_key(public_exponent=65537, key_size=size))

    @classmethod
    def generateEC(cls, curve: type[ec.EllipticCurve] = ECCURVE) -> PrivateKey:
        return cls(ec.generate_private_key(curve()))

    @classmethod
    def fromPEM(cls, data: Data, password: Password = None) -> PrivateKey:
        """Load a PEM key. password is a string, bytes, None, or a
        callable returning one; it is only used if the key is encrypted."""
        raw = _toBytes(data)
        try:
            return cls(serialization.load_pem_private_key(raw, None))
        except TypeError:
            # The key is encrypted.
            pw = _password(password)
            if pw is None:
                raise ValueError("Private key is encrypted; a password is needed.") from None
            return cls(serialization.load_pem_private_key(raw, pw))

    @classmethod
    def load(cls, path: str, password: Password = None) -> PrivateKey:
        with open(path, "rb") as f:
            return cls.fromPEM(f.read(), password)

    def as_pem(self, password: Password = None) -> bytes:
        pw = _password(password)
        enc: serialization.KeySerializationEncryption
        if pw:
            enc = serialization.BestAvailableEncryption(pw)
        else:
            enc = serialization.NoEncryption()
        return self.key.private_bytes(serialization.Encoding.PEM,
                                      serialization.PrivateFormat.PKCS8, enc)

    def save(self, path: str, password: Password = None) -> None:
        with open(path, "wb") as f:
            f.write(self.as_pem(password))

    def public_key(self) -> PublicKey:
        pub = self.key.public_key()
        if not isinstance(pub, (rsa.RSAPublicKey, ec.EllipticCurvePublicKey)):
            raise TypeError("Unsupported key type %s" % type(pub))
        return PublicKey(pub)

    def signingKey(self) -> CertificateIssuerPrivateKeyTypes:
        """Return the key for signing certificates and requests."""
        if not isinstance(self.key, (rsa.RSAPrivateKey, ec.EllipticCurvePrivateKey)):
            raise TypeError("Unsupported key type %s" % type(self.key))
        return self.key

    def as_der(self) -> bytes:
        """Return the public part as DER-encoded SubjectPublicKeyInfo.

        Matches M2Crypto's EVP.PKey.as_der(), which identities are derived from."""
        return self.public_key().as_der()

    def sign(self, data: Data) -> bytes:
        raw = _toBytes(data)
        if isinstance(self.key, rsa.RSAPrivateKey):
            return self.key.sign(raw, padding.PKCS1v15(), _HASH())
        if isinstance(self.key, ec.EllipticCurvePrivateKey):
            return self.key.sign(raw, ec.ECDSA(_HASH()))
        raise TypeError("Unsupported key type %s" % type(self.key))

    def verify(self, signature: bytes | None, data: Data) -> bool:
        return self.public_key().verify(signature, data)


def _password(password: Password) -> bytes | None:
    if callable(password):
        password = password()
    if password is None or password == b"" or password == "":
        return None
    return _toBytes(password)


def passwordPrompt(prompt: str = "Password: ") -> Callable[[], str]:
    """Return a callable that asks for a password on the terminal.
    Use it as the password argument to load or save keys."""
    import getpass

    def ask() -> str:
        return getpass.getpass(prompt)
    return ask


def _publicKey(key: KeySource) -> PublicKey:
    """Accept a PublicKey, PrivateKey or certificate and return a PublicKey."""
    if isinstance(key, Certificate):
        return key.get_pubkey()
    if isinstance(key, (PublicKey, PrivateKey)):  # pyright: ignore[reportUnnecessaryIsInstance]
        return key.public_key()
    raise TypeError("Not a key: %r" % (key,))


def makePrivateECKey(curve: type[ec.EllipticCurve] = ECCURVE, md: str = DIGESTALG) -> PrivateKey:
    return PrivateKey.generateEC(curve)


def makePrivateRSAKey(size: int = KEYSIZE, callback: object = None, md: str = DIGESTALG) -> PrivateKey:
    return PrivateKey.generateRSA(size)


def makePrivateKey(ecc: bool = False) -> PrivateKey:
    return makePrivateECKey() if ecc else makePrivateRSAKey()


#
# Names, certificates and requests
#

class Subject:
    """X509 name with the attribute names M2Crypto used. Missing
    attributes are None."""

    def __init__(self, name: x509.Name) -> None:
        self.name = name

    def _get(self, oid: x509.ObjectIdentifier) -> str | None:
        attrs = self.name.get_attributes_for_oid(oid)
        if not attrs:
            return None
        value = attrs[0].value
        return value if isinstance(value, str) else value.decode("utf-8")

    @property
    def CN(self) -> str | None:
        return self._get(NameOID.COMMON_NAME)

    @property
    def O(self) -> str | None:
        return self._get(NameOID.ORGANIZATION_NAME)

    @property
    def L(self) -> str | None:
        return self._get(NameOID.LOCALITY_NAME)

    commonName = CN
    organizationName = O
    localityName = L

    def __str__(self) -> str:
        return self.name.rfc4514_string()


def _makeName(CN: str | None = None, O: str | None = None, L: str | None = None) -> x509.Name:
    attrs: list[x509.NameAttribute[str]] = []
    if CN is not None:
        attrs.append(x509.NameAttribute(NameOID.COMMON_NAME, CN))
    if O is not None:
        attrs.append(x509.NameAttribute(NameOID.ORGANIZATION_NAME, O))
    if L is not None:
        attrs.append(x509.NameAttribute(NameOID.LOCALITY_NAME, L))
    return x509.Name(attrs)


class Certificate:
    """An X509 certificate (group CA or member)."""

    def __init__(self, cert: x509.Certificate) -> None:
        if not isinstance(cert, x509.Certificate):  # pyright: ignore[reportUnnecessaryIsInstance]
            raise TypeError(cert)
        self.x509 = cert

    @classmethod
    def fromDER(cls, data: bytes) -> Certificate:
        return cls(x509.load_der_x509_certificate(bytes(data)))

    @classmethod
    def fromPEM(cls, data: Data) -> Certificate:
        return cls(x509.load_pem_x509_certificate(_toBytes(data)))

    @classmethod
    def load(cls, path: str) -> Certificate:
        with open(path, "rb") as f:
            data = f.read()
        if data.lstrip().startswith(b"-----BEGIN"):
            return cls.fromPEM(data)
        return cls.fromDER(data)

    def as_der(self) -> bytes:
        return self.x509.public_bytes(serialization.Encoding.DER)

    def as_pem(self) -> bytes:
        return self.x509.public_bytes(serialization.Encoding.PEM)

    def save(self, path: str) -> None:
        with open(path, "wb") as f:
            f.write(self.as_pem())

    save_pem = save

    def get_subject(self) -> Subject:
        return Subject(self.x509.subject)

    def get_issuer(self) -> Subject:
        return Subject(self.x509.issuer)

    def get_pubkey(self) -> PublicKey:
        return PublicKey(self.x509.public_key())

    def get_serial_number(self) -> int:
        return self.x509.serial_number

    def digest(self) -> bytes:
        """SHA-256 digest of the DER encoding."""
        return hashlib.sha256(self.as_der()).digest()

    def get_fingerprint(self, md: str = DIGESTALG) -> str:
        return hashlib.new(md, self.as_der()).hexdigest().upper()

    def verify(self, key: KeySource | None = None) -> bool:
        """Return True if the certificate is signed by key.

        key can be a public key, a private key or the issuer's
        certificate. Without key, check that the certificate is self-signed."""
        pub = self.get_pubkey() if key is None else _publicKey(key)
        return pub.verify(self.x509.signature,
                          self.x509.tbs_certificate_bytes,
                          self.x509.signature_hash_algorithm)

    def check_ca(self) -> bool:
        try:
            bc = self.x509.extensions.get_extension_for_class(x509.BasicConstraints)
        except x509.ExtensionNotFound:
            return False
        return bc.value.ca

    @property
    def identity(self) -> str:
        return identityFromCertificate(self)

    def name(self) -> str | None:
        return self.get_subject().CN

    def address(self) -> str:
        """Return the member's "IP:port" address from the L attribute.

        @raise ValueError: if the certificate has no address."""
        addr = self.get_subject().L
        if addr is None:
            raise ValueError("Certificate has no address (L attribute): %s" % self.get_subject())
        return addr

    def _ringCounts(self) -> list[int]:
        counts = self.get_subject().O
        if counts is None:
            raise ValueError("Not a group certificate (no O attribute): %s" % self.get_subject())
        return [int(x) for x in counts.split()]

    def nrMonitoringRings(self) -> int:
        return self._ringCounts()[0]

    def nrGossipingRings(self) -> int:
        return self._ringCounts()[1]

    def uidstr(self) -> str:
        return self.get_fingerprint()

    def as_text(self) -> str:
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

    def __eq__(self, other: object) -> bool:
        return isinstance(other, Certificate) and self.as_der() == other.as_der()

    def __hash__(self) -> int:
        return hash(self.as_der())

    def __repr__(self) -> str:
        return "<Certificate %s>" % self.get_subject()


# Kept for code that refers to the old names.
GroupCertificate = Certificate
MemberCertificate = Certificate


class CertificateRequest:
    """An X509 certificate signing request."""

    def __init__(self, csr: x509.CertificateSigningRequest) -> None:
        self.csr = csr

    @classmethod
    def fromPEM(cls, data: Data) -> CertificateRequest:
        return cls(x509.load_pem_x509_csr(_toBytes(data)))

    @classmethod
    def load(cls, path: str) -> CertificateRequest:
        with open(path, "rb") as f:
            return cls.fromPEM(f.read())

    def as_pem(self) -> bytes:
        return self.csr.public_bytes(serialization.Encoding.PEM)

    def save(self, path: str) -> None:
        with open(path, "wb") as f:
            f.write(self.as_pem())

    def get_subject(self) -> Subject:
        return Subject(self.csr.subject)

    def get_pubkey(self) -> PublicKey:
        return PublicKey(self.csr.public_key())

    def verify(self, key: KeySource | None = None) -> bool:
        """True if the request's signature is valid and, if key is given,
        the request holds that key."""
        if not self.csr.is_signature_valid:
            return False
        if key is not None and _publicKey(key) != self.get_pubkey():
            return False
        return True

    def as_text(self) -> str:
        return "\n".join([
            "Certificate request:",
            "    Subject:     %s" % self.csr.subject.rfc4514_string(),
            "    Key ID:      %s" % computeSubjectKeyIdentifier(self.get_pubkey()),
        ])


def makeCACert(pkey: PrivateKey, groupName: str, mRings: int, gRings: int, days: int = 30) -> Certificate:
    """Create a self-signed group CA certificate.

    The number of monitoring and gossip rings is stored in the subject's
    O attribute as "<mRings> <gRings>"."""
    name = _makeName(CN=groupName, O="%d %d" % (mRings, gRings))
    now = _now()
    pub = pkey.public_key()
    x = (x509.CertificateBuilder()
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
         .sign(pkey.signingKey(), _HASH()))
    cert = Certificate(x)
    assert cert.check_ca()
    return cert


def makeRequest(address: str, pkey: PrivateKey, version: int = 0,
                nickname: str | None = None) -> CertificateRequest:
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
           .sign(pkey.signingKey(), _HASH()))
    req = CertificateRequest(csr)
    assert req.verify(pkey)
    return req


def makeCert(req: CertificateRequest, caCert: Certificate, caPkey: PrivateKey, sn: int = 1,
             notBefore: int = 0, notAfter: int = 60*60*24*30) -> Certificate:
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
    x = (x509.CertificateBuilder()
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
         .sign(caPkey.signingKey(), _HASH()))
    cert = Certificate(x)
    identityFromCertificate(cert)
    return cert


def loadCertificate(path: str) -> Certificate:
    return Certificate.load(path)


def loadRequest(path: str) -> CertificateRequest:
    return CertificateRequest.load(path)


def loadPrivateKey(path: str, password: Password = None) -> PrivateKey:
    return PrivateKey.load(path, password)


#
# Hashing and identities
#

def fingerprint(data: Data, outputbinary: bool = False) -> bytes | str:
    digest = hashlib.new(DIGESTALG, _toBytes(data))
    if outputbinary:
        return digest.digest()
    return digest.hexdigest()


def sHashDict(d: dict[object, object]) -> bytes:
    """Compute a deterministic hash of a dictionary by hashing its
    items sorted by key.

    @raise TypeError: if d is not a dictionary.
    """
    if not isinstance(d, dict):  # pyright: ignore[reportUnnecessaryIsInstance]
        raise TypeError
    h = hashlib.new(DIGESTALG)
    for k in sorted(d, key=str):
        h.update(("%s=%s," % (k, d[k])).encode("utf-8"))
    return h.digest()


def identitySize() -> int:
    """Returns the size (in bytes) of identity numbers."""
    return DIGESTSIZE // 8


def _skiDigest(pkey: KeySource) -> bytes:
    return hashlib.new(DIGESTALG, _publicKey(pkey).as_der()).digest()


def computeSubjectKeyIdentifierFromCertificate(cert: Certificate) -> str:
    if not isinstance(cert, Certificate):  # pyright: ignore[reportUnnecessaryIsInstance]
        raise ValueError(cert)
    return computeSubjectKeyIdentifier(cert.get_pubkey())


def computeSubjectKeyIdentifier(pkey: PublicKey | PrivateKey) -> str:
    """Return the key identifier as colon-separated upper-case hex."""
    if not isinstance(pkey, (PublicKey, PrivateKey)):  # pyright: ignore[reportUnnecessaryIsInstance]
        raise ValueError(pkey)
    return ":".join("%02X" % b for b in _skiDigest(pkey))


def identityFromCertificate(cert: Certificate) -> str:
    """Return the member identity: the subjectKeyIdentifier as upper-case hex."""
    if not isinstance(cert, Certificate):  # pyright: ignore[reportUnnecessaryIsInstance]
        raise TypeError(cert)
    try:
        ext = cert.x509.extensions.get_extension_for_class(x509.SubjectKeyIdentifier)
    except x509.ExtensionNotFound:
        raise LookupError("No subjectKeyIdentifier in %s" % cert.as_text()) from None
    return ext.value.digest.hex().upper()


def shortIdentity(identity: str) -> str:
    return identity[-4:-1]


def subjectKeyIdentifierToID(s: str) -> str:
    return s.replace(":", "")


#
# Signed objects
#

class Signable:
    """Mixin for signable objects.

    Subclasses implement uidstr(), which returns the string that is signed.

    The fingerprint is cached. If the object changes, clear
    _fingerprint to have it recomputed."""

    signature: bytes = b""
    _fingerprint: bytes | None = None

    def uidstr(self) -> str:
        """Return a unique string identifying this object. This is what is signed."""
        raise NotImplementedError

    def uidbytes(self) -> bytes:
        return _toBytes(self.uidstr())

    def sign(self, pKey: PrivateKey) -> None:
        self.signature = pKey.sign(self.uidbytes())

    def verify(self, pKey: KeySource) -> bool:
        return _publicKey(pKey).verify(self.signature, self.uidbytes())

    def get_fingerprint(self) -> bytes:
        if not self._fingerprint:
            self._fingerprint = hashlib.new(DIGESTALG, self.uidbytes()).digest()
        return self._fingerprint


class SignableString(Signable):
    """A signable string."""

    def __init__(self, string: str) -> None:
        self.string = string

    def uidstr(self) -> str:
        return self.string
