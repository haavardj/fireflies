"""Shared helpers for creating test groups."""

from fireflies import crypto
from fireflies.state import Member, Note

MONITORING_RINGS = 7
GOSSIP_RINGS = 3


def makeCA(ecc: bool = False, name: str = "testgroup", mRings: int = MONITORING_RINGS,
           gRings: int = GOSSIP_RINGS) -> tuple[crypto.Certificate, crypto.PrivateKey]:
    key = crypto.makePrivateKey(ecc)
    return crypto.makeCACert(key, name, mRings, gRings), key


def makeMember(caCert: crypto.Certificate, caKey: crypto.PrivateKey, address: str, sn: int,
               ecc: bool = False) -> tuple[crypto.Certificate, crypto.PrivateKey]:
    key = crypto.makePrivateKey(ecc)
    req = crypto.makeRequest(address, key)
    return crypto.makeCert(req, caCert, caKey, sn=sn), key


def noteOf(member: Member) -> Note:
    """member's current note, which the test expects to exist."""
    note = member.getNote()
    assert note is not None, "%s has no note" % member
    return note
