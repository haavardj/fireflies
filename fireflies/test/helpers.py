"""Shared helpers for creating test groups."""

from fireflies import crypto

MONITORING_RINGS = 7
GOSSIP_RINGS = 3


def makeCA(ecc=False, name="testgroup", mRings=MONITORING_RINGS, gRings=GOSSIP_RINGS):
    key = crypto.makePrivateKey(ecc)
    return crypto.makeCACert(key, name, mRings, gRings), key


def makeMember(caCert, caKey, address, sn, ecc=False):
    key = crypto.makePrivateKey(ecc)
    req = crypto.makeRequest(address, key)
    return crypto.makeCert(req, caCert, caKey, sn=sn), key
