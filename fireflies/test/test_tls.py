"""TLS between members over loopback, using the options from makeSSLCtx."""

from twisted.internet import defer, protocol, reactor
from twisted.internet.interfaces import IHandshakeListener
from twisted.trial import unittest
from zope.interface import implementer

from fireflies import crypto, protocols
from fireflies.test.helpers import makeCA, makeMember

from typing import TYPE_CHECKING, Any

# The mixins below use TestCase methods; tell the type checker so without
# making them test cases trial would collect.
if TYPE_CHECKING:
    _TestCase = unittest.TestCase
else:
    _TestCase = object


@implementer(IHandshakeListener)
class Probe(protocol.Protocol):
    """Reports the peer certificate after the handshake, or the failure."""

    factory: Any

    def handshakeCompleted(self):
        transport: Any = self.transport
        peer = transport.getPeerCertificate()
        if not self.factory.result.called:
            self.factory.result.callback(crypto.Certificate(peer.to_cryptography()))
        transport.loseConnection()

    def connectionLost(self, reason: Any = protocol.connectionDone):
        if not self.factory.result.called:
            self.factory.result.errback(reason)


class ProbeFactory(protocol.ClientFactory):
    protocol = Probe

    def __init__(self):
        self.result = defer.Deferred()

    def clientConnectionFailed(self, connector, reason):
        if not self.result.called:
            self.result.errback(reason)


class _TLSTests(_TestCase):

    ecc = False

    def setUp(self):
        self.caCert, self.caKey = makeCA(self.ecc)
        self.serverCert, serverKey = makeMember(self.caCert, self.caKey, "127.0.0.1:1", 1, self.ecc)
        self.clientCert, clientKey = makeMember(self.caCert, self.caKey, "127.0.0.1:2", 2, self.ecc)
        self.serverOpts = protocols.makeSSLCtx(self.serverCert, serverKey, self.caCert)
        self.clientOpts = protocols.makeSSLCtx(self.clientCert, clientKey, self.caCert)
        self.serverFactory = ProbeFactory()
        self.port = reactor.listenSSL(0, self.serverFactory, self.serverOpts, interface="127.0.0.1")

    def tearDown(self):
        return self.port.stopListening()

    def connect(self, opts):
        f = ProbeFactory()
        reactor.connectSSL("127.0.0.1", self.port.getHost().port, f, opts)
        return f

    @defer.inlineCallbacks
    def testMutualAuthentication(self):
        client = self.connect(self.clientOpts)
        seenByClient = yield client.result
        seenByServer = yield self.serverFactory.result
        self.assertEqual(seenByClient, self.serverCert)
        self.assertEqual(seenByServer, self.clientCert)

    @defer.inlineCallbacks
    def testForeignCARejected(self):
        otherCA, otherKey = makeCA(self.ecc, "other")
        cert, key = makeMember(otherCA, otherKey, "127.0.0.1:3", 1, self.ecc)
        client = self.connect(protocols.makeSSLCtx(cert, key, otherCA))
        results = yield defer.DeferredList([client.result, self.serverFactory.result],
                                           consumeErrors=True)
        self.assertEqual([ok for ok, _ in results], [False, False])

    def testMakeSSLCtxChecksChain(self):
        otherCA, otherKey = makeCA(self.ecc, "other")
        cert, key = makeMember(otherCA, otherKey, "127.0.0.1:3", 1, self.ecc)
        self.assertRaises(ValueError, protocols.makeSSLCtx, cert, key, self.caCert)


class RSATLSTest(_TLSTests, unittest.TestCase):
    pass


class ECTLSTest(_TLSTests, unittest.TestCase):
    ecc = True
