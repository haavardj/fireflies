
#import fireflies.group, fireflies.members

import logging
from collections.abc import Iterable
from typing import TYPE_CHECKING, Any, Protocol

import twisted.internet.address
from OpenSSL import crypto as ossl
from twisted.internet import protocol, ssl, tcp
from twisted.internet.base import DelayedCall
from twisted.internet.interfaces import IAddress, IHandshakeListener
from twisted.internet.protocol import ReconnectingClientFactory, ServerFactory
from twisted.internet.task import LoopingCall
from twisted.protocols.basic import Int32StringReceiver
from twisted.python.failure import Failure
from zope.interface import implementer  # pyright: ignore[reportMissingTypeStubs]

import fireflies
import fireflies.packer
import fireflies.stats
from fireflies import crypto
from fireflies.state import Member, Note
from fireflies.util import reactor

if TYPE_CHECKING:
    from fireflies.group import Group
    from fireflies.ring import RingSet

debug = False
noiselevel = 0


# A nicer print function for addresses
def _addressStr(address: twisted.internet.address.IPv4Address) -> str:
    return "%s:%d" % (address.host, address.port)

twisted.internet.address.IPv4Address.__str__ = _addressStr  # pyright: ignore[reportAttributeAccessIssue]


class NoCertificate(Exception):
    """The peer did not present a certificate."""


class WrongCertificate(Exception):
    """The peer presented a certificate other than the expected one."""


class GossipService(Protocol):
    """What the factories and protocols here need from the gossip service
    (gossip.Gossip or gossipsim.Gossip)."""

    @property
    def group(self) -> "Group": ...
    @property
    def logger(self) -> logging.Logger: ...
    @property
    def rate(self) -> float: ...
    @property
    def running(self) -> int: ...
    @property
    def active(self) -> "set[ReconnectingPeerFactory]": ...
    @property
    def connectedAsServer(self) -> "set[ReconnectingPeerFactory]": ...
    @property
    def rings(self) -> "RingSet[Member]": ...

    def peerConnected(self, factory: "ReconnectingPeerFactory") -> None: ...
    def getMemberFactory(self, member: Member) -> "ReconnectingPeerFactory": ...


def connect(member: Member, factory: "ReconnectingPeerFactory", timeout: float = 30,
            bindAddress: "tuple[str, int] | None" = None) -> tcp.Connector:
    """Open a TLS connection to member.

    The peer's certificate is checked against the group CA during the
    handshake, and against the expected member afterwards in
    L{FirefliesProtocol.handshakeCompleted}."""
    address = member.address
    return reactor.connectSSL(address.host, address.port, factory,
                                               member.group.getTLSOptions(),
                                               timeout, bindAddress)


def listen(port: int, factory: ServerFactory, contextFactory: ssl.CertificateOptions,
           backlog: int = 5, interface: str = '', reactor: Any = reactor) -> tcp.Port:
    """Listen for TLS connections.

    contextFactory is a Twisted TLS context factory such as the one
    returned by L{makeSSLCtx}."""
    return reactor.listenSSL(port, factory, contextFactory, backlog, interface)


def makeSSLCtx(certificate: crypto.Certificate, key: crypto.PrivateKey,
               ca: crypto.Certificate) -> ssl.CertificateOptions:
    """Return TLS options for a member.

    Both sides present their member certificate and require the peer's
    certificate to be signed by the group CA.
    """
    if not ca.verify():
        raise ValueError("Group certificate is not self-signed.")
    if not certificate.verify(ca):
        raise ValueError("Member certificate is not signed by the group CA.")

    return ssl.CertificateOptions(privateKey=ossl.load_privatekey(ossl.FILETYPE_PEM, key.as_pem()),
                                  certificate=ossl.load_certificate(ossl.FILETYPE_PEM, certificate.as_pem()),
                                  verify=True,
                                  caCerts=[ossl.load_certificate(ossl.FILETYPE_PEM, ca.as_pem())],
                                  requireCertificate=True)


class ReconnectingPeerFactory(ReconnectingClientFactory):
    """If activated, this factory will always try to maintain an active connection to the specified member.
    It will also handle inbound connections so that only a single inbound or outbound connection will be allowed."""

    connectedProtocol: "FirefliesProtocol | None" = None
    continueTrying = 0
    # The gossip service and its client protocol class, set by the service
    # after construction. (Twisted's Factory.protocol is typed against a
    # protocol whose factory cannot be narrowed, so it is not used.)
    service: GossipService
    peerProtocol: "type[FirefliesProtocol] | None" = None
    maxDelay = 10
    maxRetries = 1000000

    def __str__(self) -> str:

        return "Factory(%d) %s A=%s, C=%s" % (hash(self), self.member, self.continueTrying, self.connectedProtocol)

    def __init__(self, member: Member) -> None:
        self.member = member
        self._task = LoopingCall(self.update)

    @property
    def group(self) -> "Group":
        return self.member.group

    @property
    def logger(self) -> logging.Logger:
        return self.service.logger

    def update(self) -> None:
        if self.connectedProtocol and self.connectedProtocol.master:
            self.connectedProtocol.gossip()

    #def startFactory(self):
    #    twisted.internet.protocol.ReconnectingClientFactory.startFactory(self)
    #    if not self.member: raise RuntimeError("Member not set")

    def isActive(self) -> bool:
        return bool(self.continueTrying)

    def activate(self) -> None:
        if self.continueTrying:
            assert self in self.service.active
            self.logger.warning("already activated %s", self.member)
            raise RuntimeError("Already activated")
        else:
            assert not self in self.service.active

        self.continueTrying = 1
        self.service.active.add(self)
        self._task.start(self.service.rate, now=False)

        self.logger.info("activating %s", self.member)
        if not self.connectedProtocol:
            self._connect()
        else:
            assert not self.connectedProtocol.master

    def deactivate(self) -> None:
        self.logger.info("deactivating %s", self.member)
        if not self.isActive(): raise RuntimeError("Member not activated.")
        self._task.stop()
        self.service.active.remove(self)
        self.stopTrying()

        if self.connectedProtocol and self.connectedProtocol.master:
            self.hangup()
            #self.connectedProtocol.hangup()
            #reactor.callLater(0, self.connectedProtocol.hangup)
            #self.connectedProtocol = None

    #
    # Client connection stuff.
    #
    def clientConnectionFailed(self, connector: Any, reason: Failure) -> None:

        assert self.numPorts

        if self.continueTrying and not self.connectedProtocol:
            self.logger.info("clientConnectionFailed %s, retrying", self.member)
            self.connector = connector
            self.retry()  # pyright: ignore[reportUnknownMemberType]  # untyped in Twisted
        else:
            self.logger.info("clientConnectionFailed %s", self.member)

    def clientConnectionLost(self, connector: Any, unused_reason: Failure) -> None:

        assert self.numPorts

        self.connector = connector
        if self.continueTrying and not self.connectedProtocol:
            assert self.isActive()
            self.logger.info("clientConnectionLost %s, retrying", self.member)
            self.retry()  # pyright: ignore[reportUnknownMemberType]  # untyped in Twisted
        else:
            self.logger.info("clientConnectionLost %s", self.member)

    def startedConnecting(self, connector: Any) -> None:
        assert self.numPorts

        self.logger.debug("startedConnecting %s", self.member)

    def connectionLost(self, protocol: "FirefliesProtocol") -> None:

        if self.connectedProtocol != protocol:
            assert protocol.factory == None or protocol.factory == self
            self.logger.info("connectionLost %s non-attached protocol %s", self.member, protocol)
        else:

            self.connectedProtocol = None

            # Reconnect?
            if protocol.master:
                pass
            else:
                if self.isActive():
                    self.logger.info("connectionLost %s was server, now activated as client", self.member)
                    self._connect()
                else:
                    self.logger.info("connectionLost %s was server", self.member)

    def _connect(self) -> None:
        assert not self.connectedProtocol
        assert self.isActive()
        assert self.continueTrying

        connect(self.member, self)

    def isConnected(self) -> bool:
        return bool(self.connectedProtocol)

    def hangup(self) -> None:
        assert self.connectedProtocol is not None
        self.connectedProtocol.hangup()
        self.connectedProtocol = None

    def _outbound(self, member: Member, other: Member) -> list[Member]:
        """member's first successor on each gossip ring that is live or is
        other. Never None: other is on every ring."""
        found = self.service.rings.succ(member, lambda x: x.isLive() or x == other)
        return [x for x in found if x is not None]

    def clientConnected(self, protocol: "FirefliesProtocol") -> None:
        """Connected to the server."""

        assert protocol.master
        assert protocol.member == self.member
        assert protocol.factory == self
        assert self.numPorts

        me = self.service.group.getMe()
        him = protocol.member
        self.resetDelay()

        if not self.isActive():
            protocol.hangup()
            self.logger.info("clientConnected hangup %s inactive", protocol)

        elif self.connectedProtocol:
            assert self.connectedProtocol.master == False
            assert self in self.service.connectedAsServer

            hisOutbound = self._outbound(him, me)
            myOutbound = self._outbound(me, him)

            if me not in hisOutbound or him not in myOutbound:
                # Our views disagree on who is live, so the rings cannot
                # pick a connection. Keep the one that already exists.
                protocol.hangup()
                self.logger.info("clientConnected hangup %s, views differ; keep existing", protocol)
                return

            hisConnectionRing = hisOutbound.index(me)
            myconnectionRing = myOutbound.index(him)

            if hisConnectionRing < myconnectionRing:
                protocol.hangup()
                self.logger.info("serverConnected hangup my connection %s, use his", protocol)
            else:
                oldproto = self.connectedProtocol
                self.logger.info("serverConnected hangup his connection, use mine %s", protocol)
                self.connectedProtocol = protocol
                self.service.peerConnected(self)
                oldproto.hangup()
        else:
            self.connectedProtocol = protocol
            self.logger.info("serverConnected use mine %s, no existing connection", protocol)
            self.service.peerConnected(self)


    def serverConnected(self, protocol: "FirefliesProtocol") -> None:
        """Client connected. Upcall from server-side factory."""

        assert not protocol.master
        assert protocol.member == self.member
        assert protocol.factory == self
        assert self.group.running


        if self.numPorts == 0:
            self.logger.error("error: serverConnected when numbports = 0 %s", self)


        me = self.service.group.getMe()
        him = protocol.member
        hisOutbound = self._outbound(him, me)
        myOutbound = self._outbound(me, him)

        self.logger.info("ReconnectingPeerFactory.serverConnected %s", him)

        if not me in hisOutbound:
            # Not a partner of him, redirect. set() removes duplicate entries.
            protocol.redirect(set(hisOutbound))
            self.logger.info("redirect -> %s", him)
        elif not self.connectedProtocol:
            self.connectedProtocol = protocol
            protocol.accept()
            self.service.peerConnected(self)
            self.logger.info("accept -> %s No connection", him)

        elif self.connectedProtocol.master == False:
            protocol.hangup()
            self.logger.info("hangup -> %s Already connected as client", him)

        elif him not in myOutbound:
            # Our views disagree on who is live (see clientConnected).
            # Keep the existing connection.
            protocol.hangup()
            self.logger.info("hangup -> %s views differ; keep existing", him)

        else:
            hisConnectionRing = hisOutbound.index(me)
            myconnectionRing = myOutbound.index(him)

            if hisConnectionRing < myconnectionRing:
                oldProtocol = self.connectedProtocol
                self.connectedProtocol = protocol
                protocol.accept()
                oldProtocol.hangup()

                self.service.peerConnected(self)
                self.logger.info("accept -> %s In hisConnectionRing < myConnectionRing", him)
            else:
                protocol.hangup()
                self.logger.info("hangup -> %s hisConnectionRing > myConnectionRing", him)

    def getMemberByCertificate(self, x509: crypto.Certificate) -> Member:
        return self.group.getMemberByCertificate(x509)

    def buildProtocol(self, addr: "IAddress | None") -> "FirefliesProtocol":  # pyright: ignore[reportIncompatibleMethodOverride]  # Twisted's protocol type does not allow a narrower factory
        assert self.peerProtocol is not None
        p = self.peerProtocol()
        p.master = True
        p.factory = self
        return p


class PeerServerFactory(ServerFactory):

    # The server protocol class, set by the gossip service.
    peerProtocol: "type[FirefliesProtocol] | None" = None

    def __init__(self, service: GossipService) -> None:
        self.service = service

    @property
    def member(self) -> None:
        return None

    def connectionLost(self, protocol: "FirefliesProtocol") -> None:
        self.logger.debug("connectionLost %s server", protocol)

    def buildProtocol(self, addr: "IAddress | None") -> "FirefliesProtocol":  # pyright: ignore[reportIncompatibleMethodOverride]  # as above
        assert self.peerProtocol is not None
        p = self.peerProtocol()
        p.factory = self
        p.master = False
        return p

    @property
    def logger(self) -> logging.Logger:
        return self.service.logger

    def getMemberFactory(self, member: Member) -> ReconnectingPeerFactory:
        return self.service.getMemberFactory(member)

    def getMemberByCertificate(self, x509: crypto.Certificate) -> Member:
        return self.service.group.getMemberByCertificate(x509)

    def addCertificate(self, x509: crypto.Certificate) -> Member:
        return self.service.group.view.addCertificate(x509)


@implementer(IHandshakeListener)  # pyright: ignore[reportUntypedClassDecorator]
class FirefliesProtocol(Int32StringReceiver):
    STATE_IDLE = "idle"
    STATE_CONNECTING = "conn"
    STATE_HOLDING = "hold"
    STATE_GOSSIPING = "gossip"
    STATE_TERMINATED = "term"
    MAX_LENGTH = 100000000

    state = STATE_CONNECTING
    master = False
    connectionTimeout = 60*2
    factory: "ReconnectingPeerFactory | PeerServerFactory | None" = None

    protonr = 0
    _member: "Member | None" = None
    _timer: "DelayedCall | None" = None
    _stop = False
    # Twisted's TLS transport. ITransport is a zope interface, which
    # pyright cannot call methods on.
    transport: Any = None

    def __init__(self) -> None:
        self.stats = fireflies.stats.Stats()
        self.protonr = FirefliesProtocol.protonr
        FirefliesProtocol.protonr += 1

    def idle(self) -> None:
        """Called when the connection is idle. Subclasses decide what to do."""
        raise NotImplementedError

    def gossip(self) -> None:
        """Start a gossip round. Implemented by client-side subclasses."""
        raise NotImplementedError

    @property
    def peerFactory(self) -> ReconnectingPeerFactory:
        """The factory, which must be a ReconnectingPeerFactory: always on the
        client side, and on the server side after the partner message."""
        assert isinstance(self.factory, ReconnectingPeerFactory)
        return self.factory

    def doIdle(self) -> None:
        assert self.group
        if self.connected and self.factory and self.transport and self.state != self.STATE_TERMINATED:
            self.state = self.STATE_IDLE
            self.idle()

    # Server-side protocols learn their member from the peer's
    # certificate (postConnectionCheck); client-side ones take it from
    # the factory. Python 2's old-style classes let the assignment
    # shadow the property; Python 3 needs the setter.
    @property
    def member(self) -> Member:
        """The peer. Set once the TLS handshake is done."""
        if self._member is not None:
            return self._member
        assert self.factory is not None and self.factory.member is not None
        return self.factory.member

    @member.setter
    def member(self, member: Member) -> None:
        self._member = member

    def hasMember(self) -> bool:
        return self._member is not None or (self.factory is not None and self.factory.member is not None)

    @property
    def service(self) -> GossipService:
        assert self.factory is not None
        return self.factory.service

    @property
    def logger(self) -> logging.Logger:
        assert self.factory is not None
        return self.factory.logger

    @property
    def group(self) -> "Group":
        return self.service.group

    def handshakeCompleted(self) -> None:
        """Called by Twisted when the TLS handshake is done. The peer's
        certificate chain has been verified against the group CA."""
        transport = self.transport
        try:
            peer = transport.getPeerCertificate()
            if peer is None:
                raise NoCertificate("peer did not return certificate")
            self.postConnectionCheck(crypto.Certificate(peer.to_cryptography()),
                                     transport.getPeer())
        except Exception as why:
            self.logger.warning("post connection check failed %s: %s", self, why)
            transport.abortConnection()

    def postConnectionCheck(self, x509: crypto.Certificate, host: IAddress) -> bool:
        assert self.factory is not None
        self.group.view.addCertificate(x509)
        member = self.factory.getMemberByCertificate(x509)

        if not self.master:
            assert not self.hasMember()
            self.member = member
        else:
            if self.member != member:
                raise WrongCertificate('peer did not authenticate with correct certificate')

        self.stats = self.member.group.stats

        self.stats.tcpOpen += 1

        if self.master:
            self.logger.debug("postconnection check master=1")
            reactor.callLater(0, self._sendPartner, self.group.getMe().getNote())
        else:
            self.logger.debug("postconnection check master=0. set timeout")
            self.setTimeout()
        return True

    def connectionMade(self) -> None:
        assert self.group
        self.logger.debug("FirefliesProtocol.connectionMade %s master=%s", self, self.master)

    def connectionLost(self, reason: Failure = protocol.connectionDone) -> None:
        self.state = self.STATE_TERMINATED
        try:
            if self._timer: self.cancelTimeout()
        except KeyboardInterrupt:
            raise
        assert self.factory is not None
        self.factory.connectionLost(self)

    def dataReceived(self, data: bytes) -> None:
        recd = data
        if self.state == self.STATE_TERMINATED:
            self.logger.warning("traffic after hangup.")
            return

        if not self.service.group.running:
            self.logger.warning("traffic after leaving group")
            return

        assert self.service.running == self.service.group.running
        self.stats.tcpR += len(recd)
        return Int32StringReceiver.dataReceived(self, recd)

    def sendString(self, string: bytes) -> None:
        data = string
        if self.state == self.STATE_TERMINATED:
            self.logger.warning("traffic after hangup.")
            return
        self.stats.tcpW += (len(data) + 4)
        Int32StringReceiver.sendString(self, data)  # pyright: ignore[reportUnknownMemberType]  # untyped in Twisted

    def sendCommand(self, cmd: str, *args: Any) -> None:
        assert self.group.running

        try:
            self.sendString(fireflies.packer.PackMessage(cmd, *args))
        except KeyboardInterrupt:
            raise
        except Exception as why:
            self.logger.exception("Exception: Unable to send command %s. %s", cmd, why)

    def stringReceived(self, string: bytes) -> None:
        data = string
        assert self.factory
        assert self.group.running

        try:
            cmd, args = fireflies.packer.unpackMessage(data)
            getattr(self, "handle_" + cmd)(*args)
        except KeyboardInterrupt:
            raise
        except Exception as why:
            self.logger.exception("Exception: Unable to run command: %s", why)

    def hangup(self, hard: bool = True) -> None:
        if hard or (self.state != self.STATE_GOSSIPING):
            if not self.transport: return
            self.transport.loseConnection()
            self.state = self.STATE_TERMINATED
            self.connected = False
        else:
            self._stop = True
        self.logger.debug("hangup %s", self)

    def timedout(self) -> None:
        assert self._timer and not self._timer.active()
        self._timer = None
        self.logger.warning("timeout %s", self)
        self.hangup()

    def __repr__(self) -> str:

        if self.transport:
            addr = self.transport.getPeer()
            return "%s:%d,%s,%d" % (addr.host, addr.port, self.state,self.protonr)
        else:
            return "-:-(%s)" % (self.state)

    def setTimeout(self) -> None:
        if self._timer and self._timer.active():
            raise Exception("Timer already set.")
        self._timer = reactor.callLater(self.connectionTimeout, self.timedout)

    def cancelTimeout(self) -> None:
        assert self._timer and self._timer.active()
        self._timer.cancel()
        self._timer = None


    def handle_version(self, major: int, minor: int, patchlevel: int) -> None:
        #
        # TODO: The node will die if it has an old version
        # number. This is VERY INSECURE and will be removed. However,
        # it is nice for testing on PlanetLab.
        #

        if (major, minor, patchlevel) > fireflies.protocol_version:
            self.logger.warning("version <- %s Version error. I have an old version. Exiting.", self)
            reactor.callLater(2, reactor.stop)
        elif (major, minor, patchlevel) < fireflies.protocol_version:
            self.logger.warning("version <- %s Version error. Other have an old version.", self)

        if not self.master:
            self.cancelTimeout()
            self.sendCommand("version", *fireflies.protocol_version)

    def _sendPartner(self, note: "Note | None") -> None:
        self.logger.debug("partner -> %s", self)
        self.setTimeout()
        self.sendCommand("partner", note)

    def handle_accepted(self) -> None:
        self.cancelTimeout()
        self.logger.info("accepted <- %s", self)
        self.peerFactory.clientConnected(self)
        reactor.callLater(0, self.doIdle)

    def handle_redirect(self, data: "list[tuple[crypto.Certificate, Note]]") -> None:
        self.cancelTimeout()
        self.logger.debug("redirect <- %s", self)
        for cert, note in data:
            self.service.group.view.addCertificate(cert)
            self.service.group.view.addNote(note)
        self.hangup()

    def redirect(self, members: Iterable[Member]) -> None:
        self.stats.redirect += 1
        self.logger.debug("redirect -> %s", self)
        self.setTimeout()
        lst = [(m.getCertificate(), m.getNote()) for m in members]
        self.sendCommand("redirect", lst)

    def accept(self) -> None:
        self.logger.debug("accepted -> %s", self)
        self.sendCommand("accepted")
        reactor.callLater(0, self.doIdle)

    def handle_partner(self, hisNote: Note) -> None:


        assert not self.master
        assert isinstance(self.factory, PeerServerFactory)
        self.cancelTimeout()

        self.factory = self.factory.getMemberFactory(self.member)
        self.service.group.view.addNote(hisNote)
        self.logger.debug("partner <- %s", self)
        self.factory.serverConnected(self)
