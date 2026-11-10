
#import fireflies.group, fireflies.members

import twisted
import twisted.internet
import twisted.internet.address
import twisted.internet.reactor
from twisted.internet import task, defer, protocol
from twisted.internet.task import LoopingCall
from twisted.protocols.basic import Int32StringReceiver
from twisted.application import service

import logging

from twisted.internet import ssl
from twisted.internet.interfaces import IHandshakeListener
from zope.interface import implementer

import fireflies
import fireflies.packer
import fireflies.state
import fireflies.stats
from fireflies import crypto

debug = False
noiselevel = 0

# A nicer print function for addresses
twisted.internet.address.IPv4Address.__str__ = lambda x: "%s:%d" % (x.host, x.port)


class NoCertificate(Exception):
    """The peer did not present a certificate."""


class WrongCertificate(Exception):
    """The peer presented a certificate other than the expected one."""


def connect(member, factory, timeout=30, bindAddress=None):
    """Open a TLS connection to member.

    The peer's certificate is checked against the group CA during the
    handshake, and against the expected member afterwards in
    L{FirefliesProtocol.handshakeCompleted}."""
    address = member.address
    return twisted.internet.reactor.connectSSL(address.host, address.port, factory,
                                               member.group.getTLSOptions(),
                                               timeout, bindAddress)


def listen(port, factory, contextFactory, backlog=5, interface='',
           reactor=twisted.internet.reactor):
    """Listen for TLS connections.

    contextFactory is a Twisted TLS context factory such as the one
    returned by L{makeSSLCtx}."""
    return reactor.listenSSL(port, factory, contextFactory, backlog, interface)


def makeSSLCtx(certificate, key, ca):
    """Return TLS options for a member.

    Both sides present their member certificate and require the peer's
    certificate to be signed by the group CA.

    @type certificate: L{fireflies.crypto.Certificate}
    @type key: L{fireflies.crypto.PrivateKey}
    @type ca: L{fireflies.crypto.Certificate}
    @rtype: L{twisted.internet.ssl.CertificateOptions}
    """
    if not ca.verify():
        raise ValueError("Group certificate is not self-signed.")
    if not certificate.verify(ca):
        raise ValueError("Member certificate is not signed by the group CA.")

    own = ssl.PrivateCertificate.loadPEM(certificate.as_pem() + key.as_pem())
    caCert = ssl.Certificate.loadPEM(ca.as_pem())
    return ssl.CertificateOptions(privateKey=own.privateKey.original,
                                  certificate=own.original,
                                  verify=True,
                                  caCerts=[caCert.original],
                                  requireCertificate=True)

    
class ReconnectingPeerFactory(twisted.internet.protocol.ReconnectingClientFactory):
    """If activated, this factory will always try to maintain an active connection to the specified member.
    It will also handle inbound connections so that only a single inbound or outbound connection will be allowed."""
    
    connectedProtocol = None
    continueTrying = 0
    service = None
    maxDelay = 10
    maxRetries = 1000000
    
    def __str__(self):
          
        return "Factory(%d) %s A=%s, C=%s" % (hash(self), self.member, self.continueTrying, self.connectedProtocol)
    
    def __init__(self, member):
        self.member = member        
        self._task = LoopingCall(self.update)  
        isinstance(self.member, fireflies.state.Member)        

    @property
    def group(self):
        isinstance(self.member.group, fireflies.group.Group)
        return self.member.group
        
    @property
    def logger(self):
        return self.service.logger

    def update(self):
        if self.connectedProtocol and self.connectedProtocol.master:
            self.connectedProtocol.gossip()
        
    #def startFactory(self):
    #    twisted.internet.protocol.ReconnectingClientFactory.startFactory(self)
    #    if not self.member: raise RuntimeError("Member not set")
    
    def isActive(self):
        return self.continueTrying
    
    def activate(self):
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
            
    def deactivate(self):        
        self.logger.info("deactivating %s", self.member)
        if not self.isActive(): raise RuntimeError("Member not activated.")
        self._task.stop()
        self.service.active.remove(self)
        self.stopTrying()        
        
        if self.connectedProtocol and self.connectedProtocol.master:
            self.hangup()
            #self.connectedProtocol.hangup()
            #twisted.internet.reactor.callLater(0, self.connectedProtocol.hangup)
            #self.connectedProtocol = None

    #
    # Client connection stuff.
    #
    def clientConnectionFailed(self, connector, reason):
        
        assert self.numPorts
        
        if self.continueTrying and not self.connectedProtocol:
            self.logger.info("clientConnectionFailed %s, retrying", self.member)
            self.connector = connector
            self.retry()
        else:
            self.logger.info("clientConnectionFailed %s", self.member)

    def clientConnectionLost(self, connector, reason):

        assert self.numPorts        
        
        self.connector = connector
        if self.continueTrying and not self.connectedProtocol: 
            assert self.isActive()
            self.logger.info("clientConnectionLost %s, retrying", self.member)
            self.retry()                                         
        else:
            self.logger.info("clientConnectionLost %s", self.member)
                
    def startedConnecting(self, connector):        
        assert self.numPorts
    
        self.logger.debug("startedConnecting %s", self.member)                

    def connectionLost(self, protocol):
        
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
                              
    def _connect(self):
        assert not self.connectedProtocol
        assert self.isActive()
        assert self.continueTrying
        
        fireflies.protocols.connect(self.member, self)
              
    def isConnected(self):
        return bool(self.connectedProtocol)

    def hangup(self):
        self.connectedProtocol.hangup()
        self.connectedProtocol = None
                
    def clientConnected(self, protocol):
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
            
            hisOutbound = self.service.rings.succ(him, lambda x: x.isLive() or x == me)
            myOutbound = self.service.rings.succ(me, lambda x: x.isLive() or x == him)
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
            

    def serverConnected(self, protocol):
        """Client connected. Upcall from server-side factory."""
      
        assert not protocol.master
        assert protocol.member == self.member
        assert protocol.factory == self
        assert self.group.running


        if self.numPorts == 0:
            self.logger.error("error: serverConnected when numbports = 0 %s", self)

        
        me = self.service.group.getMe()
        him = protocol.member  
        hisOutbound = self.service.rings.succ(him, lambda x: x.isLive() or x == me)
        myOutbound = self.service.rings.succ(me, lambda x: x.isLive() or x == him)

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
        
        else:
            assert him in myOutbound
            
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

    def getMemberByCertificate(self, x509):
        return self.group.getMemberByCertificate(x509)

    def buildProtocol(self, address):
        p = self.protocol()
        p.master = True
        p.factory = self
        return p


class PeerServerFactory(twisted.internet.protocol.ServerFactory):
    
    def __init__(self, service):
        self.service = service
        
    @property
    def member(self):
        return None
        
    def connectionLost(self, protocol):
        self.logger.debug("connectionLost %s server", protocol)

    def buildProtocol(self, address):
        p = twisted.internet.protocol.ServerFactory.buildProtocol(self, address)
        p.master = False        
        return p

    @property
    def logger(self):
        return self.service.logger
    
    def getMemberFactory(self, member):
        return self.service.getMemberFactory(member)
    
    def getMemberByCertificate(self, x509):
        return self.service.group.getMemberByCertificate(x509)
    
    def addCertificate(self, x509):
        return self.service.group.addCertificate(x509)
    

@implementer(IHandshakeListener)
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
    factory = None
    
    protonr = 0
    _member = None
    _timer = None

    def __init__(self):
        self.stats = fireflies.stats.Stats()        
        self.protonr = FirefliesProtocol.protonr
        FirefliesProtocol.protonr += 1
        isinstance(self.factory, ReconnectingPeerFactory)
        
    def doIdle(self):
        assert self.group
        if self.connected and self.factory and self.transport and self.state != self.STATE_TERMINATED:            
            self.state = self.STATE_IDLE
            self.idle()
    
    # Server-side protocols learn their member from the peer's
    # certificate (postConnectionCheck); client-side ones take it from
    # the factory. Python 2's old-style classes let the assignment
    # shadow the property; Python 3 needs the setter.
    @property
    def member(self):
        if self._member is not None:
            return self._member
        return self.factory.member

    @member.setter
    def member(self, member):
        self._member = member

    @property
    def service(self):
        return self.factory.service
    
    @property
    def logger(self):
        return self.factory.logger

    @property
    def group(self):
        return self.service.group
    
    def handshakeCompleted(self):
        """Called by Twisted when the TLS handshake is done. The peer's
        certificate chain has been verified against the group CA."""
        try:
            peer = self.transport.getPeerCertificate()
            if peer is None:
                raise NoCertificate("peer did not return certificate")
            self.postConnectionCheck(crypto.Certificate(peer.to_cryptography()),
                                     self.transport.getPeer())
        except Exception as why:
            self.logger.warning("post connection check failed %s: %s", self, why)
            self.transport.abortConnection()

    def postConnectionCheck(self, x509, host):
        self.group.view.addCertificate(x509)
        member = self.factory.getMemberByCertificate(x509)
        
        if not self.master:
            assert not self.member
            self.member = member
        else:
            if self.member != member:
                raise WrongCertificate('peer did not authenticate with correct certificate')
        
        self.stats = self.member.group.stats
    
        self.stats.tcpOpen += 1
        
        if self.master:
            self.logger.debug("postconnection check master=1")
            twisted.internet.reactor.callLater(0, self._sendPartner, self.group.getMe().getNote())
        else:
            self.logger.debug("postconnection check master=0. set timeout")
            self.setTimeout()          
        return True
    
    def connectionMade(self):
        assert self.group
        self.logger.debug("FirefliesProtocol.connectionMade %s master=%s", self, self.master)

    def connectionLost(self, reason):
        self.state = self.STATE_TERMINATED
        try:
            if self._timer: self.cancelTimeout()
        except KeyboardInterrupt:
            raise
        self.factory.connectionLost(self)

    def dataReceived(self, recd):
        if self.state == self.STATE_TERMINATED:
            self.logger.warning("traffic after hangup.")
            return

        if not self.factory.service.group.running: 
            self.logger.warning("traffic after leaving group")
            return
        
        assert self.factory.service.running == self.factory.service.group.running
        self.stats.tcpR += len(recd)      
        return Int32StringReceiver.dataReceived(self, recd)

    def sendString(self, data):
        if self.state == self.STATE_TERMINATED:
            self.logger.warning("traffic after hangup.")
            return        
        self.stats.tcpW += (len(data) + 4)
        return Int32StringReceiver.sendString(self, data)

    def sendCommand(self, cmd, *args):
        assert self.group.running
        
        try:        
            self.sendString(fireflies.packer.PackMessage(cmd, *args))
        except KeyboardInterrupt:
            raise
        except Exception as why:
            self.logger.exception("Exception: Unable to send command %s. %s", cmd, why)
            
    def stringReceived(self, data):
        assert self.factory
        assert self.group.running
                
        try:
            cmd, args = fireflies.packer.unpackMessage(data)
            getattr(self, "handle_" + cmd)(*args)
        except KeyboardInterrupt:
            raise
        except Exception as why:
            self.logger.exception("Exception: Unable to run command: %s", why)
                    
    def hangup(self, hard=True):
        if hard or (self.state != self.STATE_GOSSIPING):
            if not self.transport: return
            self.transport.loseConnection()
            self.state = self.STATE_TERMINATED    
            self.connected = False
        else:
            self._stop = True
        self.logger.debug("hangup %s", self)

    def timedout(self):
        assert self._timer and not self._timer.active()   
        self._timer = None
        self.logger.warning("timeout %s", self)
        self.hangup()

    def __repr__(self):
   
        if self.transport:
            addr = self.transport.getPeer()
            return "%s:%d,%s,%d" % (addr.host, addr.port, self.state,self.protonr)
        else:
            return "-:-(%s)" % (self.state)

    def setTimeout(self):
        if self._timer and self._timer.active():
            raise Exception("Timer already set.")
        self._timer = twisted.internet.reactor.callLater(self.connectionTimeout, self.timedout)

    def cancelTimeout(self):
        assert self._timer and self._timer.active()        
        self._timer.cancel()
        self._timer = None
   
        
    def handle_version(self, major, minor, patchlevel):
        #
        # TODO: The node will die if it has an old version
        # number. This is VERY INSECURE and will be removed. However,
        # it is nice for testing on PlanetLab.
        #
        
        if (major, minor, patchlevel) > fireflies.protocol_version:
            self.logger.warning("version <- %s Version error. I have an old version. Exiting.", self)
            twisted.internet.reactor.callLater(2, twisted.internet.reactor.stop)
        elif (major, minor, patchlevel) < fireflies.protocol_version:
            self.logger.warning("version <- %s Version error. Other have an old version.", self)
            
        if not self.master:
            self.cancelTimeout()
            self.sendCommand("version", *fireflies.protocol_version)

    def _sendPartner(self, note):
        self.logger.debug("partner -> %s", self)
        self.setTimeout()
        self.sendCommand("partner", note)
        
    def handle_accepted(self):   
        self.cancelTimeout()
        self.logger.info("accepted <- %s", self)
        self.factory.clientConnected(self)
        twisted.internet.reactor.callLater(0, self.doIdle)
        
    def handle_redirect(self, data):
        self.cancelTimeout()
        self.logger.debug("redirect <- %s", self)
        for cert, note in data:
            self.factory.service.group.view.addCertificate(cert)
            self.factory.service.group.view.addNote(note)   
        self.hangup()

    def redirect(self, members):
        self.stats.redirect += 1
        self.logger.debug("redirect -> %s", self)
        self.setTimeout()
        lst = []
        for m in members:
            lst.append( (m.getCertificate(), m.getNote() ))
        self.sendCommand("redirect", lst)

    def accept(self):
        self.logger.debug("accepted -> %s", self)
        self.sendCommand("accepted")
        twisted.internet.reactor.callLater(0, self.doIdle)
            
    def handle_partner(self, hisNote):
        
        
        assert not self.master
        self.cancelTimeout()
        
        self.factory = self.factory.getMemberFactory(self.member)        
        self.factory.service.parent.getView().addNote(hisNote)
        self.logger.debug("partner <- %s", self)
        self.factory.serverConnected(self)

        
