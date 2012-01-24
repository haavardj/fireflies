
#import fireflies.group, fireflies.members

import twisted
from twisted.internet import reactor, task, defer, protocol
from twisted.protocols.basic import Int32StringReceiver
from twisted.protocols.policies import ProtocolWrapper, WrappingFactory
from twisted.application import service
from twisted.protocols import policies

import logging, random, os, tempfile
import M2Crypto
import M2Crypto.SSL.TwistedProtocolWrapper as wrapper
from M2Crypto.SSL.Checker import WrongHost, WrongCertificate, NoCertificate 

from zope.interface import implements, Interface, Attribute
import fireflies
import fireflies.state
import fireflies.group
from fireflies import state, crypto, ring, view

debug = False
noiselevel = 0
#M2Crypto.SSL.TwistedProtocolWrapper.debug = 0
# A nicer print function for addresses

twisted.internet.address.IPv4Address.__str__ = lambda x: "%s:%d" % (x.host, x.port)
            
def connect(member, factory, timeout=30, bindAddress=None):
    """
    A convenience function to start an SSL/TLS connection using Twisted.
    
    See IReactorSSL interface in Twisted. 
    """
    
    ctx = member.group
    address = member.address
    
    wrappingFactory = policies.WrappingFactory(factory)
    wrappingFactory.protocol = lambda factory, wrappedProtocol: \
                   wrapper.TLSProtocolWrapper(factory,
                                      wrappedProtocol,
                                      startPassThrough=0,
                                      client=1,
                                      contextFactory=ctx,
                                      postConnectionCheck=ClientConnectionChecker(member.getCertificate()))
        
    return reactor.connectTCP(address.host, address.port, wrappingFactory, timeout, bindAddress)
                              

def listen(port,
           factory,
           contextFactory, 
           backlog=5, 
           interface='',
           reactor=twisted.internet.reactor,  
           postConnectionCheck=M2Crypto.SSL.TwistedProtocolWrapper._alwaysSucceedsPostConnectionCheck):
    """
    A convenience function to listen for SSL/TLS connections using Twisted. 

    See IReactorSSL interface in Twisted. 
    """
    wrappingFactory = policies.WrappingFactory(factory)
    wrappingFactory.protocol = lambda factory, wrappedProtocol: \
                   wrapper.TLSProtocolWrapper(factory,
                                              wrappedProtocol,
                                              startPassThrough=0,
                                              client=0,
                                              contextFactory=contextFactory,
                                              postConnectionCheck=postConnectionCheck)
    
    return reactor.listenTCP(port, wrappingFactory, backlog, interface)
         

def makeSSLCtx(certificate, key, ca):
    if 0: isinstance(ca, state.GroupCertificate)
    if 0: isinstance(certificate, state.MemberCertificate)
    if 0: isinstance(key, M2Crypto.EVP.PKey)
        
    certificate = certificate
    key = key
    ca = ca
        
    ca.verify()
    certificate.verify(ca.get_pubkey())
    ctx = M2Crypto.SSL.Context("sslv23")
                
    #M2Crypto's SSL context objects do only support loading keys and
    #certificates from files. As such, we need to write these items to
    #temporary files and then load the context with these.
        
    cD, cN = tempfile.mkstemp()
    os.close(cD)
    kD, kN = tempfile.mkstemp()
    os.close(kD)
    caD, caN = tempfile.mkstemp()
    os.close(caD)
        
    certificate.save(cN)
    
    # We do not want to read and write private keys in cleartext.
    secret = str(random.randint(0,2**128)) 
    key.save_key(kN, callback=lambda x: secret)
    ca.save(caN)
    
    ctx.load_cert(cN, kN, callback=lambda x: secret)       
    ctx.set_client_CA_list_from_file(caN)
    ctx.load_verify_locations(caN)
    ctx.set_verify(M2Crypto.SSL.verify_peer | M2Crypto.SSL.verify_fail_if_no_peer_cert, 9) #.verify_none,0)
    
    ctx.set_allow_unknown_ca(False)  
    #ctx.set_verify(M2Crypto.SSL.verify_peer | M2Crypto.SSL.verify_fail_if_no_peer_cert, 9, sslVerifyCB)
    #ctx.set_verify(M2Crypto.SSL.verify_client_once, 2)
    if debug: ctx.set_info_callback()
    
    #Remove temporary files.
    os.remove(cN)
    os.remove(kN)
    os.remove(caN)
    return ctx
    
   
def sslPostConnectionCheck(peerX509, expectedHost):
    print "Post connection check"
    print peerX509, expectedHost
    return True


class ClientConnectionChecker:
    
    def __init__(self, certificate):
        self.expectedCertificate = certificate
        
    def __call__(self, peerCert, host=None):
        
        isinstance(peerCert, M2Crypto.X509.X509)
        if peerCert is None:
            raise NoCertificate('peer did not return certificate')
        
        if peerCert.get_fingerprint() != self.expectedCertificate.get_fingerprint():
            raise WrongCertificate('peer did return wrong certificate')        
        return True

    
class ReconnectingPeerFactory(twisted.internet.protocol.ReconnectingClientFactory):
    """If activated, this factory will always try to maintain an active connection to the specified member.
    It will also handle inbound connections so that only a single inbound or outbound connection will be allowed."""
    
    connectedProtocol = None
    continueTrying = 0
    service = None
    
    def __init__(self, member):
        self.member = member        
        isinstance(self.member, fireflies.state.Member)

    @property
    def group(self):
        isinstance(self.member.group, fireflies.group.Group)
        return self.member.group
        
    @property
    def logger(self):
        return self.service.logger
        
    def startFactory(self):
        if not self.member: raise RuntimeError("Member not set")
        
    def stopFactory(self):
        pass
    
    def isActive(self):
        return self.continueTrying
    
    def activate(self):
        if self.isActive(): 
            self.logger.warning("already activated %s", self.member)
            raise RuntimeError("Already activated")        

        self.continueTrying = 1
        self.logger.info("activating %s", self.member)
        if not self.connectedProtocol:
            self._connect()
        else:
            assert not self.connectedProtocol.master

    def deactivate(self):
        self.logger.info("deactivating %s", self.member)
        if not self.isActive(): raise RuntimeError("Already deactivated")
        self.stopTrying()
        if self.connectedProtocol:
            self.connectedProtocol.hangup()
            self.connectedProtocol = None

    #
    # Client connection stuff.
    #
    def clientConnectionFailed(self, connector, reason):
        if self.continueTrying and not self.connectedProtocol:
            assert self.isActive()
            self.logger.info("clientConnectionFailed %s, retrying", self.member)
            self.connector = connector
            self.retry()
        else:
            self.logger.info("clientConnectionFailed %s", self.member)

    def clientConnectionLost(self, connector, reason):
        self.connector = connector
        if self.continueTrying and not self.connectedProtocol: 
            assert self.isActive()
            self.logger.info("clientConnectionLost %s, retrying", self.member)
            self.connector = connector
            self.retry()                     
        else:
            self.logger.info("clientConnectionLost %s", self.member)
                
    def startedConnecting(self, connector):
        pass
        #self.logger.debug("startedConnecting %s", self.member)                

    def connectionLost(self, protocol):
        
        if self.connectedProtocol != protocol:
            assert protocol.factory == None or protocol.factory == self
            self.logger.info("connectionLost %s non-attached protocol %s", self.member, protocol)
        else:
            self.connectedProtocol = None
            
            if protocol.master:
                # clientConnectionLost will be called
                pass
            else:
                self.logger.info("connectionLost %s attached client", self.member)
                if self.isActive():
                    self._connect()
                              
    def _connect(self):
        assert not self.connectedProtocol
        assert self.isActive()
        assert self.continueTrying
        
        fireflies.protocols.connect(self.member, self)
              
    def isConnected(self):
        return bool(self.connectedProtocol)

    def disconnect(self):
        if not self.isConnected(): raise RuntimeError("Not connected")
        self.connectedProtocol.hangup()
        self.connectedProtocol = None
        if self.isActive():
            if self.connector:
                self.retry()
            else:
                self._connect()
                
    def serverConnected(self, protocol):
        """Connected to the server."""
         
        assert protocol.master
        assert protocol.member == self.member
        assert protocol.factory == self
        
        me = self.service.group.getMe()
        him = protocol.member
        self.resetDelay()
        
        if not self.isActive():
            protocol.hangup()
            self.logger.info("serverConnected hangup %s inactive", protocol)
 
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
                self.connectedProtocol.hangup()
                self.logger.info("serverConnected hangup his connection, use mine %s", protocol)
                self.connectedProtocol = protocol
                self.resetDelay()
                self.service.peerConnected(self)                
        else:
            self.connectedProtocol = protocol
            self.logger.info("serverConnected use mine %s, no existing connection", protocol)            
            self.service.peerConnected(self)                
                

    def clientConnected(self, protocol):
        """Client connected. Upcall from server-side factory."""
     
        assert not protocol.master
        assert protocol.member == self.member
        assert protocol.factory == self
        
        me = self.service.group.getMe()
        him = protocol.member  
        hisOutbound = self.service.rings.succ(him, lambda x: x.isLive() or x == me)
        myOutbound = self.service.rings.succ(me, lambda x: x.isLive() or x == him)

        self.logger.info("ReconnectingPeerFactory.clientConnected %s", him)        

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
                self.disconnect()
                self.connectedProtocol = protocol
                protocol.accept()
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
        p.group = self.service.group
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
    

class FirefliesProtocol(Int32StringReceiver):
    STATE_IDLE = "idle"
    STATE_CONNECTING = "conn"
    STATE_HOLDING = "hold"
    STATE_GOSSIPING = "gossip"
    STATE_TERMINATED = "term"
    MAX_LENGTH = 100000000


    state = STATE_CONNECTING
    master = False
    connectionTimeout = fireflies.defaultConfig['tcptimeout']
    factory = None
    
    protonr = 0
    
    def __init__(self):
        self.stats = fireflies.stats.Stats()        
        self.protonr = FirefliesProtocol.protonr
        FirefliesProtocol.protonr += 1
        isinstance(self.factory, ReconnectingPeerFactory)
        
    def doIdle(self):
        if self.connected and self.factory and self.transport and self.state != self.STATE_TERMINATED:            
            self.state = self.STATE_IDLE
            reactor.callLater(0, self.idle)
    
    @property
    def member(self):
        return self.factory.member
        
    @property
    def service(self):
        return self.factory.service
    
    @property
    def logger(self):
        return self.factory.logger

    @property
    def group(self):
        return self.service.group
    
    def postConnectionCheck(self, x509, host):
        isinstance(x509, M2Crypto.X509.X509)
        
        self.group.view.addCertificate(x509)
        member = self.factory.getMemberByCertificate(x509)
        
        if not self.master:
            assert not self.member
            self.member = member
        else:
            if self.member != member:
                raise WrongCertificate('peer did not authenticate with correct certificate')
        
        self.member.stats += self.stats
        self.stats = self.member.stats
    
        self.stats.tcpOpen += 1
        
        if self.master:
            reactor.callLater(0, self._sendPartner, self.group.getMe().getNote())
        else:
            self.setTimeout()          
        return True
    
    def connectionMade(self):
        self.logger.debug("FirefliesProtocol.connectionMade %s", self)        
        self.transport.postConnectionCheck = self.postConnectionCheck

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
        self.stats.tcpR += len(recd)        
        return Int32StringReceiver.dataReceived(self, recd)

    def sendString(self, data):
        if self.state == self.STATE_TERMINATED:
            self.logger.warning("traffic after hangup.")
            return        
        self.stats.tcpW += (len(data) + 4)
        return Int32StringReceiver.sendString(self, data)

    def sendCommand(self, cmd, *args):
        try:        
            self.sendString(fireflies.packer.PackMessage(cmd, *args))
        except KeyboardInterrupt:
            raise
        except Exception, why:
            self.logger.exception("Unable to send command %s. %s", cmd, why)
            
    def stringReceived(self, data):
        try:
            cmd, args = fireflies.packer.unpackMessage(data)
            getattr(self, "handle_" + cmd)(*args)
        except KeyboardInterrupt:
            raise
        except Exception, why:
            self.logger.exception("Unable to run command %s: %s", cmd, why)
                    
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
            raise Exception, "Timer already set."
        self._timer = reactor.callLater(self.connectionTimeout, self.timedout)

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
            reactor.callLater(2, reactor.stop)
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
        self.logger.debug("accepted <- %s", self)
        reactor.callLater(0, self.factory.serverConnected, self)
        reactor.callLater(0, self.doIdle)
        
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
        reactor.callLater(0, self.doIdle)
            
    def handle_partner(self, hisNote):
        
        
        assert not self.master
        self.cancelTimeout()
        
        self.factory = self.factory.getMemberFactory(self.member)        
        self.factory.service.parent.getView().addNote(hisNote)
        self.logger.debug("partner <- %s", self)
        reactor.callLater(0, self.factory.clientConnected, self)

        
