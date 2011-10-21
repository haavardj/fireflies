
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

class IPeerNetworkingService(Interface):
    
    ServerProtocolClass = Attribute("""Class for server protocols""")
    ClientProtocolClass = Attribute("""Class for client protocols""")
    rings = Attribute("""Set of membership rings.""")
    group = Attribute("""Group object.""")
    
    def getPerFactoryFromProtocol(protocol):
        pass
    
    def peerConnected(self, peer): 
        pass
    
    


class ReconnectingPeerFactory(twisted.internet.protocol.ReconnectingClientFactory):
    """If activated, this factory will always try to maintain an active connection to the specified member.
    It will also handle inbound connections so that only a single inbound or outbound connection will be allowed."""
    
    logger = logging.getLogger()
    protocol = None
    member = None
    continueTrying = 0
    
    def __init__(self, service):
        self.service = service
        
    def startFactory(self):
        if not self.member: raise RuntimeError("Member not set")
    
    def isActive(self):
        return self.continueTrying
    
    def activate(self):
        if self.isActive(): 
            self.logger.warning("already activated %s", self.member)
            assert self.continueTrying
            raise RuntimeError("Already activated")        

        self.continueTrying = 1
        self.logger.info("activating %s", self.member)                
        self._connect()

    def deactivate(self):
        self.logger.info("deactivating %s", self.member)
        if not self.isActive(): raise RuntimeError("Already deactivated")
        self.stopTrying()

    #
    # Client connection stuff.
    #
    def clientConnectionFailed(self, connector, reason):
        self.logger.info("clientConnectionFailed %s", self.member)
        if self.continueTrying and not self.protocol:
            self.connector = connector
            self.retry()

    def clientConnectionLost(self, connector, reason):
        self.logger.info("clientConnectionLost %s", self.member)
        self.connector = connector
        if self.continueTrying and not self.protocol: 
            self.connector = connector
            self.retry()                     
                
    def startedConnecting(self, connector):
        #assert not self.protocol # Never start trying while a protocol is running.
        
        self.logger.debug("startedConnecting %s", self.member)                

    def connectionLost(self, protocol):
        
        if self.protocol != protocol:
            self.logger.info("connectionLost %s non-attached protocol", self.member)
        else:
            self.protocol = None
            
            if protocol.master:
                # clientConnectionLost will be called
                pass
            else:
                self.logger.info("connectionLost %s attached client", self.member)
                if self.isActive():
                    self._connect()
                              
    def _connect(self):
        assert not self.protocol
        host, port = self.member.getAddress().split(":")
        port = int(port)
        fireflies.protocols.connect(self.member, self)
              

    def serverConnected(self, protocol):
        """Server Connected"""
        
        assert protocol.master
        me = self.service.group.getMe()
        him = protocol.other

        self.logger.info("serverConnected %s", him)

        if not self.isActive():
            protocol.hangup()
            self.logger.info("hangup -> %s Not active.", him)

        elif self.protocol:
            assert self.protocol.master == False
            assert self in self.service.connectedAsServer
            
            hisOutbound = self.service.rings.succ(him, lambda x: x.isLive() or x == me)
            myOutbound = self.service.rings.succ(me, lambda x: x.isLive() or x == him)
            hisConnectionRing = hisOutbound.index(me)            
            myconnectionRing = myOutbound.index(him)
            
            if hisConnectionRing < myconnectionRing:
                protocol.hangup()
                self.logger.info("hangup -> %s My connection use his", him)
            else:
                self.protocol.hangup()
                self.logger.info("hangup -> %s His Connection use mine", him)
                self.protocol = protocol
                self.resetDelay()
                self.service.peerConnected(self)                
        else:
            self.protocol = protocol
            self.logger.info("connected %s as client.", self.member)            
            self.service.peerConnected(self)

    def isConnected(self):
        return self.protocol != None

    def disconnect(self):
        if not self.isConnected(): raise RuntimeError("Not connected")
        self.protocol.hangup()
        self.protocol = None
        if self.isActive():
            if self.connector:
                self.retry()
            else:
                self._connect()

    def clientConnected(self, protocol):
        """Client connected. Upcall from server-side factory."""

        assert not protocol.master
        assert protocol.other == self.member
        protocol.factory = self
        
        me = self.service.group.getMe()
        him = protocol.other               
        hisOutbound = self.service.rings.succ(him, lambda x: x.isLive() or x == me)
        myOutbound = self.service.rings.succ(me, lambda x: x.isLive() or x == him)

        self.logger.info("clientConnected %s", him)

        if not me in hisOutbound:
            # Not a partner of him, redirect. set() removes duplicate entries.            
            protocol.redirect(set(hisOutbound))            
            self.logger.info("redirect -> %s", him)
        elif not self.protocol:
            self.protocol = protocol
            protocol.accept()
            self.service.peerConnected(self)
            self.logger.info("accept -> %s No connection", him)

        elif self.protocol.master == False:
            protocol.hangup()
            self.logger.info("hangup -> %s Already connected as client", him)
        
        else:
            assert him in myOutbound
            
            hisConnectionRing = hisOutbound.index(me)            
            myconnectionRing = myOutbound.index(him)            
            
            if hisConnectionRing < myconnectionRing:
                self.disconnect()
                self.protocol = protocol
                protocol.accept()
                self.service.peerConnected(self)
                self.logger.info("accept -> %s In hisConnectionRing < myConnectionRing", him)  
            else:
                protocol.hangup()
                self.logger.info("hangup -> %s hisConnectionRing > myConnectionRing", him)


    def buildProtocol(self, address):
        p = self.service.ClientProtocolClass()
        p.other = self.member
        p.master = True
        p.group = self.service.group
        p.factory = self
        p.logger = self.logger
        return p


class PeerServerFactory(twisted.internet.protocol.ServerFactory):
    
    logger = logging.getLogger()

    def __init__(self, service):
        self.service = service

    def clientConnected(self, protocol):            
        self.service.getPeerFactoryFromProtocol(protocol).clientConnected(protocol)
        
    def connectionLost(self, protocol):
        self.logger.debug("connectionLost %s server", protocol)

    def buildProtocol(self, address):
        p = self.service.ServerProtocolClass()
        p.master = False
        p.factory = self
        p.service = self.service
        return p


import pickle    
class SSLAuthenticatedProtocol(Int32StringReceiver):
    
    factory = None
    certificate = None
    log = logging.getLogger("SSLAuthenticatedProtocol")
    
    def postConnection(self, x509, host):
        #logging.debug("postConnection %s %s", x509, host)
        if not x509: return False 
        isinstance(x509, M2Crypto.X509.X509)
        self.x509 = crypto.MemberCertificate(x509.x509)
        self.factory.clientConnectionMade(self)
        reactor.callLater(0, self.next)
        return True 
     
        
    def getCertificate(self):
        return self.x509
    
    def connectionMade(self):  
        #logging.debug("%s connectionMade", self.factory.node.getMe().address)
        self.transport.postConnectionCheck = self.postConnection

    def connectionLost(self, reason):
        if self in self.factory._connections:
            self.factory._connections.remove(self)
                         
    def stringReceived(self, msg):
        if noiselevel > 0: self.log.debug("%s<-%s %s ", self.factory.node.me, self.factory, msg)

        try:
            remoteOID, localOID, args, kwargs = pickle.loads(msg)
            self.factory.receiveMessage(self, remoteOID, localOID, *args, **kwargs)
        except:
            self.log.exception("%s<-%s Error processing message: %s", self.factory.node.me, self.factory, msg)            
            
    def sendMessage(self, localOID, remoteOID, *args, **kwargs):
        s = pickle.dumps( (localOID, remoteOID, args, kwargs))
        #self.log.debug("%s->%s %s", self.factory.node.getMe(), self.factory, s)
        self.sendString(s)
        
            
    def dataReceived(self, recd):
        if self.state == self.STATE_TERMINATED:
            self.logger.warning("traffic after hangup.")
            return
        self.factory.service.parent.view.stats.tcpR += len(recd)
        return Int32StringReceiver.dataReceived(self, recd)

    def sendString(self, data):
        if self.state == self.STATE_TERMINATED:
            self.logger.warning("traffic after hangup.")
            return        
        self.factory.service.parent.view.stats.tcpW += (len(data) + 4)
        return Int32StringReceiver.sendString(self, data)



class UnsecuredDatagramProtocol(protocol.DatagramProtocol):

    log = logging.getLogger("UnAuthenticatedDatagramProtocol")
    
    
    def datagramReceived(self, data, (host, port)):      
        memberID, remoteOID, localOID, args, kwargs = pickle.loads(data)    
        root = self.factory.getRootService()        
        m = root.getMemberByIdentity(memberID)
        m.receiveMessage(self, remoteOID, localOID, *args, **kwargs)
               
    def sendMessage(self, member, localOID, remoteOID, *args, **kwargs):        
        s = pickle.dumps( (member.identity, localOID, remoteOID, args, kwargs))
        self.transport.write( s, (member.address.host, member.address.port))
        


    
class AuthenticatedReliableFiFO(protocol.ReconnectingClientFactory):

    protocol = SSLAuthenticatedProtocol
    unsafeTracebacks = 1
    continueTrying = 0
    _active = False
    _allowConnectionFrom = False
    _allowConnectionTo = False
    
    def __init__(self, member):
        
        if 0: isinstance(certificate, state.MemberCertificate)
        if 0: isinstance(self.node, Node)
        self._pendingActivation = set()
        self._msgQueue = defer.DeferredQueue()
        self._connections = set()
        self.member = member
        self.certificate = member.certificate
        self.log = logging.getLogger("protocols.peer")
        
    def sendMessage(self, *args, **kwargs):
        self.log.debug("%s->%s %s %s", self.node.me, self, args, kwargs)
        #self.activate()
        self._msgQueue.put( (args, kwargs))
            
    def receiveMessage(self, protocol, remoteOID, localOID, *args, **kwargs):
        self.log.debug("%s:%s<-%s:%s %s %s", 
                       self.node.me, localOID,
                       self, remoteOID,
                       args, 
                       kwargs)

        try:
            service = self.node.getServiceNamed(localOID)
        except KeyError:
            self.log.warning("%s:%s<-%s:%s no such service", 
                             self.node.me, localOID,
                             self, remoteOID)
            raise
        else:
            service.receiveMessage(self, remoteOID, *args, **kwargs)
                
    def clientConnectionFailed(self, connector, reason):
        #self.log.debug("clientConnectionFailed")

        if self.continueTrying:
            self.connector = connector
            self.retry()
                
    def clientConnectionLost(self, connector, reason):
        #self.log.debug("clientConnectionLost %s", reason)

        if self.continueTrying:
            self.connector = connector
            self.retry()

    def clientConnectionMade(self, protocol):
        self.log.debug("%s clientConnectionMade %s", self.node.me.address, self.address)
        self._connections.add(protocol)
        
        while self._pendingActivation:
            d = self._pendingActivation.pop()
            d.callback(self)                    
        
    def isActive(self):
        return self._active
                
    def activate(self):
        """Start connecting to this peer."""

        if self.isActive():
            #assert self._connections
            assert self.continueTrying
            #assert self._callID
            self.log.debug("%s activate %s (multiple)", self.node.me.address, self.address)
            return defer.succeed(self)
        else:
            self.log.info("%s activate %s", self.node.me.address, self.address)

        assert not self._connections
        assert not self.continueTrying
        assert not self._callID

        self._active = True
        self.continueTrying = 1
        
        if self.connector:
            self.retry()
        else:
            self.connect()

        d = defer.Deferred()
        self._pendingActivation.add(d)
        return d
                
    def deactivate(self, reason=None):
        """Deactivate a connection to this peer."""
        
        if not self.isActive(): 
            #self.log.debug("%s deactivate %s (multiple).", self.node.getMe().address, self.address)
            #assert not self._connections
            return
        else:
            self.log.debug("%s deactivate %s", self.node.me.address, self.address)
            
        self._active = False
        
        try:
            self.stopTrying()
        except twisted.internet.error.NotConnectingError:
            pass
        
        while self._connections:
            x = self._connections.pop()
            x.transport.loseConnection()

        while self._pendingActivation:
            d = self._pendingActivation.pop()
            d.errback()        
    
    def isConnected(self):
        return bool(self._connections) 
    
    @property
    def identity(self):
        return self.certificate.identity()

    @property
    def address(self):
        host, port = self.certificate.get_subject().CN.split(":")
        return twisted.internet.address.IPv4Address("TCP", host, int(port))        
           
    def connect(self):
        self.log.debug("connect")
        adr = self.address
        return connect(adr.host, adr.port, self, self.node)
    
    def isAllowedConnectionFrom(self):
        return self._allowConnectionFrom   
    
    def allowConnectionFrom(self):
        self._allowConnectionFrom = True

    def denyConnectionFrom(self):
        self._allowConnectionFrom = False

    def isAllowedConnectionTo(self):
        return self._allowConnectionTo   
    
    def allowConnectionTo(self):
        self._allowConnectionTo = True

    def denyConnectionTo(self):
        self._allowConnectionTo = False
        
    def __str__(self):
        return str(self.address)
        



