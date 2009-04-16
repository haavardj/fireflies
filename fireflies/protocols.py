
#import fireflies.group, fireflies.members

import twisted
from twisted.spread import pb 
from twisted.internet import reactor, task, defer, protocol
from twisted.protocols.basic import Int32StringReceiver
from twisted.protocols.policies import ProtocolWrapper, WrappingFactory
from twisted.application import service
import logging, random, os, tempfile
import M2Crypto
import M2Crypto
import M2Crypto.SSL.TwistedProtocolWrapper as wrapper
from twisted.protocols import policies
import struct
from M2Crypto.SSL.Checker import WrongHost, WrongCertificate, NoCertificate 
from M2Crypto import m2
from zope.interface import implements, Interface, Attribute

from fireflies import state, crypto, ring, view
import xdrlib

from twisted.conch import client

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
        


class UDPNetwork(service.MultiService):
    
    name = "UDP"
    
    def __init__(self, group):
        super(UDPNetwork, self).__init__()
        self.group = group
        
    def startService(self):
        super(UDPNetwork, self).startService()   
        me = self.getRootService().me
        self.log.info("Binding to UDP:%s", me.address)
        
        self.protocol = UnsecuredDatagramProtocol()
        self.protocol.factory = self
        self._port = reactor.listenUDP(me.address.port, self.protocol, interface=me.address.host)        
        
    def stopService(self):
        super(FailureDetector, self).stopService()
        self._port.stopListening()

    def send(self, member, *args, **kwargs):
        self.protocol.sendMessage(member, *args, **kwargs)
        
    def receive(self, protocol, member, *args, **kwargs):
        pass

class Network(service.MultiService):

    log = logging.getLogger("Network")
    name = "TCP"
    
    def __init__(self, group):
        super(Network, self).__init__()
        self._pool = {}
        self.group = group
        
    def startService(self):
   
        for m in group.members:
            self._pool[m] = Peer(m.certificate)
            
        addr = self.group.me.address
        self._port = listen(addr.port,
                            FirefliesServerFactory(self),
                            self.sslCtx,
                            interface=addr.host,
                            postConnectionCheck=sslPostConnectionCheck)
        super(Network, self).startService()
        self.log.debug("listen %s", addr)
        return self._port
        
    def stopService(self):
        d = super(Network, self).stopService()
        d = TypedChannel.stopService(self)
        d.addCallback(lambda x: self._port.stopListening())
        
        def deactivateClients():
            for x in self.members:
                x.deactivate()

        d.addCallback(lambda x: deactivateClients())
        return d    
    
    def send(self, member, *args, **kwargs):        
        pass
    
    def receive(self, protocol, member, *args, **kwargs):
        pass
    
    
    
        
class FirefliesServerFactory(protocol.ServerFactory):

    unsafeTracebacks = 1
    protocol = SSLAuthenticatedProtocol

    def __init__(self, node, unsafeTracebacks=False):
        self.node = node 
        self.unsafeTracebacks = unsafeTracebacks

    def buildProtocol(self, addr):
        proto = self.protocol()
        proto.factory = self
        return proto

    def clientConnectionMade(self, proto):
        m = self.node.addCertificate(proto.x509)
        proto.factory = m
        return m.clientConnectionMade(proto)

    
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
        



