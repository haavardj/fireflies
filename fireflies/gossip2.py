import logging
from twisted.internet.protocol import Factory, Protocol, ClientFactory, ServerFactory
from twisted.protocols.basic import Int32StringReceiver
from twisted.internet import reactor, task, defer
from Crypto.Hash import MD5
import fireflies, members, time, cert
import fireflies.globals as g

from cert import TimestampMixin

_hashcache = {}

class GossipRing(fireflies.members.Ring):
    """A Fireflies gossip ring. The item's gRingID function is used
    for generating sort keys. This class also needs to be instantiated
    with the number of the gossip ring.
    """
    
    def __init__(self, nr):
        """nr - The monitor-ring number."""
        self.nr = nr
        super(GossipRing, self).__init__()
    def _sortKey(self, peer):
        try:
            return _hashcache[peer.id][self.nr]
        except KeyError:
            ids = []
            for x in range(g.NUMGOSSIPRINGS):
                ids.append(long(MD5.new("%d-g-%d" % (peer.id, self.nr)).hexdigest(), 16) % g.IDSPACE)
            _hashcache[peer.id] = ids
        return _hashcache[peer.id][self.nr] 


class Gossip:
    def __init__(self, peer):
        self.peer = peer
        self.view = peer.view
        if not peer.view: raise Exception, "Peer not in view"
        self.logger = logging.getLogger(peer.cert.address)
        
        self.rings = []

        for x in range(g.NUMGOSSIPRINGS):
            self.rings.append(GossipRing(x))

        for peer in self.view.pRing:
            for ring in self.rings:
                ring.insert(peer)

        self.sFactory = GossipServerFactory(peer)
        self.cFactory = GossipClientFactory(peer)
        self.view.registerListener(self)
                        
    def handle_join(self, peer):
        for ring in self.rings:
            ring.insert(peer)

    def handle_leave(self, peer):
        for ring in self.rings:
            ring.remove(peer)

    def handle_note(self, note):
        self.sFactory.sendNote(note)
        self.cFactory.sendNote(note)

    def handle_accusation(self, accusation):
        self.sFactory.sendAccusation(accusation)
        self.cFactory.sendAccusation(accusation)

    def handle_cert(self, cert):
        self.sFactory.sendCert(cert)
        self.cFactory.sendCert(cert)

    def start(self):
        host, port = self.peer.cert.address.split(":")
        port = int(port)
        self.logger.info("Binding gossip to tcp %s:%d", host, port)
        reactor.listenTCP(port, self.sFactory, interface=host)
        self.cFactory.doStart()

    def stop(self):
        self.cFactory.doStop()
        self.sFactory.doStop()




class XDRMessagingProtocol(Int32StringReceiver):

    def stringReceived(self, data):
        self.XDRReceived(data)

    def XDRReceived(self, data):
        pass

    def sendXDR(self, packer):
        self.sendString(packer.get_buffer())
        


cmd2code = {
    'partner': 0x1,
    'hashes': 0x2,
    'match': 0x3,
    'accepted': 0x4,
    'gossip': 0x5,
    'authenticate': 0x6,
    'redirect': 0x7,
    'note': 0x8,
    'accusation': 0x9,
    'certificate': 0x10
    }

code2cmd = {}
for k, v in cmd2code.items():
    code2cmd[v] = k


class FirefliesGossipMessaging(XDRMessagingProtocol):
        
    def XDRReceived(self, data):
        pass
    def sendAuthenticate(self):
        pass

    def sendAuthenticateReply(self):
        pass
    def sendRedirect(self):
        pass
    def sendPartner(self):
        pass
    

class FirefliesServer:
    pass

class FirefliesClient:

    # Connection handlers
    def connectionMade(self):
        if self.isClient():

            mycert = self.getCert()
            self.sendAuthenticate()

    def connectionLost(self, reason):
        pass

    def authenticate(self):
        pass
            
    def sendAuthenticate(self):pass
    def sendAuthenticateReply(self):pass
    

    def isClient(self):
        raise NotImplementedError

class GossipMessagingProtocol(XDRMessagingProtocol):


    def __init__(self):
        self._state = "init"
        self._deffered = None
        self.partner = None


    # Unpacks received message and dispatch it to correct state
    # handler.
    def xdrReceived(self, unpacker):
        tpe = unpacker.unpack_uint()
        msg = None

        getattr(self, "state_" + self._state)(msg)
    
    def sendGossipMessage(self, msg):
        pass

    # State handlers
    def state_init(self, msg):       
        if type(msg) != AuthMsg:
            raise
        req = self.request
        if not req: raise
                    
    def state_authenticated(self, msg):
        pass

    def state_idle(self, msg):
        pass

    def state_gossip(self, msg):
        pass

    # Commands
    def authenticate(self, mycrt, priv):
        """Authenticate myself as crt.

        Returns - Deffered that will trigger when
        authenticated.
        """
        d = deffer.Deffered()
        
        def reply(msg2):
            if not msg2.verify(msg2.cert):
                raise
            if not msg2.noun == msg.noun:
                raise
            return d.callback(msg2.cert)
        
        msg = AuthMsg(crt)
        msg.sign(priv)        
        r = self.sendCommand(msg)
        r.addCallback(reply)        
        return d
    
    def redirect(self, crt, note):
        msg = RedirectMsg(crt, note)
        self.sendMsg(msg)

    
    # Requires reply
    def sendRequest(msg):
        pass

    def sendMsg(msg):
        pass


    def dataReceived(self, recd):
        fireflies.stats.tcpR += len(recd)
        return Int32StringReceiver.dataReceived(self, recd)


    















    def __init__(self):
        self.peer = None
        self.ringNr = None
        self.state = self.STATE_CONNECTING
        self._stop = False
        self._timer = None
        self.timestamp = 0
            
    def connectionMade(self):
        pass

    def connectionLost(self, reason):
        try:
            self.cancelTimeout()
        except KeyboardInterrupt:
            raise
        except:
            pass
        self.state = self.STATE_TERMINATED

    def handle_authenticate(self, crt, note):
        view = self.factory.peer.view
        pprint = view.pprint

        if note.serial != crt.serial:
            self.logger.warning("authenticate<- %s Error. Note and crt serial do not match.", self)
            self.hangup()
        else:
            self.logger.debug("authenticate<- %s %s", self, pprint(crt))
            view.addCerts(crt)
            view.addNotes(note)
            self.peer = view.sn2peer[note.serial]
            self.setTimeout()
            self.sendCommand("authenticate", self.factory.peer.cert, self.factory.peer.note)

    def redirect(self, peer):
        pprint = self.factory.peer.view.pprint
        self.logger.debug("redirect-> %s to %s", self, pprint(peer.cert))
        self.setTimeout()
        self.sendCommand("redirect", peer.cert, peer.note)

    def accept(self):
        self.logger.debug("accepted-> %s", self)
        self.sendCommand("accepted")
        
    def handle_partner(self, ringNr):
        self.cancelTimeout()
        view = self.factory.peer.view
        pprint = view.pprint
        self.logger.debug("partner<- %s on %d", self, ringNr)
        self.ringNr = ringNr
        reactor.callLater(0, self.factory.clientConnected, self, ringNr)
        
    def handle_hashes(self, ch, nh, ah):
        if self.state == self.STATE_GOSSIPING:
            self.logger.error("error %s double gossiping", self)
            self.hangup(True)
            return
        #self.logger.debug("hashes<- %s", self)
        self.state = self.STATE_GOSSIPING        
        view = self.factory.peer.view

        self.updateBuckets()
        
        if False and (self.certHash == ch and
                      self.noteHash == nh and
                      self.accHash == ah):
            
            self.timestamp = self.bucketTS
            self.sendCommand("match")
            self.state = self.STATE_IDLE
            #self.factory.gossipCompleted()
        else:            
            self.logger.debug("gossip-> %s c=%d n=%d a=%d", self,
                              len(self.certBucket),
                              len(self.noteBucket),
                              len(self.accBucket))
            self.setTimeout()
            self.sendCommand("gossip",
                             self.certHash, self.noteHash, self.accHash,
                             self.certBucket, self.noteBucket, self.accBucket)

    def handle_match(self):
        self.cancelTimeout()
        if self.state != self.STATE_GOSSIPING:
            self.logger.error("error %s protocol", self)
            self.hangup(True)
        #self.logger.debug("match<- %s", self)
        self.timestamp = self.bucketTS
        #self.factory.gossipCompleted()
        self.state = self.STATE_IDLE

    def handle_gossip(self, ch, nh, ah, certs, notes, accusations):
        self.cancelTimeout()
        self.logger.debug("gossip<- %s c=%d n=%d a=%d", self, len(certs), len(notes), len(accusations))
        view = self.factory.peer.view

        view.addCerts(certs)
        view.addNotes(notes, True)
        view.addAccusations(accusations, True)
        view.checkAccusations()
        self.timestamp = self.bucketTS
        self.updateBuckets()
        if self.certHash != ch:
            self.logger.debug("gossip %s mismatch cert hashes", self)
        if self.noteHash != nh:
            self.logger.debug("gossip %s mismatch note hashes", self)
        if self.accHash != ah:
            self.logger.debug("gossip %s mismatch accusation hashes", self)
        self.sendCommand("match")
        self.state = self.STATE_IDLE
        #self.factory.gossipCompleted()






class GossipBase(Int32StringReceiver):
    STATE_IDLE = "idle"
    STATE_CONNECTING = "conn"
    STATE_HOLDING = "hold"
    STATE_GOSSIPING = "gossip"
    STATE_TERMINATED = "term"
    MAX_LENGTH = 100000000            


    def __init__(self):
        pass
    
    def sendAccusation(self, acc):
        pass

    def sendNote(self, note):
        pass

    def sendCert(self, cert):
        pass


    def updateBuckets(self):
        view = self.factory.peer.view
        self.bucketTS = self.timestamp
        self.certBucket = []
        self.noteBucket = []
        self.accBucket = []

        ch = MD5.new("certhashes")
        nh = MD5.new("notehashes")
        ah = MD5.new("accushashes")

        # Add all new certificates, notes and accusations to the
        # buckets, and compute hashes. The ordering of the pRing makes
        # shure that all members compute the hashes in the same way.        
        for peer in view.pRing:
            ts = peer.note.getTimestamp()
            if ts > self.timestamp:
                self.noteBucket.append(peer.note)
                nh.update(str(peer.note.shash()))
                self.bucketTS = max(self.bucketTS, ts)
            ts = peer.cert.getTimestamp()
            if ts > self.timestamp:
                self.certBucket.append(peer.cert)
                ch.update(str(peer.cert.shash()))
                self.bucketTS = max(self.bucketTS, ts)
            if peer.isAccused():
                for accus in peer.vAccusations:
                    if not accus: continue
                    ts = accus.getTimestamp()
                    if ts > self.timestamp:
                        self.accBucket.append(accus)
                        ah.update(str(accus.shash()))
                        self.bucketTS = max(self.bucketTS, ts)

        # Save hashes
        self.certHash = ch.digest()
        self.noteHash = nh.digest()
        self.accHash = ah.digest()

    def dataReceived(self, recd):
        fireflies.stats.tcpR += len(recd)
        return Int32StringReceiver.dataReceived(self, recd)

    def sendString(self, data):
        fireflies.stats.tcpW += (len(data) + 4)
        return Int32StringReceiver.sendString(self, data)

    def sendCommand(self, cmd, *args):        
        try:
            self.sendString(dumps( (cmd, args) ))
        except KeyboardInterrupt:
            raise
        except Exception, why:
            self.logger.exception("Unable to send command %s. %s", cmd, why)
            
    def stringReceived(self, msg):
            try:
                cmd, args = loads(msg)
                getattr(self, "handle_" + cmd)(*args)
            except KeyboardInterrupt:
                raise
            except Exception, why:
                self.logger.exception("Unable to run command: %s.", why)
                    
    def hangup(self, hard=True):
        if hard or (self.state != self.STATE_GOSSIPING):
            if not self.transport: return
            self.transport.loseConnection()
            self.state = self.STATE_TERMINATED                
        else:
            self._stop = True
        self.logger.debug("hangup %s", self)

    def timeout(self):
        self.logger.info("timeout %s", self)
        self.hangup()

    def __repr__(self):
        if self.peer:
            return "%s,%s" % (self.peer.view.pprint(self.peer.note), self.state) 
        elif self.transport:
            addr = self.transport.getPeer()
            return "%s:%d,%s" % (addr.host, addr.port, self.state)
        else:
            return "-:-(%s)" % (self.state)

    def setTimeout(self, delay=g.GOSSIPTIMEOUT):
        if self._timer and self._timer.active():
            raise Exception, "Timer already set."
        self._timer = reactor.callLater(delay, self.timeout)

    def cancelTimeout(self, delay=g.GOSSIPTIMEOUT):
        assert self._timer and self._timer.active()        
        self._timer.cancel()
        self._timer = None





        
class ClientProtocol(GossipBase):

    def __init__(self, peer, ringNr):
        self.peer = peer
        self.ringNr = ringNr
        self.state = self.STATE_CONNECTING
        self._timer = None
        self.timestamp = 0
        self._d = None
        
    def connectionMade(self):
        fireflies.stats.tcpOpen += 1
        crt, note = self.factory.getCredentials()
        self._sendAuthenticate(crt, note)

    def connectionLost(self, reason):
        addr = self.transport.getPeer()
        if self._timer: self.cancelTimeout()
        self.state = self.STATE_TERMINATED
                        
    def sendAuthenticate(self, ):
        
        
        
        pprint = self.factory.peer.view.pprint
        self.logger.debug("authenticate-> %s %s-%s ", self, pprint(crt),pprint(note))
        self.setTimeout()
        self.sendCommand("authenticate", crt, note)
        
    def handle_authenticate(self, crt, note):
        view = self.factory.peer.view
        pprint = self.factory.peer.view.pprint
        self.cancelTimeout()
        
        if crt.serial != self.peer.id:
            self.logger.warning("authenticate<- %s Error. Expected %s. Got  %s.", self, pprint(self.peer.cert), pprint(crt))
            self.hangup()
            return

        if  note.serial != self.peer.id:
            self.logger.warning("authenticate<- %s Error. Note and crt serial do not match.", self)
            self.hangup()
            return

        self.logger.debug("authenticate<- %s OK", self)
        self.factory.view.addCerts(crt)
        self.factory.view.addNotes(note)        
        self._sendPartner(self.ringNr)
        
    def _sendPartner(self, ringNr):
        self.logger.debug("partner-> %s on %s", self, ringNr)
        self.setTimeout()
        self.sendCommand("partner", ringNr)
        
    def handle_accepted(self):
        self.state = self.STATE_IDLE
        self.cancelTimeout()
        self.logger.debug("accepted<- %s", self)
        reactor.callLater(0, self.factory.serverConnected, self)
        
    def handle_redirect(self, crt, note):
        self.cancelTimeout()
        self.logger.debug("redirect<- %s to %s", self, crt.address)
        self.factory.view.addCerts(crt)
        self.factory.view.addNotes(note)
        self.hangup()

    def __gossip(self):    
        view = self.factory.peer.view
        self.updateBuckets()        
        self.setTimeout()
        #self.logger.debug("hashes-> %s", self)
        self.sendCommand("hashes", self.certHash, self.noteHash, self.accHash)
            
    def gossip(self):
        if self.state == self.STATE_GOSSIPING:
            self.logger.error("error %s double gossiping", self)
            self.hangup()
            return
        self.state = self.STATE_GOSSIPING
        self._d = defer.Deferred()
        reactor.callLater(0, self.__gossip)
        return self._d
        
    def handle_match(self):
        self.cancelTimeout()
        if self.state != self.STATE_GOSSIPING:
            self.logger.error("match<- %s error protocol", self)
            self.hangup()
        #self.logger.debug("match<- %s", self)
        self.timestamp = self.bucketTS
        #self.factory.gossipCompleted()
        self.state = self.STATE_IDLE
        self._d.callback(self)
        
    def handle_gossip(self, ch, nh, ah, crts, notes, accusations):
        self.cancelTimeout()
        view = self.factory.peer.view
        self.logger.debug("gossip<- %s c=%d n=%d a=%d", self, len(crts), len(notes), len(accusations))
        if self.state != self.STATE_GOSSIPING:
            self.logger.error("error %s protocol", self)
            self.hangup()
            return

        view.addCerts(crts)
        view.addNotes(notes, True)
        view.addAccusations(accusations, True)
        view.checkAccusations()
        self.updateBuckets()
        
        if False and (self.certHash == ch and
                      self.noteHash == nh and
                      self.accHash == ah):
            
            #self.logger.debug("match-> %s", self)
            self.timestamp = self.bucketTS
            self.sendCommand("match")
            #self.factory.gossipCompleted()
            self.state = self.STATE_IDLE
            self._d.callback(self)
        else:                
            self.logger.debug("gossip-> %s c=%d n=%d a=%d",
                              self,
                              len(self.certBucket),
                              len(self.noteBucket),
                              len(self.accBucket))
            self.setTimeout()
            self.sendCommand("gossip",
                             self.certHash,
                             self.noteHash,
                             self.accHash,
                             self.certBucket,
                             self.noteBucket,
                             self.accBucket)



class GossipServerFactory(ServerFactory):

    protocol = ServerProtocol

    def __init__(self, service):
        if not service.peer.view: raise Exception, "Peer not in view"
        self.service = service
        self.peer = service.peer
        self.view = self.peer.view
        self.logger = logging.getLogger(service.peer.cert.address)
        self.cons = [None] * g.NUMGOSSIPRINGS

    def sendCert(self, cert):
        pass

    def sendNote(self, note):
        pass

    def sendAccusation(self, accusation):
        pass


    def clientConnected(self, protocol, rnr):
        """Client connected."""

        me = self.peer
        him = protocol.peer
        hisPartner = self.view.gRings[rnr].succ(him)
        cp = self.cons[rnr]

        if hisPartner.id != me.id:
            # The connecting client is not my partner, we therefore
            # redirect him to whom he should talk to.        
            protocol.redirect(hisPartner)
            protocol.hangup()
        else:
            
            # If the connecting client or/and the currently connected
            # client is accused, they both can have us as their
            # correct gossip partner. We keep the one that is closest.

            if (not cp) or (cp.state == cp.STATE_TERMINATED):
                protocol.accept()
                self.cons[rnr] = protocol
            else:                
                if (cp.peer.id == him.id) or self.view.gRings[rnr].between(cp.peer, him, me):
                    cp.hangup()
                    self.cons[rnr] = protocol
                    protocol.accept()
                else:
                    # Our current connected client is closer to the
                    # connecting client than we are.
                    protocol.redirect(cp.peer)
                    protocol.hangup()


    def buildProtocol(self, address):
        p = ServerFactory.buildProtocol(self, address)
        p.logger = self.logger
        return p

    
class GossipClientFactory(ClientFactory):

    def __init__(self, peer):
        self.peer = peer
        self.view = peer.view
        if not peer.view: raise Exception, "Peer not in view"
        
        self.connections = [None] * g.NUMGOSSIPRINGS
        self._initializing= {}        

        self.logger = logging.getLogger(peer.cert.address)
        self._last = -1 % g.NUMGOSSIPRINGS
        self._task = None
        #ClientFactory.__init__(self)

    def startFactory(self):
        if self._task: return
        self._task = task.LoopingCall(self.update)
        self._task.start(g.GOSSIPROUNDTIME/g.NUMGOSSIPRINGS)

    def stopFactory(self):
        self._task.stop()
        
    def clientConnectionFailed(self, connector, reason):
        address = connector.getDestination()
        id = "%s:%d" % (address.host, address.port)
        try:
            p = self._initializing[id]
            del self._initializing[id]
            p.state = p.STATE_TERMINATED
        except KeyboardInterrupt:
            raise Exception, "Lost"
        except KeyError:
            pass
        
    #def clientConnectionLost(self, connector, reason):
    #def startedConnecting(self, connector):
        
    def getCredentials(self):
        return (self.peer.cert, self.peer.note)
        
    def connect(self, peer, ringNr):
        if peer.cert.address in self._initializing:
            raise Exception, "Allready connecting to this guy"
        
        host, port = peer.cert.address.split(":")
        port = int(port)
        prot = ClientProtocol(peer, ringNr)
        prot.logger = self.logger
        self._initializing[peer.cert.address] = prot
        
        cc = self.connections[ringNr]
        if cc and cc.state != cc.STATE_TERMINATED:
            cc.hangup()
        self.connections[ringNr] = prot
        
        reactor.connectTCP(host, port, self)

    def serverConnected(self, protocol):
        protocol.gossip()

    def buildProtocol(self, address):
        id = "%s:%d" % (address.host, address.port) 
        p = self._initializing[id]
        del self._initializing[id]
        p.factory = self
        p.logger = self.logger
        return p

                
    def update(self):

        x = self._last = (self._last + 1) % g.NUMGOSSIPRINGS
        
        # Purge initializing protocols that terminated.
        for k,v in self._initializing.items():
            if v.state == v.STATE_TERMINATED:
                del self._initializing[k]

        cg = self.connections[x]            
        if (not cg) or cg.state == cg.STATE_TERMINATED:
            #We do not hava a partner on this ring.            
            partnerOnX = self.view.gRings[x].succ(self.peer)            
            if partnerOnX.id == self.peer.id:
                #self.gossipCompleted()
                return

            # A peer can be our partner on multiple
            # rings. Nevertheless, we only want to connect to him
            # once.
            dub = False
            for conn in self.connections:
                if not conn: continue
                if conn.state == conn.STATE_TERMINATED: continue
                if conn.peer.id != partnerOnX.id: continue
                dub = True
                break                
            if not dub:
                    self.connect(partnerOnX, x)
                    #self.gossipCompleted()
                    
        elif cg and cg.state == cg.STATE_IDLE:
            # We have a partner on this ring, so just gossip.            
            cg.gossip()
            #self.gossipCompleted()
        else:
            # We can not gossip with this partner at this moment. 
            pass
        








