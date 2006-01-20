# -*- coding: iso-8859-1 -*-
######################################################################
## Filename:      gossip.py
## Description:   Fireflies timestamp based gossip protocol 
## Author:        Håvard Dagenborg Johansen <haavardj@cs.uit.no>
## Modified at:   Mon Jan 16 18:32:42 2006
## Modified by:   Håvard Dagenborg Johansen <haavardj@cs.uit.no>
## Licence:       GPL (see the LICENSE file).
##  
##         Copyright© 2006, University of Tromsø (Norway)
##                
## $Id: gossip.py,v 1.1 2006/01/20 12:41:27 haavardj Exp $
##                
######################################################################


import logging
#from fireflies.packer import loads, dumps
from packer import FirefliesPacker, FirefliesUnpacker

from twisted.internet.protocol import Factory, Protocol, ClientFactory, ServerFactory
from twisted.protocols.basic import Int32StringReceiver
from twisted.internet import reactor, task, defer
from Crypto.Hash import MD5
import fireflies, members, time, cert
from cert import TimestampMixin
import copy


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


DUBLICATEPARTNERS = True

class Gossip:
    def __init__(self, peer, rate=60.0, TCPTimeout=360.0):
        self.rate = rate
        self.peer = peer
        self.view = peer.view
        if not peer.view: raise Exception, "Peer not in view"
        self.logger = logging.getLogger(peer.cert.address)
        self.sFactory = GossipServerFactory(peer, TCPTimeout)
        self.cFactory = GossipClientFactory(peer, rate, TCPTimeout)    

    def start(self):
        host, port = self.peer.cert.address.split(":")
        port = int(port)
        self.logger.info("Binding gossip to tcp %s:%d", host, port)
        self._port = reactor.listenTCP(port, self.sFactory, interface=host)
        self.sFactory.doStart()
        self.cFactory.doStart()

        def _d():            
            self._task = task.LoopingCall(self.cFactory.update)
            self._task.start(self.rate/len(self.peer.view.gRings) ).addErrback(self._failback)
        reactor.callLater(0.1, _d)

    def stop(self):
        self._task.stop()
        self._port.stopListening()
        self.sFactory.doStop()
        self.cFactory.doStop()

    def _failback(self, reason):
        self.logger.exception(reason)

class GossipBase(Int32StringReceiver):
    STATE_IDLE = "idle"
    STATE_CONNECTING = "conn"
    STATE_HOLDING = "hold"
    STATE_GOSSIPING = "gossip"
    STATE_TERMINATED = "term"
    MAX_LENGTH = 100000000

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
            if not peer.note: continue
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
            if peer.hasAccusations():
                r = peer.pAccusations.keys()
                r.sort()
                for nr in r:
                    accus = peer.pAccusations[nr]
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
        if self.state == self.STATE_TERMINATED:
            self.logger.warning("traffic after hangup.")
            return

        self.factory.peer.view.stats.tcpR += len(recd)
        return Int32StringReceiver.dataReceived(self, recd)

    def sendString(self, data):
        if self.state == self.STATE_TERMINATED:
            self.logger.warning("traffic after hangup.")
            return
        
        self.factory.peer.view.stats.tcpW += (len(data) + 4)
        return Int32StringReceiver.sendString(self, data)

    def sendCommand(self, cmd, *args):
        try:
            p = FirefliesPacker()

            p.pack_fstring(1, chr(cmd2code[cmd]))

            if cmd == "partner":
                nr, = args
                p.pack_uint(nr)
            elif cmd == "hashes":
                ch, nh, ah = args
                p.pack_serial(ch)
                p.pack_serial(nh)
                p.pack_serial(ah)
            elif cmd == "match":
                pass
            elif cmd == "accepted":
                pass
            elif cmd == "gossip":
                ch, nh, ah, crts, notes, accs = args
                
                p.pack_serial(ch)
                p.pack_serial(nh)
                p.pack_serial(ah)

                assert type(crts) == list
                p.pack_uint(len(crts))
                for x in crts:
                    p.pack_cert(x)

                assert type(notes) == list
                p.pack_uint(len(notes))
                for x in notes:
                    p.pack_note(x)

                assert type(accs) == list
                p.pack_uint(len(accs))
                for x in accs:
                    p.pack_accusation(x)

            elif cmd == "authenticate":
                crt, note = args
                p.pack_cert(crt)
                p.pack_note(note)

            elif cmd == "redirect":
                crt, note = args
                p.pack_cert(crt)
                p.pack_note(note)
            else:
                raise Exception, "Unknown command"

            self.sendString(p.get_buffer())

        except KeyboardInterrupt:
            raise
        except Exception, why:
            self.logger.exception("Unable to send command %s. %s", cmd, why)
            
    def stringReceived(self, data):
        try:
            cmd = "N/A"
            p = FirefliesUnpacker(data)
            cmd = code2cmd[ord(p.unpack_fstring(1))]
            args = ()
            if cmd == "partner":
                args = (p.unpack_uint(),)
            elif cmd == "hashes":
                args = (
                    p.unpack_serial(),
                    p.unpack_serial(),
                    p.unpack_serial())
            elif cmd == "match":
                args = ()
            elif cmd == "gossip":
                ch = p.unpack_serial()
                nh = p.unpack_serial()
                ah = p.unpack_serial()

                crts = []
                num = p.unpack_uint()
                for x in range(num):
                    crts.append(p.unpack_cert())

                notes = []
                num = p.unpack_uint()
                for x in range(num):
                    notes.append(p.unpack_note())

                accs = []
                num = p.unpack_uint()
                for x in range(num):
                    accs.append(p.unpack_accusation())
                args = (ch, nh, ah, crts, notes, accs)

            elif cmd == "authenticate":
                args = (p.unpack_cert(), p.unpack_note())

            elif cmd == "redirect":
                args = (p.unpack_cert(), p.unpack_note())
                
            elif cmd == "accepted":
                args = ()                
            else:
                raise Exception, "unknown command."

            p.done()
            #cmd, args = loads(msg)
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
        else:
            self._stop = True
        self.logger.debug("hangup %s", self)

    def timeout(self):
        self._timer = None
        self.logger.error("timeout %s", self)
        self.hangup()

    def __repr__(self):
        if self.peer:
            return "%s,%s" % (self.peer.view.pprint(self.peer.note), self.state) 
        elif self.transport:
            addr = self.transport.getPeer()
            return "%s:%d,%s" % (addr.host, addr.port, self.state)
        else:
            return "-:-(%s)" % (self.state)

    def setTimeout(self):
        if self._timer and self._timer.active():
            raise Exception, "Timer already set."
        self._timer = reactor.callLater(self.factory._timeout, self.timeout)

    def cancelTimeout(self):
        assert self._timer and self._timer.active()        
        self._timer.cancel()
        self._timer = None




class ServerFloodingProtocol(GossipBase):

    def __init__(self):
        self.peer = None
        self.ringNr = None
        self.state = self.STATE_CONNECTING
        self._stop = False
        self._timer = None
        self.timestamp = 0

        self.nq = []
        self.cq = []
        self.aq = []

    def sendCrt(self, crt):
        self.cq.append(crt)
    def sendNote(self, note):
        self.nq.append(note)
    def sendAccusation(self, accus):
        self.aq.append(accus)
    
    def connectionMade(self):
        pass

    def connectionLost(self, reason):
        self.logger.warning("connetion lost %s, %s", self, reason)
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
            self.sendCommand("authenticate", copy.copy(self.factory.peer.cert), copy.copy(self.factory.peer.note))

    def redirect(self, peer):
        self.factory.peer.view.stats.redirect += 1
        self.logger.debug("redirect-> %s to %s", self, pprint(peer.cert))
        self.setTimeout()
        self.sendCommand("redirect", copy.copy(peer.cert), copy.copy(peer.note))

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
        
    def handle_note(self, note):
        self.factory.addNotes(note)
    
    def handle_cert(self, cert):
        self.factory.addCert(cert)
    
    def handle_accus(self, accus):
        self.factory.addAccus(accus)




class ServerProtocol(GossipBase):

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
            self.sendCommand("authenticate", copy.copy(self.factory.peer.cert), copy.copy(self.factory.peer.note))

    def redirect(self, peer):
        pprint = self.factory.peer.view.pprint
        self.logger.debug("redirect-> %s to %s", self, pprint(peer.cert))
        self.setTimeout()
        self.sendCommand("redirect", copy.copy(peer.cert), copy.copy(peer.note))

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
        self.logger.debug("hashes<- %s", self)
        self.state = self.STATE_GOSSIPING        
        view = self.factory.peer.view

        self.updateBuckets()

        if (self.certHash == ch and
            self.noteHash == nh and
            self.accHash == ah):
            
            self.timestamp = self.bucketTS
            self.sendCommand("match")
            self.state = self.STATE_IDLE
            #self.factory.gossipCompleted()
        else:
            self.logger.debug("gossip-> %s c=%d n=%d a=%d",
                             self,
                             len(self.certBucket),
                             len(self.noteBucket),
                             len(self.accBucket))
            self.setTimeout()

            if self.factory.peer.note.badness == 2:
                #nb = filter(lambda x: (x.serial == self.peer.id) or (not view.sn2peer[x.serial].isAccused()), self.noteBucket)                                
                nb = filter(lambda x: x.serial == self.factory.peer.id, self.noteBucket)
                self.sendCommand("gossip",
                                 self.certHash,
                                 self.noteHash,
                                 self.accHash,
                                 map(lambda x: copy.copy(x), self.certBucket),
                                 map(lambda x: copy.copy(x), nb),
                                 map(lambda x: copy.copy(x), self.accBucket))
            elif self.factory.peer.note.badness == 1:
                self.sendCommand("gossip",
                                 self.certHash,
                                 self.noteHash,
                                 self.accHash,
                                 map(lambda x: copy.copy(x), self.certBucket),
                                 map(lambda x: copy.copy(x), self.noteBucket),
                                 [])                
            else:
                self.sendCommand("gossip",
                                 self.certHash,
                                 self.noteHash,
                                 self.accHash,
                                 map(lambda x: copy.copy(x), self.certBucket),
                                 map(lambda x: copy.copy(x), self.noteBucket),
                                 map(lambda x: copy.copy(x), self.accBucket))

    def handle_match(self):
        self.cancelTimeout()
        if self.state != self.STATE_GOSSIPING:
            self.logger.error("error %s protocol", self)
            self.hangup(True)
        self.logger.debug("match<- %s", self)
        self.timestamp = self.bucketTS
        #self.factory.gossipCompleted()
        self.state = self.STATE_IDLE

    def handle_gossip(self, ch, nh, ah, crts, notes, accusations):
        self.cancelTimeout()
        self.logger.info("gossip<- %s c=%d n=%d a=%d", self, len(crts), len(notes), len(accusations))
        view = self.factory.peer.view

        view.addCerts(crts)
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


        
class ClientProtocol(GossipBase):

    def __init__(self, peer, ringNr):
        self.peer = peer
        self.ringNr = ringNr
        self.state = self.STATE_CONNECTING
        self._timer = None
        self.timestamp = 0
        self._d = None
        
    def connectionMade(self):
        self.factory.peer.view.stats.tcpOpen += 1
        crt, note = self.factory.getCredentials()
        self._sendAuthenticate(crt, note)

    def connectionLost(self, reason):
        addr = self.transport.getPeer()
        if self._timer: self.cancelTimeout()
        self.state = self.STATE_TERMINATED
                        
    def _sendAuthenticate(self, crt, note):
        pprint = self.factory.peer.view.pprint
        self.logger.debug("authenticate-> %s %s-%s ", self, pprint(crt),pprint(note))
        self.setTimeout()
        self.sendCommand("authenticate", copy.copy(crt), copy.copy(note))
        
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
        self.logger.debug("hashes-> %s", self)
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
        self.logger.debug("match<- %s", self)
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

        if (self.certHash == ch and
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

            if self.factory.peer.note.badness == 2:
                #nb = filter(lambda x: (x.serial == self.peer.id) or (not view.sn2peer[x.serial].isAccused()), self.noteBucket)
                nb = filter(lambda x: x.serial == self.factory.peer.id, self.noteBucket)
                self.sendCommand("gossip",
                                 self.certHash,
                                 self.noteHash,
                                 self.accHash,
                                 map(lambda x: copy.copy(x), self.certBucket),
                                 map(lambda x: copy.copy(x), nb),
                                 map(lambda x: copy.copy(x), self.accBucket))
            elif self.factory.peer.note.badness == 1:
                self.sendCommand("gossip",
                                 self.certHash,
                                 self.noteHash,
                                 self.accHash,
                                 map(lambda x: copy.copy(x), self.certBucket),
                                 map(lambda x: copy.copy(x), self.noteBucket),
                                 [])
            else:
                self.sendCommand("gossip",
                                 self.certHash,
                                 self.noteHash,
                                 self.accHash,
                                 map(lambda x: copy.copy(x), self.certBucket),
                                 map(lambda x: copy.copy(x), self.noteBucket),
                                 map(lambda x: copy.copy(x), self.accBucket))


class GossipServerFactory(ServerFactory):

    protocol = ServerProtocol

    def __init__(self, peer, timeout):
        self._timeout = timeout
        if not peer.view: raise Exception, "Peer not in view"
        self.peer = peer
        self.view = peer.view        
        self.logger = logging.getLogger(peer.cert.address)
        self.cons = [None] * self.view.cacert.config["NUM_GOSSIPRINGS"]

    def startFactory(self):
        pass

    def stopFactory(self):
        for c in self.cons:
            if not c: continue
            c.hangup()
        self.cons = [None] * self.peer.view.cacert.config["NUM_GOSSIPRINGS"]

    def clientConnected(self, protocol, rnr):
        """Client connected."""

        me = self.peer
        him = protocol.peer
        hisPartner = self.view.gRings[rnr].succ(him)
        while hisPartner.isFailed():
            hisPartner = self.view.gRings[rnr].succ(hisPartner)

        cp = self.cons[rnr]
        if hisPartner.id != me.id:
            # The connecting client is not my partner, we therefore
            # redirect him to whom he should talk to.
            protocol.redirect(hisPartner)
            #protocol.hangup()
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
                    #protocol.hangup()

    def buildProtocol(self, address):
        p = ServerFactory.buildProtocol(self, address)
        p.logger = self.logger
        return p

    
class GossipClientFactory(ClientFactory):

    def __init__(self, peer, roundtime, timeout=420):
        self._timeout = timeout
        self._roundtime = roundtime
        
        self.peer = peer
        self.view = peer.view
        if not peer.view: raise Exception, "Peer not in view"
        
        self.connections = [None] * len(peer.view.gRings)
        self._initializing= {}        

        self.logger = logging.getLogger(peer.cert.address)
        self._last = -1 % len(peer.view.gRings)
        self._task = None

    def startFactory(self):
        if self._task: return

    def stopFactory(self):

        for c in self.connections:
            if not c: continue
            c.hangup()

        for n,v in self._initializing.items():
            v.hangup()
            
        self.connections = [None] *len(self.view.gRings)
        self._initializing = {}

    def _failback(self, msg):
        self.logger.exception("Gossip outgoing failed %s", str(msg))
        
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
        x = self._last = (self._last + 1) % len(self.view.gRings)
        
        # Purge initializing protocols that terminated.
        for k,v in self._initializing.items():
            if v.state == v.STATE_TERMINATED:
                del self._initializing[k]

        cg = self.connections[x]

        ring = self.view.gRings[x]
        partnerOnX = ring.succ(self.peer)
        while partnerOnX.isFailed():
            partnerOnX = ring.succ(partnerOnX)
            if partnerOnX.id == self.peer.id:
                break

        if partnerOnX.serial == self.peer.serial:
            # No other peers in ring. Leave things as they are.
            pass
        else:
            if (not cg) or (cg.state == cg.STATE_TERMINATED):
                # We do not have an active connection on this ring, so
                # make one.
                ids = map(lambda t: t.peer.id, filter(None, self.connections[0:x]))
                if (DUBLICATEPARTNERS) or (parntersOnX.id not in ids):
                    if not partnerOnX.cert.address in self._initializing:
                        self.connect(partnerOnX, x)
                else:
                    self.connections[x] = None
            else:
                # We have an active connection on the current ring. We
                # can either close the current one and connect to a
                # new member, or keep the current connection.

                if partnerOnX != cg.peer:
                    cg.hangup()
                    if not partnerOnX.cert.address in self._initializing:
                        self.connect(partnerOnX, x)
                elif cg.state == cg.STATE_IDLE:
                    cg.gossip()
                else:
                    pass

        

