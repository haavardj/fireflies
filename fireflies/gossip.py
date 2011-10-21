######################################################################
## Filename:      gossip.py
## Description:   Fireflies set-recon based gossip protocol 
## Author:        Haavard Dagenborg Johansen <haavardj@cs.uit.no>
## Modified at:   Wed Feb  1 18:12:09 2006
## Modified by:   Haavard Dagenborg Johansen <haavardj@cs.uit.no>
## Licence:       GPL (see the LICENSE file).
##  
##         Copyright 2006, Haavard D Johansen (Norway)
##                
## $Id: gossip.py,v 1.30 2011/10/21 08:25:22 haavardj Exp $
##                
######################################################################

import logging
from twisted.internet.protocol import Factory, Protocol, ClientFactory, ServerFactory
from twisted.protocols.basic import Int32StringReceiver
from twisted.internet import reactor, task, defer
import sha
import copy, sys
import M2Crypto

from twisted.application.service import Service
import fireflies
from fireflies.packer import FirefliesPacker, FirefliesUnpacker
from fireflies import setrecon, ring
from fireflies.state import Note, Accusation, Member
from fireflies.crypto import identityFromCertificate
from fireflies.persist import Store
from M2Crypto.SSL.Checker import WrongHost, WrongCertificate, NoCertificate 
from fireflies.protocols import ClientConnectionChecker
from zope.interface import implements


PARTITION_FACTOR = 3
RECON_EXTRA = 5
MBAR=10
BITSIZE=160

setrecon.init(BITSIZE, MBAR)

NODE_STATUS_EMPTY = 0
NODE_STATUS_TERMINAL = 1
NODE_STATUS_NONTERMINAL = 2


DUBLICATEPARTNERS = False


class NoteSet(setrecon.ReconSet):
    
    def elmToZZp(self, elm):
        if not isinstance(elm, Note): raise ValueError
        return setrecon.to_ZZ_p(setrecon.to_ZZFromBytes(elm.get_fingerprint()))

class AccusationSet(setrecon.ReconSet):
    def elmToZZp(self, elm):
        if not isinstance(elm, Accusation): raise ValueError
        return setrecon.to_ZZ_p(setrecon.to_ZZFromBytes(elm.get_fingerprint()))

class X509Set(setrecon.ReconSet):
    def elmToZZp(self, elm):
        if not isinstance(elm, M2Crypto.X509.X509): raise ValueError
        return setrecon.to_ZZ_p(setrecon.to_ZZFromBytes(elm.get_fingerprint()))    

def sslPostConnectionCheck(peerX509, expectedHost):
    print peerX509, expectedHost
    return True

def sslVerifyCB(sslCTX_ptr, x509_ptr, a,b,c):
    x509 = M2Crypto.X509.X509(x509_ptr, 0)
    print x509.as_text()
    return True
        
class ReconciliationPeer(fireflies.protocols.ReconnectingPeerFactory):
    
    maxDataHistorySize = 1000

    def __init__(self, service):
        fireflies.protocols.ReconnectingPeerFactory.__init__(self, service)    
        self.dataHistory = []
                   
        
    def getSet(self, name):
        if name == "cSet":
            s = self.service.cSet
            f = self.service.parent.view.addCertificate
        elif name == "nSet":
            s = self.service.nSet
            f = self.service.parent.view.addNote

        elif name == "aSet":
            s = self.service.aSet
            f = self.service.parent.view.addAccusation
        else:
            raise ValueError("No such set.")
        return s, f


class GossipBase(Int32StringReceiver):
    STATE_IDLE = "idle"
    STATE_CONNECTING = "conn"
    STATE_HOLDING = "hold"
    STATE_GOSSIPING = "gossip"
    STATE_TERMINATED = "term"
    MAX_LENGTH = 100000000

    other = None
    state = STATE_CONNECTING
    master = False
    connectionTimeout = fireflies.defaultConfig['tcptimeout']
    
    logger = logging.getLogger()
    
    def __init__(self):
        self.missingHases = set()

    def postConnection(self, x509, host):
        isinstance(x509, M2Crypto.X509.X509)
        service = self.factory.service.parent
        isinstance(service, fireflies.group.Group)        
        service.view.addCertificate(x509)
        peer = service.getView().getMemberByCertificate(x509)
        if self.master and peer != self.other:
            raise WrongCertificate('peer did not authenticate with correct certificate')
        self.other = peer
        
        if self.master:
            reactor.callLater(0, self._sendPartner, self.factory.service.parent.getMe().getNote())
        else:
            self.setTimeout()
                
        return True
    
    def connectionMade(self):
        self.transport.postConnectionCheck = self.postConnection

    def connectionLost(self, reason):
        self.state = self.STATE_TERMINATED
        try:
            if self._timer: self.cancelTimeout()
        except KeyboardInterrupt:
            raise
        except:
            pass
        self.factory.connectionLost(self)

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
        else:
            self._stop = True
        self.logger.debug("hangup %s", self)

    def timedout(self):
        assert self._timer and self._timer.active()           
        self._timer = None
        self.logger.warning("timeout %s", self)
        self.hangup()

    def __repr__(self):
        if self.other:
            return "%s,%s" % (self.factory.service.parent.view.pprint(self.other.getNote()), self.state) 
        elif self.transport:
            addr = self.transport.getPeer()
            return "%s:%d,%s" % (addr.host, addr.port, self.state)
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

    def sendData(self, data):
        assert self.state == self.STATE_IDLE
        self.sendCommand("data", data)
        
    def handle_data(self, data):
        self.logger.debug("data <- %s %s", data, self)
        assert self.state == self.STATE_IDLE
        if isinstance(data, Accusation):
            self.factory.service.group.view.addAccusation(data)
        elif isinstance(data, Note):
            self.factory.service.group.view.addNote(data)
        elif isinstance(data, M2Crypto.X509.X509):
            self.factory.service.group.view.addCertificate(data)

    def reconcile_next(self):
        """Moves to the next partition available partition, or marks
        the reconciliation as done if no more partitions are available.

        Sends
        -- reconciliation_done ()
        -- reconciliation_next_req ()
        """
        assert self.state == self.STATE_GOSSIPING, "state is %s should be %s" % (self.state, self.STATE_GOSSIPING)
        self.logger.debug("reconcile_next %s nodes=%d", self, len(self.nodes))

        if self.nodes == []:
            self.setTimeout()
            self.reqBuff = filter(lambda x:  x not in self.set, self.reqBuff)
            self.logger.debug("reconcile_data_req->%s %d ", self, len(self.reqBuff))
            self.sendCommand("reconcile_data_req", self.reqBuff)
            self.reqBuff = []
        else:
            assert self.state == self.STATE_GOSSIPING, "state is %s should be %s" %(self.state, self.STATE_GOSSIPING)
            if self.curNode: self.curNode.unref()
            self.curNode = self.nodes.pop(0)

            if isEmptyNode(self.curNode):
                nt = NODE_STATUS_EMPTY
                hv = None
                ev = None
                ss = 0
            elif self.curNode.isTerminal():
                nt = NODE_STATUS_TERMINAL
                hv = setrecon.vec_ZZ_p(self.curNode.hash_vector)
                ev = None
                ss = self.curNode.setsize
            else:
                nt = NODE_STATUS_NONTERMINAL
                hv = setrecon.vec_ZZ_p(self.curNode.hash_vector)
                ev = setrecon.vec_ZZ_p(self.curNode.extra_hashes)
                ss = self.curNode.setsize

            self.nt, self.hv, self.ev, self.ss = nt, hv, ev, ss
            
            self.logger.debug("reconcile_next->%s type=%d", self, nt)
            self.sendCommand("reconcile_next", nt, hv, ev, ss)      
            self.setTimeout()


    def handle_reconcile_next(self, nodeType, hash_vector, extra_hashes, size):
        """Start reconciling of the current partition.    
        """

        self.cancelTimeout()        
        #self.logger.debug("reconcile_next<-%s nt=%s  hv=%s  eh=%s ss=%s",
        #                  self,
        #                  nodeType,
        #                  hash_vector,
        #                  extra_hashes,
        #                  size)
        
        assert self.state == self.STATE_GOSSIPING
        myNode = self.curNode

        # Both nodes are empty means that we are done.
        if (self.nt == NODE_STATUS_EMPTY) and (nodeType == NODE_STATUS_EMPTY):
            self.logger.debug("reconcile %s both empty" %self)
            self.reconcile_next()
        
        #His node is empty, send all terminal data.
        elif nodeType==NODE_STATUS_EMPTY:
            self.logger.debug("reconcile %s his empty" %self)
            td = self.set.internal2external(myNode.terminal_data())
            for x in td:
                assert x not in self.outBuff
                self.outBuff.append(x)
            self.reconcile_next()
          
        # My node is empty. Request all elements in this partition.
        elif self.nt == NODE_STATUS_EMPTY:
            self.logger.debug("reconcile %s my empty" %self)
            self.reconcile_next()

        # We have 2 non empty nodes. If one of them is terminal, we
        # can compute the difference directly. If both are none
        # terminal, we must use the set reconciliation algorithm.

        else:            

            # If his node is terminal, I can figure out what he is missing.
            if nodeType == NODE_STATUS_TERMINAL:
                self.logger.debug("reconcile %s his treminal" %self)
                td = myNode.terminal_data()
                hismissing = self.set.internal2external(setrecon.difference_set(hash_vector, td))
                
                for x in hismissing:
                    assert x not in self.outBuff
                    self.outBuff.append(x)

                # If I have a non-terminal node, the other guy can not
                # figure out what hashes I'm missing. Since I know
                # what I'm missing from his set, I need to request
                # these.                
                if self.nt == NODE_STATUS_NONTERMINAL:
                    self.logger.debug("reconcile %s both nodes treminal" %self)
                    mymissing = self.set.internal2external(setrecon.difference_set(td, hash_vector))
                    for x in mymissing:
                        assert x not in self.reqBuff
                        self.reqBuff.append(x)
                self.reconcile_next()
            
            # My node is terminal, his is not. The other node will
            # inform me of missing elements.            
            elif self.nt == NODE_STATUS_TERMINAL:
                self.logger.debug("reconcile %s mynode not treminal" %self)
                self.reconcile_next()

            # Both nodes are non-terminal.
            else:
                self.logger.debug("reconcile %s both not terminal" % self)
                valids = myNode.valids
                if self.master:
                    aHash = self.hv
                    aExtra = self.ev
                    aSize = self.ss
                    bHash = hash_vector
                    bExtra = extra_hashes
                    bSize = size                    
                else:
                    bHash = self.hv
                    bExtra = self.ev
                    bSize = self.ss
                    aHash = hash_vector
                    aExtra = extra_hashes
                    aSize = size

                status, aMissing, bMissing = self.set.reconcile(aHash, aExtra, aSize, bHash, bExtra, bSize, valids)
                ##self.logger.debug("reconcile %sreconcile\n\taHash=%s \n\taExtra=%s \n\taSize=%d \n\tbHas=%s \n\tbExtra=%s \n\tbSize=%d \n\tvalids=%s ", self,
##                                  aHash,
##                                  aExtra,
##                                  aSize,
##                                  bHash,
##                                  bExtra,
##                                  bSize,
##                                  valids)
                

                if self.master:
                    mymissing = aMissing
                    hismissing = bMissing
                else:
                    mymissing = bMissing
                    hismissing = aMissing                    

                if status == 0:
                    self.logger.debug("reconcile %s reconcile failed valids", self)
                    c = []
                    for x in range(self.set._recon.p):
                        if self.curNode.hasChild(x):
                            n = self.curNode.getChild(x)
                            n.ref()
                            c.append(n)
                        else:
                            c.append(None)
                    self.nodes = c + self.nodes
                else:
                    self.logger.debug("reconcile %s reconcile worked hismissing=%s mymissing=%s", self, hismissing, mymissing)
                    for x in hismissing:
                        assert x not in self.outBuff
                        self.outBuff.append(x)                    
                self.reconcile_next()

    def handle_reconcile_data(self, data):
        """Data from client.
        """
        assert self.nodes == []
        assert self.state == self.STATE_GOSSIPING
        self.logger.debug("reconcile_data<-%s %s", self, data)
        self.dataBuff.append(data)

    def handle_reconcile_data_req(self, hashes):
        self.cancelTimeout()         
        assert self.state == self.STATE_GOSSIPING
        assert self.nodes == [], "%s %s %s" % (self.factory.peer, self, self.nodes)
        
        self.logger.debug("reconcile_data_req<-%s %d", self, len(hashes))

        for x in hashes:
            assert not x in self.outBuff
            self.outBuff.append(x)

        badness = self.factory.service.parent.badness
        while self.outBuff:
            x = self.outBuff.pop()
            
            if self.setName == "aSet" and badness == 1:
                #Passive attack, do not forward accusations.
                continue
                
            try:
                d = self.set[x]
            except KeyError, e:
                self.logger.warning("reconcile_data->%s %s removed", self, x)
            else:

                if badness == 2 and self.setName == "nSet":
                    # If active attack, forward only our own notes.
                    if d.identity != self.factory.service.parent.getMe().getIdentity():
                        continue                
                self.sendCommand("reconcile_data", d)
                self.logger.debug("reconcile_data->%s %s", self, d)

        if self.master:
            self.logger.debug("reconcile_done->%s", self)
            self.sendCommand("reconcile_done")

        self.setTimeout()



class ServerProtocol(GossipBase):
    
    logger = logging.getLogger()
    factory = None
    
    def __init__(self):        
        self._stop = False
        self._timer = None
        self.curNode = None
        self.nodes = []
        self.dataBuff = []
        self.reqBuff = []
        self.outBuff = []
        self.factory = None
        isinstance(self.factory, ReconciliationPeer)

    def handle_version(self, major, minor, patchlevel):
        #
        # TODO: The node will die if it has an old version
        # number. This is VERY INSECURE and will be removed. However,
        # it is nice for testing on PlanetLab.
        # 
        if (major, minor, patchlevel) > fireflies.protocol_version:
            self.logger.warning("authenticate<- %s Version error. I have an old version. Exiting.", self)
            reactor.callLater(2, reactor.stop)
        elif (major, minor, patchlevel) < fireflies.protocol_version:
            self.logger.warning("authenticate<- %s Version error. Other have an old version. Exiting.", self)
        self.sendCommand("version", *fireflies.protocol_version)
 
    def redirect(self, members):
        #self.factory.peer.view.stats.redirect += 1
        pprint = self.factory.service.parent.view.pprint
        self.logger.debug("redirect-> %s", self)
        self.setTimeout()
        lst = []
        for m in members:
            lst.append( (m.getCertificate(), m.getNote() ))
        self.sendCommand("redirect", lst)

    def accept(self):
        self.logger.debug("accepted-> %s", self)
        self.sendCommand("accepted")
        self.state = self.STATE_IDLE
        
    def handle_partner(self, hisNote):
        self.cancelTimeout()
        self.factory.service.parent.getView().addNote(hisNote)    
        self.logger.debug("partner<- %s", self)
        reactor.callLater(0, self.factory.clientConnected, self)

    def handle_dataRequest(self):
        while self.factory.msgQueue.waiting:
            d = self.factory.msgQueue.get()
            d.addCallback(lambda x: self.sendData(x))
            
    #
    # Main protocol steps
    #

    def handle_reconcile(self, name, digest):
        """
        Protocol start. Name specifies the set to be reconciled.
        """

        self.logger.debug("reconcile<-%s name=%s", self, name)
        assert self.state == self.STATE_IDLE
        self.state = self.STATE_GOSSIPING

        assert self.dataBuff == []
        assert self.reqBuff == []
        assert self.outBuff == []
        self.set, self.appendfunc = self.factory.getSet(name)
        self.setName = name
        
        if self.curNode: self.curNode.unref()
        self.curNode = None
        self.nodes = []
        
        n = self.set.getRootPartition()
        hsh = sha.new()
        
        hv = map(lambda x: str(x), n.hash_vector)
        hv.sort()
        for x in hv:            
            hsh.update(x)
        
        if digest == hsh.digest():
            self.logger.debug("digest_match->%s True", self)
            self.sendCommand("digest_match", True)
            self.state = self.STATE_IDLE
        else:
            n.ref()
            self.nodes = [n]
            self.logger.debug("digest_match->%s False", self)
            self.sendCommand("digest_match", False)
            self.reconcile_next()
    

    def handle_reconcile_done(self):
        """Reconciliation is done.

        Sends:
         - reconcile_done ()
        """
        assert not self.nodes
        self.cancelTimeout()
        self.logger.debug("reconcile_done<-%s", self)
        assert self.state == self.STATE_GOSSIPING, "%s %s, invalid state %s" %(self.factory.peer, self, self.state)
        assert self.nodes == []
        self.logger.debug("reconcile_done->%s", self)
        self.sendCommand("reconcile_done")
        self.state = self.STATE_IDLE

        tmpbuff = self.dataBuff
        self.dataBuff = []
        for itm in tmpbuff:
            try:
                self.appendfunc(itm)
            except ValueError, why:
                self.logger.warning("reconcile_done error in data %s %s", itm, why) 
        

        
class ClientProtocol(GossipBase):
    
    logger = logging.getLogger()
    factory = None
    interval = 10
    task = None
    
    def __init__(self):
        self._timer = None
        self.timestamp = 0
        self._d = None
        self.curNode = None
        self.nodes = []
        self.master = True
        self.dataBuff = []
        self.reqBuff = []
        self.outBuff = []

        self.taskQ = defer.DeferredQueue()
        
        isinstance(self.factory, ReconciliationPeer)
        self.task = task.LoopingCall(self.update)
   
    def idle(self):
        d = self.taskQ.get()
        d.addCallback(self.cb_nextTask)

    def update(self):
        if self != self.factory.protocol:
            self.task.stop()
            return
        
        self.logger.debug("dataRequest <- %s", self)
        self.sendCommand("dataRequest")
        
    def cb_nextTask(self, task):
        if isinstance(task, NoteSet):
            self.reconcile("nSet", task, self.factory.service.group.view.addNote)
        elif isinstance(task, AccusationSet):
            self.reconcile("aSet", task, self.factory.service.group.view.addAccusation)
        elif isinstance(task, X509Set):
            self.reconcile("cSet", task, self.factory.service.group.view.addCertificate)
        elif isinstance(task, str):
            if task == "dataRequest":
                self.sendCommand("dataRequest")
        else:
            self.sendData(msg)
        
        
    def handle_version(self, major, minor, patchlevel):
        #
        # TODO: The node will die if it has an old version
        # number. This is VERY INSECURE and will be removed. However,
        # it is nice for testing on PlanetLab.
        #
        
        self.cancelTimeout()
        if (major, minor, patchlevel) > fireflies.protocol_version:
            self.logger.warning("version<- %s Version error. I have an old version. Exiting.", self)
            reactor.callLater(2, reactor.stop)
        elif (major, minor, patchlevel) < fireflies.protocol_version:
            self.logger.warning("version<- %s Version error. Other have an old version.", self)
            
        crt, note = self.factory.getCredentials()
      
        
    def _sendPartner(self, note):
        self.logger.debug("partner > %s", self)
        self.setTimeout()
        self.sendCommand("partner", note)
        
    def handle_accepted(self):   

        self.state = self.STATE_IDLE
        self.cancelTimeout()
        self.logger.debug("accepted < %s", self)
        reactor.callLater(0, self.factory.serverConnected, self)
        reactor.callLater(0, self.idle)
        
    def handle_redirect(self, data):
        self.cancelTimeout()
        self.logger.debug("redirect < %s", self)
        for cert, note in data:
            self.factory.view.addCertificate(crt)
            self.factory.view.addNote(note)   
        self.hangup()
        

    #
    # Reconcile stuff
    #    
    def reconcile(self, name, set, appendfunc):

        assert self.state == self.STATE_IDLE
        self.state = self.STATE_GOSSIPING

        self._d = defer.Deferred()
        assert self.reqBuff == []
        assert self.outBuff == []
        assert self.dataBuff == []
        self.setName = name
        self.set = set
        self.appendfunc = appendfunc

        if self.curNode: self.curNode.unref()
        self.curNode = None
        
        n = set.getRootPartition()
        hsh = sha.new()

        hv = map(lambda x: str(x), n.hash_vector)
        hv.sort()
        for x in hv:            
            hsh.update(x)
        
        self.logger.debug("reconcile->%s %s hash=%s", self, name, str(hsh.hexdigest()))                
        self.sendCommand("reconcile", name, hsh.digest())        
        self.setTimeout()
        return self._d

    def handle_digest_match(self, match):
        assert self.state == self.STATE_GOSSIPING
        self.cancelTimeout()
        self.logger.debug("digest_match<-%s %s", self, bool(match))
        if match:
            assert self.nodes == self.reqBuff == self.dataBuff == self.outBuff == []
            self.state = self.STATE_IDLE
            self._d.callback(None)
            self.idle()
        else:
            n = self.set.getRootPartition()
            n.ref()
            self.nodes = [n]
            self.reconcile_next()

    def handle_reconcile_done(self):
        """Done reply from server. This extra message is needed to
        flush any data that might be on the wire.
        """
        assert not self.nodes
        self.cancelTimeout()
        self.logger.debug("reconcile_done<-%s", self)
        assert self.state == self.STATE_GOSSIPING
        self.state = self.STATE_IDLE
        assert self.nodes == []
        tmpbuff = self.dataBuff
        self.dataBuff = []
        
        for itm in tmpbuff:
            try:
                self.appendfunc(itm)
            except ValueError, why:
                self.logger.warning("reconcile_done error in data %s %s", itm, why) 
                
        self._d.callback(None)
        self.idle()

            
def isEmptyNode(node):
    if node:
        if node.intree:
            if node.ref_count() < 2: node.printNode(0)
            assert node.ref_count() > 1, "refcount is %d shoud be 2. intree=%s" %(node.ref_count(), node.intree)
        else:
            if node.ref_count() == 0: node.printNode(0)
            assert node.ref_count() > 0, "refcount is %d shoud be >0. intree=%s" %(node.ref_count(), node.intree)
            
    return bool(   (node == None) or (node.setsize==0) or (node.intree == False))


class Gossip(Service):
    
    implements(fireflies.protocols.IPeerNetworkingService)
    
    name = "gossip"
    logger = logging.getLogger(name)
    byzantineToleranceNumber = 7
    rate = 30.0
    TCPTimeout = 360.0
    
    ServerProtocolClass = ServerProtocol
    ClientProtocolClass = ClientProtocol
    rings = None
    group = None
    
    
    def __init__(self, group):
        isinstance(group, fireflies.group.Group)
        
        self.group = group
        self.setServiceParent(group)
        self.rings = ring.RingSet()
        for x in range(self.byzantineToleranceNumber):
            self.rings.insertRing(ring.NameHashedRing(x))
        
        self.sFactory = fireflies.protocols.PeerServerFactory(self)

        self.cSet = X509Set(PARTITION_FACTOR, RECON_EXTRA)
        self.nSet = NoteSet(PARTITION_FACTOR, RECON_EXTRA)
        self.aSet = AccusationSet(PARTITION_FACTOR, RECON_EXTRA)

        self.connectedAsServer = set()
        self.active = set()
        self.neighborPool = {}

    def evDataAccusation(self, name, itm, status):
        if name == "data.accusation": sset = self.aSet
        elif name == "data.note": sset = self.nSet
        elif name == "data.certificate": sset = self.cSet
        else: raise RuntimeError, "Invalid data event", name
                
        if status == True:
            sset.insert(itm)
           # for f in self.active.union(self.connectedAsServer):
           #     f.sendMsg(itm)
        else:
            sset.remove(itm)
            
    def evMemberNew(self, name, member, status):
        if status == fireflies.EV_CRASH_NEW:
            self.rings.insertItem(member)
            self.logger.debug("adding %s to gossip rings", member)
            factory = ReconciliationPeer(self)
            factory.protocolClass = ClientProtocol
            factory.member = member
            
            self.neighborPool[member] = factory
    
    def getPeerFactoryFromProtocol(self, protocol):
        return self.neighborPool[protocol.other]

    def startService(self):
        Service.startService(self)

        # Register all member in the gossip mesh
        for m in self.parent.view.getAllMembers():
            self.evMemberNew("", m, fireflies.EV_CRASH_NEW)

        # Add all certificates, notes, and accusations to our data sets.
        for m in self.parent.view.getAllMembers():
            self.cSet.insert(m.getCertificate())
            if m.getNote(): self.nSet.insert(m.getNote())
            for a in m.getAccusations(): self.aSet.add(a)

        #register to receive notification on group updates.
        self.parent.registerEventHandler("member.crash", self.evMemberNew)        
        self.parent.registerEventHandler("data.accusation", self.evDataAccusation)
        self.parent.registerEventHandler("data.note", self.evDataAccusation)
        self.parent.registerEventHandler("data.certificate", self.evDataAccusation)
                
        address = self.parent.getMe().address
        self.logger.info("Binding gossip to tcp %s:%d", address.host, address.port)
        
        self._port = fireflies.protocols.listen(address.port, self.sFactory, self.parent, interface=address.host,postConnectionCheck=sslPostConnectionCheck)

        self.sFactory.doStart()

        def _d():            
            self._task = task.LoopingCall(self.update)
            self._task.start(self.rate/len(self.rings.getRings())).addErrback(self._failback)
                             
        reactor.callLater(0.1, _d)
        
    def stopService(self):
        Service.stopService(self)
        self._task.stop()
        self._port.stopListening()

        for factory in self.factories.values():
            factory.doStop()   
        self.sFactory.doStop()

        
    def update(self):

        outbound = self.rings.succ(self.group.getMe(), lambda x: x.isLive())
        outbound = filter(lambda x: x != self.group.getMe(), outbound)
        inbound = self.rings.pred(self.group.getMe(), lambda x: x.isLive())
        inbound = filter(lambda x: x != self.group.getMe(), inbound)

        # Deactivate outbound connections
        toDeactivate = filter(lambda x: not x.member in outbound, self.active)
        
        for factory in toDeactivate:
            self.active.remove(factory)
            factory.deactivate()
                
        # Activate new connections 
        for him in set(outbound):

            # Should never fail
            factory = self.neighborPool[him]
            
            if not factory.isActive(): 
                assert not factory in self.active
                self.active.add(factory)
                factory.activate()
            else:
                assert factory in self.active
                if factory.protocol.master:
                    factory.protocol.taskQ.put(self.cSet)
                    factory.protocol.taskQ.put(self.nSet)
                    factory.protocol.taskQ.put(self.aSet)
                                                
    def _failback(self, reason):
        self.logger.exception(reason)

    def peerConnected(self, factory):
        """Called when a new connection is accepted."""
        
        assert factory.protocol
        isinstance(factory, ReconciliationPeer)
        if factory.protocol.master:
            assert factory in self.active
            assert factory.isActive()
        else:
            self.connectedAsServer.add(factory)
        
