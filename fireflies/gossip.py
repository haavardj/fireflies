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
## $Id: gossip.py,v 1.31 2011/11/07 13:28:55 haavardj Exp $
##                
######################################################################

import logging, sha, M2Crypto, fireflies
from twisted.internet.protocol import Factory, Protocol, ClientFactory, ServerFactory
from twisted.protocols.basic import Int32StringReceiver
from twisted.internet import reactor, task, defer
from twisted.application.service import Service
from zope.interface import implements
from M2Crypto.SSL.Checker import WrongHost, WrongCertificate, NoCertificate 

from fireflies import setrecon, ring
import fireflies.protocols
from fireflies.packer import FirefliesPacker, FirefliesUnpacker
from fireflies.state import Note, Accusation, Member


PARTITION_FACTOR = 3
RECON_EXTRA = 5
MBAR=10
BITSIZE=160

setrecon.init(BITSIZE, MBAR)

NODE_STATUS_EMPTY = 0
NODE_STATUS_TERMINAL = 1
NODE_STATUS_NONTERMINAL = 2


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


class GossipBase(fireflies.protocols.FirefliesProtocol):
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
    factory = None
    logger = logging.getLogger()
    _timer = None
    
    isinstance(factory, ReconciliationPeer)    
    
    def __init__(self):
        self.curNode = None
        self.nodes = []        
        self.dataBuff = []
        self.reqBuff = []
        self.outBuff = []
    


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

    def handle_reconcile_done(self):
        """Reconciliation is done."""

        assert not self.nodes
        self.cancelTimeout()
        self.logger.debug("reconcile_done<-%s", self)
        assert self.state == self.STATE_GOSSIPING, "%s %s, invalid state %s" %(self.factory.peer, self, self.state)
        assert self.nodes == []
        self.logger.debug("reconcile_done->%s", self)
        
        if not self.master: self.sendCommand("reconcile_done")
        self.state = self.STATE_IDLE

        tmpbuff = self.dataBuff
        self.dataBuff = []
        for itm in tmpbuff:
            try:
                self.appendfunc(itm)
            except ValueError, why:
                self.logger.warning("reconcile_done error in data %s %s", itm, why) 

        if self.master:
            self._d.callback(None)
            self.idle()


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
    

class ServerProtocol(GossipBase):
    master = False
     

class ClientProtocol(GossipBase):
    
    interval = 10
    task = None
    
    def __init__(self):
        GossipBase.__init__(self)
        
        self._timer = None
        self._d = None
        self.master = True
        self.taskQ = defer.DeferredQueue()
        
        isinstance(self.factory, ReconciliationPeer)                
        

    def idle(self):
        d = self.taskQ.get()
        
        if not d.called:

            idleCL = reactor.callLater(self.interval, self._cbidle)
        
            def _cancelIdle(data, idleCL):
                if idleCL.active():
                    idleCL.cancel()
                return data
            
            d.addCallback(_cancelIdle, idleCL)        
            
        d.addCallback(self.cb_nextTask)


    def _cbidle(self):
        if self != self.factory.protocol:
            return
        self.logger.debug("idle %s reconcile", self)
        self.taskQ.put(self.factory.service.cSet)
        self.taskQ.put(self.factory.service.nSet)
        self.taskQ.put(self.factory.service.aSet)
 

        
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

    def evData(self, name, itm, status):
        if name == "data.accusation": sset = self.aSet
        elif name == "data.note": sset = self.nSet
        elif name == "data.certificate": sset = self.cSet
        else: raise RuntimeError, "Invalid data event", name
                
        if status == True:
            sset.insert(itm)
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
        self.parent.registerEventHandler("data.accusation", self.evData)
        self.parent.registerEventHandler("data.note", self.evData)
        self.parent.registerEventHandler("data.certificate", self.evData)
                
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
                #if factory.protocol and factory.protocol.master:
                #    factory.protocol.taskQ.put(self.cSet)
                #    factory.protocol.taskQ.put(self.nSet)
                #    factory.protocol.taskQ.put(self.aSet)
                                                
    def _failback(self, reason):
        self.logger.exception(reason)

    def peerConnected(self, factory):
        """Called when a new connection is accepted."""
        
        assert factory.protocol
        isinstance(factory, ReconciliationPeer)
        if factory.protocol.master:
            assert factory in self.active
            assert factory.isActive()
            factory.protocol.taskQ.put(self.cSet)
            factory.protocol.taskQ.put(self.nSet)
            factory.protocol.taskQ.put(self.aSet)

        else:
            self.connectedAsServer.add(factory)
        
