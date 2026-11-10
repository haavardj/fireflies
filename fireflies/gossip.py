######################################################################
## Filename:      gossip.py
## Description:   Fireflies set-recon based gossip protocol 
## Author:        Håvard Dagenborg <havard.dagenborg@outlook.com>
## Modified at:   Wed Feb  1 18:12:09 2006
## Modified by:   Håvard Dagenborg <havard.dagenborg@outlook.com>
## Licence:       MIT (see the LICENCE file).
##  
##         Copyright© 2006, Håvard Dagenborg
##                
## $Id: gossip.py,v 1.37 2014/06/16 07:49:47 haavardj Exp $
##                
######################################################################

import logging, fireflies
from twisted.internet.protocol import Factory, Protocol, ClientFactory, ServerFactory
from twisted.protocols.basic import Int32StringReceiver
import twisted.internet
from twisted.internet import defer
from twisted.application.service import Service

from fireflies import crypto, setrecon, ring
import fireflies.protocols
from fireflies.packer import FirefliesPacker, FirefliesUnpacker
from fireflies.state import Note, Accusation, Member
import hashlib, inspect


PARTITION_FACTOR = 3
RECON_EXTRA = 5
MBAR=10
BITSIZE=256

setrecon.init(int(BITSIZE), int(MBAR))

NODE_STATUS_EMPTY = 0
NODE_STATUS_TERMINAL = 1
NODE_STATUS_NONTERMINAL = 2

LOGDATA=True
LOGSHASHCHECK = False
LOGSETRECON = False

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
        if not isinstance(elm, crypto.Certificate): raise ValueError
        # 256-bit SHA-256 digest of the DER encoding. (M2Crypto used the
        # 32-character MD5 hex fingerprint, also 256 bits.)
        return setrecon.to_ZZ_p(setrecon.to_ZZFromBytes(elm.digest()))



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
    factory = None
    _timer = None
    
    
    def __init__(self):
        fireflies.protocols.FirefliesProtocol.__init__(self)
        self.curNode = None
        self.nodes = []        
        self.dataBuff = []
        self.reqBuff = []
        self.outBuff = []
        
    def idle(self):
        pass

    def reconcile_next(self):
        """Moves to the next partition available partition, or marks
        the reconciliation as done if no more partitions are available.

        Sends
        -- reconciliation_done ()
        -- reconciliation_next_req ()
        """
        assert self.state == self.STATE_GOSSIPING, "state is %s should be %s" % (self.state, self.STATE_GOSSIPING)
        if LOGSETRECON: self.logger.debug("reconcile_next %s nodes=%d", self, len(self.nodes))

        if self.nodes == []:
            self.setTimeout()
            self.reqBuff = [x for x in self.reqBuff if x not in self.set]
            if LOGSETRECON: self.logger.debug("reconcile_data_req->%s %d ", self, len(self.reqBuff))
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
            
            if LOGSETRECON: self.logger.debug("reconcile_next->%s type=%d", self, nt)
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
            if LOGSETRECON: self.logger.debug("reconcile %s both empty" %self)
            self.reconcile_next()
        
        #His node is empty, send all terminal data.
        elif nodeType==NODE_STATUS_EMPTY:
            if LOGSETRECON: self.logger.debug("reconcile %s his empty" %self)
            td = self.set.internal2external(myNode.terminal_data())
            for x in td:
                assert x not in self.outBuff
                self.outBuff.append(x)
            self.reconcile_next()
          
        # My node is empty. Request all elements in this partition.
        elif self.nt == NODE_STATUS_EMPTY:
            if LOGSETRECON: self.logger.debug("reconcile %s my empty" %self)
            self.reconcile_next()

        # We have 2 non empty nodes. If one of them is terminal, we
        # can compute the difference directly. If both are none
        # terminal, we must use the set reconciliation algorithm.

        else:            

            # If his node is terminal, I can figure out what he is missing.
            if nodeType == NODE_STATUS_TERMINAL:
                if LOGSETRECON: self.logger.debug("reconcile %s his treminal" %self)
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
                    if LOGSETRECON: self.logger.debug("reconcile %s both nodes treminal" %self)
                    mymissing = self.set.internal2external(setrecon.difference_set(td, hash_vector))
                    for x in mymissing:
                        assert x not in self.reqBuff
                        self.reqBuff.append(x)
                self.reconcile_next()
            
            # My node is terminal, his is not. The other node will
            # inform me of missing elements.            
            elif self.nt == NODE_STATUS_TERMINAL:
                if LOGSETRECON: self.logger.debug("reconcile %s mynode not treminal" %self)
                self.reconcile_next()

            # Both nodes are non-terminal.
            else:
                if LOGSETRECON: self.logger.debug("reconcile %s both not terminal" % self)
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
                    if LOGSETRECON: self.logger.debug("reconcile %s reconcile failed valids", self)
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
                    if LOGSETRECON: self.logger.debug("reconcile %s reconcile worked hismissing=%s mymissing=%s", self, hismissing, mymissing)
                    for x in hismissing:
                        assert x not in self.outBuff
                        self.outBuff.append(x)                    
                self.reconcile_next()

    def handle_reconcile_data(self, data):
        """Data from client.
        """
        assert self.nodes == []
        assert self.state == self.STATE_GOSSIPING
        if LOGDATA: self.logger.debug("reconcile_data <- %s %s", self, data)
        self.dataBuff.append(data)

    def handle_reconcile_data_req(self, hashes):
        self.cancelTimeout()         
        assert self.state == self.STATE_GOSSIPING
        assert self.nodes == [], "%s %s %s" % (self.factory.peer, self, self.nodes)
        
        if LOGSETRECON: self.logger.debug("reconcile_data_req <- %s %d", self, len(hashes))

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
            except KeyError as e:
                self.logger.warning("reconcile_data -> %s %s removed", self, x)
            else:

                if badness == 2 and self.setName == "nSet":
                    # If active attack, forward only our own notes.
                    if d.identity != self.factory.service.parent.getMe().identity:
                        continue                
                self.sendCommand("reconcile_data", d)
                if LOGDATA: self.logger.debug("reconcile_data -> %s %s", self, d)

        if self.master:
            if LOGSETRECON: self.logger.debug("reconcile_done -> %s", self)
            self.sendCommand("reconcile_done")

        self.setTimeout()

    def handle_reconcile_done(self):
        """Reconciliation is done."""

        assert not self.nodes
        self.cancelTimeout()
        if LOGSETRECON: self.logger.debug("reconcile_done <-%s ", self)
        assert self.state == self.STATE_GOSSIPING, "%s %s, invalid state %s" %(self.factory.peer, self, self.state)
        assert self.nodes == []
        if LOGSETRECON: self.logger.debug("reconcile_done->%s", self)
        
        if not self.master: self.sendCommand("reconcile_done")
        self.state = self.STATE_IDLE

        tmpbuff = self.dataBuff
        self.dataBuff = []
        for itm in tmpbuff:
            try:
                self.appendfunc(itm)
            except ValueError as why:
                self.logger.warning("reconcile_done error in data %s %s", itm, why) 
            except KeyError as why:
                self.logger.warning("reconcile_done error in data %s %s", itm, why) 
                
        if self.master:
            self._d.callback(None)
            self.idle()


    #
    # Reconcile stuff
    #    
    def reconcile(self, name, set, appendfunc):

        if (not self.connected) or self.state != self.STATE_IDLE: 
            self.logger.error("error: Scheduled reconsile ignored. Connection is terminated %s", self)
            return

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
        hsh = hashlib.sha1()
        
        hv = [str(x) for x in n.hash_vector]
        hv.sort()
        for x in hv:            
            hsh.update(x.encode("ascii"))

        if LOGSETRECON: self.logger.debug("reconcile->%s %s hash=%s", self, name, str(hsh.hexdigest()))                
        self.sendCommand("reconcile", name, hsh.digest())
        self.setTimeout()
        return self._d

    def handle_digest_match(self, match):
        assert self.state == self.STATE_GOSSIPING
        self.cancelTimeout()
        if LOGSHASHCHECK: self.logger.debug("digest_match<-%s %s", self, bool(match))
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

        if LOGSETRECON: self.logger.debug("reconcile <- %s name=%s", self, name)
        assert self.state == self.STATE_IDLE
        self.state = self.STATE_GOSSIPING

        assert self.dataBuff == []
        assert self.reqBuff == []
        assert self.outBuff == []
        self.set, self.appendfunc = self.service.getSet(name)
        self.setName = name
        
        if self.curNode: self.curNode.unref()
        self.curNode = None
        self.nodes = []
        
        n = self.set.getRootPartition()
        hsh = hashlib.sha1()
        
        hv = [str(x) for x in n.hash_vector]
        hv.sort()
        for x in hv:            
            hsh.update(x.encode("ascii"))
        
        if digest == hsh.digest():
            if LOGSHASHCHECK: self.logger.debug("digest_match->%s True", self)
            self.sendCommand("digest_match", True)
            self.state = self.STATE_IDLE
            assert not self.master
        else:
            n.ref()
            self.nodes = [n]
            if LOGSHASHCHECK: self.logger.debug("digest_match->%s False", self)
            self.sendCommand("digest_match", False)
            self.reconcile_next()
    

class ServerProtocol(GossipBase):
    master = False
          
    def ide(self):
        pass

class ClientProtocol(GossipBase):
    master = True

    def __init__(self):
        
        self._timer = None
        self._d = None
        self.master = True        
        self.taskQ = defer.DeferredQueue()                            
        GossipBase.__init__(self)  
       
        
    def gossip(self):    
        self.logger.debug("gossip %s", self)
        
        if not (self.connected and self.factory and self.transport):
            raise RuntimeError

        if not self.taskQ.pending:        
            self.taskQ.put(self.factory.service.cSet)
            self.taskQ.put(self.factory.service.nSet)
            self.taskQ.put(self.factory.service.aSet) 
        else:
            self.logger.warning("warning: %s gossip not completed before next round. Skipping. pending=%s", self,str(self.taskQ.pending))
                    
    def idle(self):
        d = self.taskQ.get()            
        d.addCallback(self.cb_nextTask)
        
    def cb_nextTask(self, task):

        if not self.connected or self.state == self.STATE_TERMINATED: 
            self.logger.info("scheduled task ignored as connection is terminated %s", self)
            return
        
        if isinstance(task, NoteSet):
            self.reconcile("nSet", task, self.factory.service.group.view.addNote)
        elif isinstance(task, AccusationSet):
            self.reconcile("aSet", task, self.factory.service.group.view.addAccusation)
        elif isinstance(task, X509Set):
            self.reconcile("cSet", task, self.factory.service.group.view.addCertificate)
        else:
            raise RuntimeError 
        
              


            
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
    
    name = "gossip"
    rate = 60.0
    updateInterval = 2.0
    TCPTimeout = 360.0
    
    rings = None
    group = None
        
    def __init__(self, group):
        isinstance(group, fireflies.group.Group)        
        self.group = group
                
        self.setServiceParent(group)
        self.rings = ring.RingSet()
        for x in range(self.group.nrGossipingRings()):
            self.rings.insertRing(ring.NameHashedRing(x))
    
        self.cSet = X509Set(PARTITION_FACTOR, RECON_EXTRA)
        self.nSet = NoteSet(PARTITION_FACTOR, RECON_EXTRA)
        self.aSet = AccusationSet(PARTITION_FACTOR, RECON_EXTRA)

        self.connectedAsServer = set()
        self.active = set()
        self.neighborPool = {}
        self.eventHandlers = []
        
        self.sFactory = fireflies.protocols.PeerServerFactory(self)
        self.sFactory.protocol = ServerProtocol
        self._task = twisted.internet.task.LoopingCall(self.update)

    @property
    def logger(self):
        return self.group.logger

    def evData(self, name, itm, status):
        if name == "data.accusation": sset = self.aSet
        elif name == "data.note": sset = self.nSet
        elif name == "data.certificate": sset = self.cSet
        else: raise RuntimeError("Invalid data event", name)
                
        if status == True:
            try:
                sset.insert(itm)
            except Exception as why:
                self.logger.exception("Insert error %s %s", itm, why)
        else:
            sset.remove(itm)

    def evMemberUpdate(self, name, member, status):
        self.logger.debug("evMemberUpdate %s %s %s", name, member, status)
        
        #if self.running: self.update()

    def evMemberNew(self, name, member, status):
        self.logger.debug("evMemberNew %s %s %s", name, member, status)
        
        if status == fireflies.EV_CRASH_NEW:
            self.rings.insertItem(member)
            factory = fireflies.protocols.ReconnectingPeerFactory(member)
            factory.protocol = ClientProtocol
            factory.service = self
            self.neighborPool[member] = factory
            factory.doStart()

        #self.update()
    
    def getPeerFactoryFromProtocol(self, protocol):
        return self.neighborPool[protocol.other]

    def getMemberFactory(self, member):
        return self.neighborPool[member]

    def startService(self):
        
        # Register all member in the gossip mesh
        for m in self.group.getAllMembers():
            if not self.rings.hasItem(m):
                self.rings.insertItem(m)
                factory = fireflies.protocols.ReconnectingPeerFactory(m)
                factory.protocol = ClientProtocol
                factory.service = self
                self.neighborPool[m] = factory
                factory.doStart()
            else:
                assert m in self.neighborPool
                                
        # Add all certificates, notes, and accusations to our data sets.
        self.cSet = X509Set(PARTITION_FACTOR, RECON_EXTRA)
        self.nSet = NoteSet(PARTITION_FACTOR, RECON_EXTRA)
        self.aSet = AccusationSet(PARTITION_FACTOR, RECON_EXTRA)
        
        for m in self.group.getAllMembers():                
            self.cSet.insert(m.getCertificate())
            if m.getNote(): self.nSet.insert(m.getNote())
            for a in m.getAccusations(): self.aSet.add(a)

        #register to receive notification on group updates.
        hdlr = self.group.registerEventHandler("member.recover", self.evMemberUpdate)
        self.eventHandlers.append(hdlr)
        
        hdlr = self.group.registerEventHandler("member.crash", self.evMemberNew)       
        self.eventHandlers.append(hdlr)
        
        hdlr = self.group.registerEventHandler("data.accusation", self.evData)
        self.eventHandlers.append(hdlr)
        
        hdlr = self.group.registerEventHandler("data.note", self.evData)
        self.eventHandlers.append(hdlr)
        
        hdlr = self.group.registerEventHandler("data.certificate", self.evData)        
        self.eventHandlers.append(hdlr)        

        address = self.group.getMe().address
        self.logger.info("Binding gossip to tcp %s:%d", address.host, address.port)
        self._port = fireflies.protocols.listen(address.port, self.sFactory, self.group.getTLSOptions(), interface=address.host)
        self.sFactory.doStart()

        self._task.start(self.updateInterval, now=False)

        assert not self.running
        Service.startService(self)
        
        
    def stopService(self):
        assert self.running
        
        for hdlr in self.eventHandlers:
            try:
                self.group.removeEventHandler(hdlr)
            except ValueError:
                print("Eventhandler not found:", hdlr[0])
                raise

        self.eventHandlers = []
            
        address = self.group.getMe().address
        self.logger.info("Stop gossiping on tcp %s:%d", address.host, address.port)
        

        self._task.stop()
        self._port.stopListening()
        
        # Any connected servers will be disconnected below.
        self.connectedAsServer = set()
        
        for member, factory in list(self.neighborPool.items()):
            if factory.isActive():
                assert factory in self.active
                factory.deactivate()
            
            if factory.isConnected():
                factory.hangup()
                
            factory.doStop()
            
        self.sFactory.doStop()

        Service.stopService(self)
        
    def update(self):
        outbound = self.rings.succ(self.group.getMe(), lambda x: x.isLive())
        outbound = [x for x in outbound if x != self.group.getMe()]
        inbound = self.rings.pred(self.group.getMe(), lambda x: x.isLive())
        inbound = [x for x in inbound if x != self.group.getMe()]
       
        for f in self.active:
            if not f.isActive():
                self.logger.error("%s (%s) in active but not activated", f,f.member)
            assert f.isActive()                
                
        # Activate new connections         
        for nr, him in enumerate(outbound):

            # Should never fail
            factory = self.neighborPool[him]
            
            if not factory.isActive(): 
                assert not factory in self.active
                factory.activate()
            else:
                if not factory in self.active:
                    self.logger.error("error: inactive factory %s in active", factory)

        # Deactivate outbound connections
        toDeactivate = [x for x in self.active if not x.member in outbound]
        for factory in toDeactivate:
            self.logger.debug("deactivating previous gossip partner %s", factory)
            factory.deactivate()
        
    def _failback(self, reason):
        self.logger.exception(reason)

    def peerConnected(self, factory):
        """Called when a new connection is accepted."""

        assert factory.connectedProtocol

        if factory.connectedProtocol.master:
            if not factory.isActive():
                self.logger.error("error: connect as master, but not active %s", factory)
                factory.hangup()            
                return
            assert factory in self.active
            assert factory.isActive()
        else:
            self.connectedAsServer.add(factory)

    def peerDisconnected(self, factory):
        if factory in self.connectedAsServer:
            self.connectedAsServer.remove(factory)

    
    def getSet(self, name):
        if name == "cSet":
            s = self.cSet
            f = self.group.view.addCertificate
        elif name == "nSet":
            s = self.nSet
            f = self.group.view.addNote
        elif name == "aSet":
            s = self.aSet
            f = self.group.view.addAccusation
        else:
            raise ValueError("No such set.")
        return s, f
    
