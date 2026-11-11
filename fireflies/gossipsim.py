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
## $Id: gossip.py,v 1.36 2012/02/08 09:13:06 haavardj Exp $
##                
######################################################################

import logging, fireflies
from twisted.internet.protocol import Factory, Protocol, ClientFactory, ServerFactory
from twisted.protocols.basic import Int32StringReceiver
import twisted.internet
from twisted.internet import defer
from twisted.application.service import Service

from fireflies import setrecon, ring
import fireflies.protocols
from fireflies.packer import FirefliesPacker, FirefliesUnpacker
from fireflies.state import Note, Accusation, Member
import hashlib
from fireflies.util import reactor
from twisted.internet.task import LoopingCall
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from fireflies.group import Group


PARTITION_FACTOR = 3
RECON_EXTRA = 5
MBAR=10
BITSIZE=256

setrecon.init(int(BITSIZE), int(MBAR))

NODE_STATUS_EMPTY = 0
NODE_STATUS_TERMINAL = 1
NODE_STATUS_NONTERMINAL = 2


class NoteSet(setrecon.ReconSet):
       
    def elmToZZp(self, elm):        
        if not hasattr(elm, "__zz_value_x"):
            elm.__zz_value_x = setrecon.to_ZZ_p(setrecon.to_ZZFromBytes(elm.get_fingerprint()))        
        return elm.__zz_value_x
            
class AccusationSet(setrecon.ReconSet):

    def elmToZZp(self, elm):
        #if not isinstance(elm, Accusation): raise ValueError
        #return setrecon.to_ZZ_p(setrecon.to_ZZFromBytes(elm.get_fingerprint()))
        if not hasattr(elm, "__zz_value_x"):
            elm.__zz_value_x = setrecon.to_ZZ_p(setrecon.to_ZZFromBytes(elm.get_fingerprint()))        
        return elm.__zz_value_x
        
class X509Set(setrecon.ReconSet):

    def elmToZZp(self, elm):
        if not hasattr(elm, "__zz_value_x"):
            elm.__zz_value_x = setrecon.to_ZZ_p(setrecon.to_ZZFromBytes(elm.digest()))
        return elm.__zz_value_x




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
        self.curNode: Any = None
        self.nodes = []        
        self.dataBuff = []
        self.reqBuff = []
        self.outBuff = []
        
    def idle(self):
        pass

    def handle_reconcile_data(self, data):
        """Data from client.
        """
        assert self.nodes == []
        assert self.state == self.STATE_GOSSIPING
        self.logger.debug("reconcile_data <- %s %d", self, len(data))
        self.dataBuff.extend(data)

    def handle_reconcile_data_req(self, hashes):
        self.cancelTimeout()         
        assert self.state == self.STATE_GOSSIPING
        assert self.nodes == [], "%s %s %s" % (self.factory.peer, self, self.nodes)
        
        self.logger.debug("reconcile_data_req <- %s %d", self, len(hashes))
        
        assert hashes == []

        badness = self.factory.service.group.badness

        #Passive attack
        if self.setName == "aSet" and self.group.badness == 1:
            self.outBuff = []
        
        
        if self.group.badness == 2 and self.setName == "nSet":
            # If active attack, forward only our own notes.
            self.outBuff = [self.group.getMe().getNote()]
            
            #filter(lambda x: x.identity != self.factory.service.parent.getMe().identity, self.outBuff)

        self.logger.debug("reconcile_data -> %s %d", self, len(self.outBuff))                        
        self.sendCommand("reconcile_data", list(self.outBuff))
        self.outBuff = []

        if self.master:
            self.logger.debug("reconcile_done -> %s", self)
            self.sendCommand("reconcile_done")

        self.setTimeout()

    def handle_reconcile_done(self):
        """Reconciliation is done."""

        assert not self.nodes
        self.cancelTimeout()
        self.logger.debug("reconcile_done <-%s ", self)
        assert self.state == self.STATE_GOSSIPING, "%s %s, invalid state %s" %(self.factory.peer, self, self.state)
        assert self.nodes == []
        self.logger.debug("reconcile_done->%s", self)
        
        if not self.master: self.sendCommand("reconcile_done")
        self.state = self.STATE_IDLE

        tmpbuff =  self.dataBuff
        self.dataBuff = []
        for itm in tmpbuff:
            try:
                if not itm in self.dataset:
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
    def reconcile(self, name, dataset, appendfunc):

        if (not self.connected) or self.state != self.STATE_IDLE: 
            self.logger.info("scheduled reconsile ignored. Connection is terminated %s", self)
            return

        assert self.state == self.STATE_IDLE
        self.state = self.STATE_GOSSIPING

        self._d = defer.Deferred()
        assert self.reqBuff == []
        assert self.outBuff == []
        assert self.dataBuff == []
        self.setName = name
        self.dataset = dataset
        self.appendfunc = appendfunc

        if self.curNode: self.curNode.unref()
        self.curNode = None
        
        n = dataset.getRootPartition()
        hsh = hashlib.sha1()
        
        hv = [str(x) for x in n.hash_vector]
        hv.sort()
        for x in hv:            
            hsh.update(x.encode("ascii"))

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
            self.reconcile_next()
            
    #
    # Main protocol steps
    #
    def handle_reconcile(self, name, digest):
        """
        Protocol start. Name specifies the set to be reconciled.
        """

        self.logger.debug("reconcile <- %s name=%s", self, name)
        assert self.state == self.STATE_IDLE
        self.state = self.STATE_GOSSIPING

        assert self.dataBuff == []
        assert self.reqBuff == []
        assert self.outBuff == []
        self.dataset, self.appendfunc = self.service.getSet(name)
        self.setName = name
                
        n = self.dataset.getRootPartition()
        hsh = hashlib.sha1()
        
        hv = [str(x) for x in n.hash_vector]
        hv.sort()
        for x in hv:            
            hsh.update(x.encode("ascii"))
        
        if digest == hsh.digest():
            self.logger.debug("digest_match->%s True", self)
            self.sendCommand("digest_match", True)
            self.state = self.STATE_IDLE
        else:
            self.logger.debug("digest_match->%s False", self)
            self.sendCommand("digest_match", False)
            self.reconcile_next()
    
    def reconcile_next(self):
        assert self.state == self.STATE_GOSSIPING, "state is %s should be %s" % (self.state, self.STATE_GOSSIPING)
        self.logger.debug("reconcile_next %s nodes=%d", self, len(self.nodes))
        
        self.reqBuff = []
        self.outBuff = list(self.dataset.items())
        self.logger.debug("reconcile_data_req->%s %d ", self, len(self.reqBuff))
        self.sendCommand("reconcile_data_req", self.reqBuff)        
        self.setTimeout()

class ServerProtocol(GossipBase):
    master = False
     

class ClientProtocol(GossipBase):
    master = True

    def __init__(self):
        
        self._timer = None
        self._d = None
        self.master = True
        self.taskQ = defer.DeferredQueue()                         
        GossipBase.__init__(self)  

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
        elif isinstance(task, str):
            if task == "dataRequest":
                self.sendCommand("dataRequest")
        else:
            raise ValueError("Unknown gossip task %r" % (task,))


        
            
            
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
    rate = 30.0
    TCPTimeout = 360.0
    
    rings: ring.RingSet
    group: "Group"
        
    def __init__(self, group):
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
        
        # Register all member in the gossip mesh
        for m in self.group.getAllMembers():
            self.evMemberNew("", m, fireflies.EV_CRASH_NEW)

        # Add all certificates, notes, and accusations to our data sets.
        for m in self.group.getAllMembers():
            self.cSet.insert(m.getCertificate())
            if m.getNote(): self.nSet.insert(m.getNote())
            for a in m.getAccusations(): self.aSet.add(a)

        #register to receive notification on group updates.
        self.group.registerEventHandler("member.crash", self.evMemberNew)        
        self.group.registerEventHandler("data.accusation", self.evData)
        self.group.registerEventHandler("data.note", self.evData)
        self.group.registerEventHandler("data.certificate", self.evData)        

        self.sFactory = fireflies.protocols.PeerServerFactory(self)
        self.sFactory.protocol = ServerProtocol
        self._task = LoopingCall(self.update)

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

    def evMemberNew(self, name, member, status):
        if status == fireflies.EV_CRASH_NEW:
            self.rings.insertItem(member)
            factory = fireflies.protocols.ReconnectingPeerFactory(member)
            factory.protocol = ClientProtocol
            factory.service = self
            self.neighborPool[member] = factory
    
    def getPeerFactoryFromProtocol(self, protocol):
        return self.neighborPool[protocol.other]

    def getMemberFactory(self, member):
        return self.neighborPool[member]

    def startService(self):
        assert not self.running
        Service.startService(self)

        address = self.group.getMe().address
        
        self.logger.info("Binding gossip to tcp %s:%d", address.host, address.port)
        self._port = fireflies.protocols.listen(address.port, self.sFactory, self.group.getTLSOptions(), interface=address.host)
        self.sFactory.doStart()

        interval = self.rate # / float(len(self.rings.getRings()))
        self._task.start(interval, now=False)
        
    def stopService(self):
        assert self.running
        address = self.group.getMe().address
        self.logger.info("Stop gossiping on tcp %s:%d", address.host, address.port)
        
        Service.stopService(self)
        #if self._task.running:
        self._task.stop()
        self._port.stopListening()

        for factory in self.connectedAsServer:
            if factory.isActive():
                factory.deactivate()
                self.active.remove(factory)
            else:
                if factory.connectedProtocol:
                    factory.connectedProtocol.hangup()                   
            factory.doStop()               
             
        for member, factory in list(self.neighborPool.items()):
            if factory.isActive():
                factory.deactivate()
                self.active.remove(factory)
            factory.doStop()   
        assert not self.active     
        self.sFactory.doStop()

        
    def update(self):
        outbound = self.rings.succ(self.group.getMe(), lambda x: x.isLive())
        outbound = [x for x in outbound if x != self.group.getMe()]
        inbound = self.rings.pred(self.group.getMe(), lambda x: x.isLive())
        inbound = [x for x in inbound if x != self.group.getMe()]

        # Deactivate outbound connections
        toDeactivate = [x for x in self.active if not x.member in outbound]
        
        for f in self.active:
            assert f.isActive()
            
        
        for factory in toDeactivate:
            factory.deactivate()
            self.active.remove(factory)
                
        # Activate new connections
        
        nrpeers = len(outbound)
        interval = self.rate / float((nrpeers or 1))
        
        for nr, him in enumerate(outbound):

            # Should never fail
            factory = self.neighborPool[him]
            
            if not factory.isActive(): 
                assert factory not in self.active
                self.active.add(factory)
                factory.activate()
            else:
                #pass
                assert factory in self.active
                if factory.connectedProtocol and factory.connectedProtocol.master and not factory.connectedProtocol.taskQ.pending:
                    reactor.callLater(nr * interval, factory.connectedProtocol.taskQ.put, self.cSet)
                    reactor.callLater(nr * interval, factory.connectedProtocol.taskQ.put, self.nSet)
                    reactor.callLater(nr * interval, factory.connectedProtocol.taskQ.put, self.aSet)
                                                
    def _failback(self, reason):
        self.logger.exception(reason)

    def peerConnected(self, factory):
        """Called when a new connection is accepted."""

        assert factory.connectedProtocol

        if factory.connectedProtocol.master:
            if not factory in self.active:
                self.logger.error("error: connect as master, but not active %s", factory.connectedProtocol)
                factory.connectedProtocol.hangup()
                return
            assert factory.isActive()
            factory.connectedProtocol.taskQ.put(self.cSet)
            factory.connectedProtocol.taskQ.put(self.nSet)
            factory.connectedProtocol.taskQ.put(self.aSet)
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