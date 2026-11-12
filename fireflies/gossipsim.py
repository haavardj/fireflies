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

import hashlib
import logging
from collections.abc import Callable
from typing import TYPE_CHECKING, Any

from twisted.application.service import Service
from twisted.internet import defer, tcp
from twisted.internet.task import LoopingCall
from twisted.python.failure import Failure

import fireflies
import fireflies.protocols
from fireflies import crypto, ring, setrecon
from fireflies.protocols import ReconnectingPeerFactory
from fireflies.setrecon import ReconSet, ZZ_p, node
from fireflies.state import Accusation, Member, Note
from fireflies.util import reactor, setServiceParent

if TYPE_CHECKING:
    from fireflies.group import Group

AnySet = ReconSet[Any]
AppendFunc = Callable[[Any], object]


PARTITION_FACTOR = 3
RECON_EXTRA = 5
MBAR=10
BITSIZE=256

setrecon.init(int(BITSIZE), int(MBAR))

NODE_STATUS_EMPTY = 0
NODE_STATUS_TERMINAL = 1
NODE_STATUS_NONTERMINAL = 2


# The old versions cached the value in elm.__zz_value_x but tested for it
# with hasattr under the unmangled name, so the cache never hit.

class NoteSet(ReconSet[Note]):

    def elmToZZp(self, elm: Note) -> ZZ_p:
        return setrecon.to_ZZ_p(setrecon.to_ZZFromBytes(elm.get_fingerprint()))

class AccusationSet(ReconSet[Accusation]):

    def elmToZZp(self, elm: Accusation) -> ZZ_p:
        return setrecon.to_ZZ_p(setrecon.to_ZZFromBytes(elm.get_fingerprint()))

class X509Set(ReconSet[crypto.Certificate]):

    def elmToZZp(self, elm: crypto.Certificate) -> ZZ_p:
        return setrecon.to_ZZ_p(setrecon.to_ZZFromBytes(elm.digest()))




class GossipBase(fireflies.protocols.FirefliesProtocol):
    STATE_IDLE = "idle"
    STATE_CONNECTING = "conn"
    STATE_HOLDING = "hold"
    STATE_GOSSIPING = "gossip"
    STATE_TERMINATED = "term"
    MAX_LENGTH = 100000000

    state = STATE_CONNECTING
    master = False

    # The set being reconciled, set by reconcile() or handle_reconcile().
    dataset: AnySet
    setName: str
    appendfunc: AppendFunc
    _d: "defer.Deferred[None] | None" = None

    def __init__(self) -> None:
        fireflies.protocols.FirefliesProtocol.__init__(self)
        self.curNode: node | None = None
        self.nodes: list[node | None] = []
        self.dataBuff: list[Any] = []
        self.reqBuff: list[ZZ_p] = []
        self.outBuff: list[Any] = []

    def idle(self) -> None:
        pass

    @property
    def gossipService(self) -> "Gossip":
        service = self.service
        assert isinstance(service, Gossip)
        return service

    def handle_reconcile_data(self, data: list[Any]) -> None:
        """Data from client.
        """
        assert self.nodes == []
        assert self.state == self.STATE_GOSSIPING
        self.logger.debug("reconcile_data <- %s %d", self, len(data))
        self.dataBuff.extend(data)

    def handle_reconcile_data_req(self, hashes: list[ZZ_p]) -> None:
        self.cancelTimeout()         
        assert self.state == self.STATE_GOSSIPING
        assert self.nodes == [], "%s %s %s" % (self.factory, self, self.nodes)
        
        self.logger.debug("reconcile_data_req <- %s %d", self, len(hashes))
        
        assert hashes == []

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

    def handle_reconcile_done(self) -> None:
        """Reconciliation is done."""

        assert not self.nodes
        self.cancelTimeout()
        self.logger.debug("reconcile_done <-%s ", self)
        assert self.state == self.STATE_GOSSIPING, "%s %s, invalid state %s" %(self.factory, self, self.state)
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
            assert self._d is not None
            self._d.callback(None)
            self.idle()


    #
    # Reconcile stuff
    #    
    def reconcile(self, name: str, dataset: AnySet, appendfunc: AppendFunc) -> "defer.Deferred[None] | None":

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

    def handle_digest_match(self, match: bool) -> None:
        assert self.state == self.STATE_GOSSIPING
        self.cancelTimeout()
        self.logger.debug("digest_match<-%s %s", self, bool(match))
        if match:
            assert self.nodes == [] and self.reqBuff == [] and self.dataBuff == [] and self.outBuff == []
            self.state = self.STATE_IDLE
            assert self._d is not None
            self._d.callback(None)
            self.idle()
        else:
            self.reconcile_next()
            
    #
    # Main protocol steps
    #
    def handle_reconcile(self, name: str, digest: bytes) -> None:
        """
        Protocol start. Name specifies the set to be reconciled.
        """

        self.logger.debug("reconcile <- %s name=%s", self, name)
        assert self.state == self.STATE_IDLE
        self.state = self.STATE_GOSSIPING

        assert self.dataBuff == []
        assert self.reqBuff == []
        assert self.outBuff == []
        self.dataset, self.appendfunc = self.gossipService.getSet(name)
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
    
    def reconcile_next(self) -> None:
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

    def __init__(self) -> None:
        
        self._timer = None
        self._d = None
        self.master = True
        self.taskQ: defer.DeferredQueue[AnySet | str] = defer.DeferredQueue()
        GossipBase.__init__(self)  

    def idle(self) -> None:
        d = self.taskQ.get()            
        d.addCallback(self.cb_nextTask)
        
    def cb_nextTask(self, task: "AnySet | str") -> None:

        if not self.connected or self.state == self.STATE_TERMINATED: 
            self.logger.info("scheduled task ignored as connection is terminated %s", self)
            return
        
        view = self.group.view
        if isinstance(task, NoteSet):
            self.reconcile("nSet", task, view.addNote)
        elif isinstance(task, AccusationSet):
            self.reconcile("aSet", task, view.addAccusation)
        elif isinstance(task, X509Set):
            self.reconcile("cSet", task, view.addCertificate)
        elif isinstance(task, str):
            if task == "dataRequest":
                self.sendCommand("dataRequest")
        else:
            raise ValueError("Unknown gossip task %r" % (task,))


        
            
            
def isEmptyNode(node: "node | None") -> bool:
    if node:
        if node.intree:
            if node.ref_count() < 2: node.printNode(0)
            assert node.ref_count() > 1, "refcount is %d shoud be 2. intree=%s" %(node.ref_count(), node.intree)
        else:
            if node.ref_count() == 0: node.printNode(0)
            assert node.ref_count() > 0, "refcount is %d shoud be >0. intree=%s" %(node.ref_count(), node.intree)
            
    return node is None or node.setsize == 0 or not node.intree


class Gossip(Service):
    
    name = "gossip"
    rate = 30.0
    TCPTimeout = 360.0
    
    rings: ring.RingSet[Member]
    group: "Group"
    _port: tcp.Port

    def __init__(self, group: "Group") -> None:
        self.group = group

        setServiceParent(self, group)
        self.rings = ring.RingSet()
        for x in range(self.group.nrGossipingRings()):
            self.rings.insertRing(ring.NameHashedRing(x))
    
        self.cSet = X509Set(PARTITION_FACTOR, RECON_EXTRA)
        self.nSet = NoteSet(PARTITION_FACTOR, RECON_EXTRA)
        self.aSet = AccusationSet(PARTITION_FACTOR, RECON_EXTRA)

        self.connectedAsServer: set[ReconnectingPeerFactory] = set()
        self.active: set[ReconnectingPeerFactory] = set()
        self.neighborPool: dict[Member, ReconnectingPeerFactory] = {}
        
        # Register all member in the gossip mesh
        for m in self.group.getAllMembers():
            self.evMemberNew("", m, fireflies.EV_CRASH_NEW)

        # Add all certificates, notes, and accusations to our data sets.
        for m in self.group.getAllMembers():
            self.cSet.insert(m.getCertificate())
            note = m.getNote()
            if note: self.nSet.insert(note)
            for a in m.getAccusations(): self.aSet.add(a)

        #register to receive notification on group updates.
        self.group.registerEventHandler("member.crash", self.evMemberNew)        
        self.group.registerEventHandler("data.accusation", self.evData)
        self.group.registerEventHandler("data.note", self.evData)
        self.group.registerEventHandler("data.certificate", self.evData)        

        self.sFactory = fireflies.protocols.PeerServerFactory(self)
        self.sFactory.peerProtocol = ServerProtocol
        self._task = LoopingCall(self.update)

    @property
    def logger(self) -> logging.Logger:
        return self.group.logger

    def evData(self, name: str, itm: Any, status: bool) -> None:
        sset: AnySet
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

    def evMemberNew(self, name: str, member: Member, status: int) -> None:
        if status == fireflies.EV_CRASH_NEW:
            self.rings.insertItem(member)
            factory = ReconnectingPeerFactory(member)
            factory.peerProtocol = ClientProtocol
            factory.service = self
            self.neighborPool[member] = factory
    
    def getMemberFactory(self, member: Member) -> ReconnectingPeerFactory:
        return self.neighborPool[member]

    def startService(self) -> None:
        assert not self.running
        Service.startService(self)

        address = self.group.getMe().address
        
        self.logger.info("Binding gossip to tcp %s:%d", address.host, address.port)
        self._port = fireflies.protocols.listen(address.port, self.sFactory, self.group.getTLSOptions(), interface=address.host)
        self.sFactory.doStart()

        interval = self.rate # / float(len(self.rings.getRings()))
        self._task.start(interval, now=False)
        
    def stopService(self) -> None:
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
             
        for factory in list(self.neighborPool.values()):
            if factory.isActive():
                factory.deactivate()
                self.active.remove(factory)
            factory.doStop()   
        assert not self.active     
        self.sFactory.doStop()

        
    def update(self) -> None:
        me = self.group.getMe()
        outbound = [x for x in self.rings.succ(me, lambda x: x.isLive())
                    if x is not None and x != me]

        # Deactivate outbound connections
        toDeactivate = [x for x in self.active if not x.member in outbound]
        
        for f in self.active:
            assert f.isActive()
            
        
        for factory in toDeactivate:
            factory.deactivate()
            self.active.remove(factory)
                
        # Activate new connections
        
        nrpeers = len(outbound)
        interval = self.rate / float(nrpeers or 1)
        
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
                proto = factory.connectedProtocol
                if isinstance(proto, ClientProtocol) and not proto.taskQ.pending:
                    reactor.callLater(nr * interval, proto.taskQ.put, self.cSet)
                    reactor.callLater(nr * interval, proto.taskQ.put, self.nSet)
                    reactor.callLater(nr * interval, proto.taskQ.put, self.aSet)
                                                
    def _failback(self, reason: Failure) -> None:
        self.logger.exception(reason)

    def peerConnected(self, factory: ReconnectingPeerFactory) -> None:
        """Called when a new connection is accepted."""

        proto = factory.connectedProtocol
        assert proto

        if proto.master:
            if not factory in self.active:
                self.logger.error("error: connect as master, but not active %s", proto)
                proto.hangup()
                return
            assert factory.isActive()
            assert isinstance(proto, ClientProtocol)
            proto.taskQ.put(self.cSet)
            proto.taskQ.put(self.nSet)
            proto.taskQ.put(self.aSet)
        else:
            self.connectedAsServer.add(factory)

    def peerDisconnected(self, factory: ReconnectingPeerFactory) -> None:
        if factory in self.connectedAsServer:
            self.connectedAsServer.remove(factory)

    
    def getSet(self, name: str) -> tuple[AnySet, AppendFunc]:
        s: AnySet
        f: AppendFunc
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