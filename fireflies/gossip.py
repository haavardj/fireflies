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
## $Id: gossip.py,v 1.16 2007/08/14 07:47:12 haavardj Exp $
##                
######################################################################

import logging
from twisted.internet.protocol import Factory, Protocol, ClientFactory, ServerFactory
from twisted.protocols.basic import Int32StringReceiver
from twisted.internet import reactor, task, defer
from Crypto.Hash import MD5
import sha
import copy, sys
import M2Crypto
from zope.interface import Interface
from twisted.application.service import Service
import fireflies
from fireflies.packer import FirefliesPacker, FirefliesUnpacker
from fireflies import setrecon
from fireflies.view import MemberRings
from fireflies.state import Note, Accusation, Member
from fireflies.crypto import identityFromCertificate

PARTITION_FACTOR = 3
RECON_EXTRA = 5
MBAR=10
BITSIZE=160

setrecon.init(BITSIZE, MBAR)


NODE_STATUS_EMPTY = 0
NODE_STATUS_TERMINAL = 1
NODE_STATUS_NONTERMINAL = 2

DATA_CERTIFICATE_ID = 0x1
DATA_NOTE_ID = 0x2
DATA_ACCUSATION_ID = 0x3

DUBLICATEPARTNERS = False

cmd2code = {
    'partner': 0x1,
    'accepted': 0x4,
    'gossip': 0x5,
    'authenticate': 0x6,
    'redirect': 0x7,
    'note': 0x8,
    'accusation': 0x9,
    'certificate': 0x10,
    'version': 0x11,

    'reconcile': 0x20,
    'reconcile_next': 0x21,
    'reconcile_next_req': 0x22,
    'reconcile_done': 0x27,
    'reconcile_data': 0x28,
    'reconcile_data_req': 0x29,
    'digest_match': 0x2F
    }

code2cmd = {}
for k, v in cmd2code.items():
    code2cmd[v] = k


class ISetReconItem(Interface):
    def fingerprint(self):
        """Return unique object fingerprint string."""

    def getItem(self):
        """Return wrapped item."""


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


class Gossip(Service):
    def __init__(self, group, byzantineToleranceNumber=7, rate=30.0, TCPTimeout=360.0):
        
        self.setServiceParent(group)
        isinstance(group, fireflies.group.Group)
        isinstance(self.parent, fireflies.group.Group)

        self.rate = rate
        self.byzantineToleranceNumber = byzantineToleranceNumber
        
        self.rings = MemberRings(byzantineToleranceNumber)
        self.logger = logging.getLogger()        
        self.sFactory = GossipServerFactory(self, TCPTimeout)
        self.cFactory = GossipClientFactory(self, rate, TCPTimeout)    

        self.cSet = X509Set(PARTITION_FACTOR, RECON_EXTRA)
        self.nSet = NoteSet(PARTITION_FACTOR, RECON_EXTRA)
        self.aSet = AccusationSet(PARTITION_FACTOR, RECON_EXTRA)

    def evDataAccusation(self, name, itm, status):
        if name == "data.accusation": set = self.aSet
        elif name == "data.note": set = self.nSet
        elif name == "data.certificate": set = self.cSet
        else: raise RuntimeError, "Invalid data event", name
        
        if status == True:
            set.append(itm)
        else:
            set.remove(itm)
            
    def evMemberNew(self, name, member, status):
        if status == fireflies.EV_CRASH_NEW:
            self.rings.insert(member)
            self.logger.debug("adding %s to gossip rings", member)

    def startService(self):
        Service.startService(self)

        # Register all member in the gossip mesh
        for m in self.parent.view.getAllMembers():
            self.rings.insert(m)

        # Add all certificates, notes, and accusations to our data sets.
        for m in self.parent.view.getAllMembers():
            self.cSet.append(m.getCertificate())
            if m.getNote(): self.nSet.append(m.getNote())
            for a in m.getAccusations(): self.aSet.append(a)

        #register to receive notification on group updates.
        self.parent.registerEventHandler("member.crash", self.evMemberNew)        
        self.parent.registerEventHandler("data.accusation", self.evDataAccusation)
        self.parent.registerEventHandler("data.note", self.evDataAccusation)
        self.parent.registerEventHandler("data.certificate", self.evDataAccusation)
                
        host, port = self.parent.getMe().getAddress().split(":")
        port = int(port)
        self.logger.info("Binding gossip to tcp %s:%d", host, port)
        self._port = reactor.listenTCP(port, self.sFactory, interface=host)
        self.sFactory.doStart()
        self.cFactory.doStart()

        def _d():            
            self._task = task.LoopingCall(self.cFactory.update)
            self._task.start(self.rate/len(self.rings)).addErrback(self._failback)
                             
        reactor.callLater(0.1, _d)
        
    def stopService(self):
        Service.stopService(self)
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
            p = FirefliesPacker()

            p.pack_fstring(1, chr(cmd2code[cmd]))

            if cmd == "partner":
                nr, = args
                p.pack_uint(nr)

            elif cmd == "authenticate":
                crt, note = args
                p.pack_cert(crt)
                p.pack_note(note)

            elif cmd == "redirect":
                crt, note = args
                p.pack_cert(crt)
                p.pack_note(note)

            elif cmd == "version":
                major, minor, patchl = args
                p.pack_short(major)
                p.pack_short(minor)
                p.pack_short(patchl)

            elif cmd == "reconcile":
                name, digest = args
                p.pack_string(name)
                p.pack_string(digest)

            elif cmd == "digest_match":
                match, = args
                p.pack_bool(match)

            elif cmd == "reconcile_next":
                node_type, hash_vector, extra_hashes, setsize = args
                p.pack_uint(node_type)

                if node_type > 0:
                    p.pack_vec_ZZ_p(hash_vector)
                if node_type > 1:
                    p.pack_vec_ZZ_p(extra_hashes)
                    p.pack_uint(setsize)

            elif cmd == "reconcile_extra":
                vec, size = args
                p.pack_vec_ZZ_p(vec)
                p.pack_uint(size)

            elif cmd == "reconcile_data":
                data, = args
                if isinstance(data, Accusation):
                    p.pack_uint(DATA_ACCUSATION_ID)
                    p.pack_accusation(data)
                elif isinstance(data, Note):
                    p.pack_uint(DATA_NOTE_ID)
                    p.pack_note(data)
                elif isinstance(data, M2Crypto.X509.X509):
                    p.pack_uint(DATA_CERTIFICATE_ID)
                    p.pack_cert(data)
                else:
                    raise ValueError, "Unknown data type", data
                # note, accus, or cert

            elif cmd in ["reconcile_data_req",]:
                vec, = args
                l = len(vec)
                p.pack_uint(l)
                for x in range(l):                    
                    p.pack_ZZ(vec[x].rep())
                    
            elif cmd in ["reconcile_next_req",
                         "reconcile_done",
                         "accepted"]:
                # No arguments.
                pass                
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

            elif cmd == "authenticate":
                args = (p.unpack_cert(), p.unpack_note())

            elif cmd == "redirect":
                args = (p.unpack_cert(), p.unpack_note())

            elif cmd == "version":
                args = (p.unpack_short(),
                        p.unpack_short(),
                        p.unpack_short())

            elif cmd == "reconcile":
                args = (p.unpack_string(),
                        p.unpack_string()
                        )
            elif cmd == "digest_match":
                args = (bool(p.unpack_bool()),)

            elif cmd == "reconcile_next":
                node_type = p.unpack_uint()
                hash_vector = None
                extra_hashes = None
                setsize = -1
                if node_type > 0:
                    hash_vector = p.unpack_vec_ZZ_p()
                if node_type > 1:
                    extra_hashes = p.unpack_vec_ZZ_p()
                    setsize = p.unpack_uint()
                args = (node_type,
                        hash_vector,
                        extra_hashes,
                        setsize)

            elif cmd == "reconcile_data":
                t = p.unpack_uint()
                if t == DATA_ACCUSATION_ID:
                    args = (p.unpack_accusation(),)
                elif t == DATA_NOTE_ID:
                    args = (p.unpack_note(),)
                elif t == DATA_CERTIFICATE_ID:
                    args = (p.unpack_cert(),)
                else:
                    raise ValueError("Unknown data.")

            elif cmd in ["reconcile_data_req"]:
                l = p.unpack_uint()
                r = []
                for x in range(l):
                    r.append(setrecon.to_ZZ_p(p.unpack_ZZ()))
                    
                args = (r,)

                    
            elif cmd in ["reconcile_done",
                         "accepted"]:

                # No arguments.
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
        self._timer = reactor.callLater(self.factory._timeout, self.timeout)

    def cancelTimeout(self):
        assert self._timer and self._timer.active()        
        self._timer.cancel()
        self._timer = None


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

    def __init__(self):        
        self.other = None
        self.state = self.STATE_CONNECTING
        self._stop = False
        self._timer = None
        self.curNode = None
        self.nodes = []
        self.master = False
        self.dataBuff = []
        self.reqBuff = []
        self.outBuff = []
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

    def handle_authenticate(self, crt, note):
        view = self.factory.service.parent.view
        pprint = view.pprint
        assert isinstance(crt, M2Crypto.X509.X509)
        assert isinstance(note, Note)

        

        if note.identity != identityFromCertificate(crt):
            self.logger.warning("authenticate<- %s Error. Note and crt identity do not match.", self)
            self.hangup()
        else:
            self.logger.debug("authenticate<- %s %s", self, pprint(crt))
            view.addCertificate(crt)
            view.addNote(note)
            self.other = view.sn2peer[identityFromCertificate(crt)]
            self.setTimeout()
            self.sendCommand("authenticate", self.factory.service.parent.getMe().getCertificate(), self.factory.service.parent.getMe().getNote())

    def redirect(self, peer):
        #self.factory.peer.view.stats.redirect += 1
        pprint = self.factory.service.parent.view.pprint
        self.logger.debug("redirect-> %s to %s", self, pprint(peer.getCertificate()))
        self.setTimeout()
        self.sendCommand("redirect", peer.getCertificate(), peer.getNote())

    def accept(self):
        self.logger.debug("accepted-> %s", self)
        self.sendCommand("accepted")
        self.state = self.STATE_IDLE
        
    def handle_partner(self, ringNr):
        self.cancelTimeout()
        view = self.factory.service.parent.view
        pprint = view.pprint
        self.logger.debug("partner<- %s on %d", self, ringNr)
        self.ringNr = ringNr
        reactor.callLater(0, self.factory.clientConnected, self, ringNr)


    #
    # Recon server stuff.
    #



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
        self.appendfunc(self.dataBuff)
        self.dataBuff = []



        
class ClientProtocol(GossipBase):

    def __init__(self, peer, ringNr):

        self.other = peer
        self.ringNr = ringNr
        self.state = self.STATE_CONNECTING
        self._timer = None
        self.timestamp = 0
        self._d = None
        self.curNode = None
        self.nodes = []
        self.master = True
        self.dataBuff = []
        self.reqBuff = []
        self.outBuff = []

    def connectionMade(self):
        self.factory.peer.view.stats.tcpOpen += 1
        self.sendCommand("version", *fireflies.protocol_version)
        self.setTimeout()
        #self._sendAuthenticate()

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
            self.logger.warning("version<- %s Version error. Other have an old version. Exiting.", self)
            
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
        self.sendCommand("authenticate", crt, note)
        
    def handle_authenticate(self, crt, note):
        view = self.factory.peer.view
        pprint = self.factory.peer.view.pprint
        self.cancelTimeout()
        
        if identityFromCertificate(crt) != self.other.getIdentity():
            self.logger.warning("authenticate<- %s Error. Expected %s. Got  %s.", self, pprint(self.other.getCertificate()), pprint(crt))
            self.hangup()
            return

        if  note.identity != self.other.getIdentity():
            self.logger.warning("authenticate<- %s Error. Note and crt identity do not match.", self)
            self.hangup()
            return

        self.logger.debug("authenticate<- %s OK", self)
        self.factory.view.addCertificate(crt)
        self.factory.view.addNote(note)        
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
        self.appendfunc(self.dataBuff)
        self.dataBuff = []        
        self._d.callback(None)


            
def isEmptyNode(node):
    if node:
        if node.intree:
            if node.ref_count() < 2: node.printNode(0)
            assert node.ref_count() > 1, "refcount is %d shoud be 2. intree=%s" %(node.ref_count(), node.intree)
        else:
            if node.ref_count() == 0: node.printNode(0)
            assert node.ref_count() > 0, "refcount is %d shoud be >0. intree=%s" %(node.ref_count(), node.intree)
            
    return bool(   (node == None) or (node.setsize==0) or (node.intree == False))
        
class GossipServerFactory(ServerFactory):

    protocol = ServerProtocol

    def __init__(self, service, timeout):
        if not isinstance(service, Gossip): raise ValueError
        self._timeout = timeout
        self.service = service
        self.logger = logging.getLogger(service.parent.getMe().getAddress())
        self.cons = [None] * service.byzantineToleranceNumber

    def startFactory(self):
        pass

    def stopFactory(self):
        for c in self.cons:
            if not c: continue
            c.hangup()
        self.cons = [None] * service.byzantineToleranceNumber

    def getSet(self, name):
        if name == "cSet":
            s = self.service.cSet
            f = lambda x: map(self.service.parent.view.addCertificate, x)
        elif name == "nSet":
            s = self.service.nSet
            f = lambda x: map(self.service.parent.view.addNote, x)

        elif name == "aSet":
            s = self.service.aSet
            f = lambda x: map(self.service.parent.view.addAccusation, x)
        else:
            raise ValueError("No such set.")
        return s, f


    def clientConnected(self, protocol, rnr):
        """Client connected."""

        me = self.service.parent.getMe()
        him = protocol.other
        hisPartner = self.service.rings[rnr].succ(him)
        while hisPartner.isFailed():
            hisPartner = self.service.rings[rnr].succ(hisPartner)

        cp = self.cons[rnr]
        if hisPartner.getIdentity() != me.getIdentity():
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
                if (cp.other.id == him.id) or self.service.rings[rnr].isBetween(cp.other, him, me):
                    cp.hangup()
                    self.cons[rnr] = protocol
                    protocol.accept()
                else:
                    # Our current connected client is closer to the
                    # connecting client than we are.
                    protocol.redirect(cp.other)
                    #protocol.hangup()

    def buildProtocol(self, address):
        p = ServerFactory.buildProtocol(self, address)
        p.logger = self.logger
        return p



    
class GossipClientFactory(ClientFactory):

    def __init__(self, service, roundtime, timeout=420):
        self._timeout = timeout
        self._roundtime = roundtime
        if not isinstance(service, Gossip): raise ValueError
        self.service = service
        self.peer = service.parent.getMe() 
        self.view = service.parent.view
        
        self.connections = [None] * service.byzantineToleranceNumber
        self._initializing= {}        

        self.logger = logging.getLogger(service.parent.getMe().getAddress())
        self._last = -1 % service.byzantineToleranceNumber
        self._task = None

    def startFactory(self):
        if self._task: return

    def stopFactory(self):

        for c in self.connections:
            if not c: continue
            c.hangup()

        for n,v in self._initializing.items():
            v.hangup()
            
        self.connections = [None] * self.service.byzantineToleranceNumber
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
        return (self.peer.getCertificate(), self.peer.getNote())
        
    def connect(self, peer, ringNr):
        if peer.getAddress() in self._initializing:
            raise Exception, "Allready connecting to this guy"
        
        host, port = peer.getAddress().split(":")
        port = int(port)
        prot = ClientProtocol(peer, ringNr)
        prot.logger = self.logger
        self._initializing[peer.getAddress()] = prot
        
        cc = self.connections[ringNr]
        if cc and cc.state != cc.STATE_TERMINATED:
            cc.hangup()
        self.connections[ringNr] = prot
        
        reactor.connectTCP(host, port, self)

    def reconcile(self, protocol):

        def _f(reason):
            self.logger.error("Reconcile failed %s", reason)
        
        def _2(result):
            d = protocol.reconcile("aSet", self.service.aSet, lambda x: map(self.peer.view.addAccusation, x))
            d.addErrback(_f)

            #for m in self.peer.view.pRing:
            #    assert m.getNote()
            
        def _1(result):
            d = protocol.reconcile("nSet", self.service.nSet, lambda x: map(self.peer.view.addNote, x))
            d.addCallback(_2)
            d.addErrback(_f)
            
        d = protocol.reconcile("cSet", self.service.cSet, lambda x: map(self.peer.view.addCertificate, x))
        d.addCallback(_1)
        d.addErrback(_f)
        

    def serverConnected(self, protocol):
        self.reconcile(protocol)

    def buildProtocol(self, address):
        id = "%s:%d" % (address.host, address.port) 
        p = self._initializing[id]
        del self._initializing[id]
        p.factory = self
        p.logger = self.logger
        return p

                
    def update(self):

        nrRings = len(self.service.rings)
        x = self._last = (self._last + 1) % nrRings
        
        # Purge initializing protocols that terminated.
        for k,v in self._initializing.items():
            if v.state == v.STATE_TERMINATED:
                del self._initializing[k]

        cg = self.connections[x]

        ring = self.service.rings[x]
        partnerOnX = ring.succ(self.peer)
        while partnerOnX.isFailed():
            partnerOnX = ring.succ(partnerOnX)
            if partnerOnX == self.service.parent.getMe():
                break

        if partnerOnX == self.service.parent.getMe():
            # No other peers in ring. Leave things as they are.
            pass
        else:
            if (not cg) or (cg.state == cg.STATE_TERMINATED):
                # We do not have an active connection on this ring, so
                # make one.
                ids = map(lambda t: t.other.getIdentity(), filter(None, self.connections[0:x]))
                if (DUBLICATEPARTNERS) or (partnerOnX.getIdentity() not in ids):
                    if not partnerOnX.getAddress() in self._initializing:
                        self.connect(partnerOnX, x)
                else:
                    self.connections[x] = None
            else:
                # We have an active connection on the current ring. We
                # can either close the current one and connect to a
                # new member, or keep the current connection.

                if partnerOnX != cg.other:
                    cg.hangup()
                    if not partnerOnX.getAddress() in self._initializing:
                        self.connect(partnerOnX, x)
                elif cg.state == cg.STATE_IDLE:
                    self.reconcile(cg)
                else:
                    pass

        

