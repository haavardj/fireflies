# -*- coding: iso-8859-1 -*-
######################################################################
## Filename:      gossip3.py
## Description:   Fireflies set-recon based gossip protocol 
## Author:        Håvard Dagenborg Johansen <haavardj@cs.uit.no>
## Modified at:   Mon Jan 23 16:12:37 2006
## Modified by:   Håvard Dagenborg Johansen <haavardj@cs.uit.no>
## Licence:       GPL (see the LICENSE file).
##  
##         Copyright© 2006, University of Tromsø (Norway)
##                
## $Id: gossip3.py,v 1.4 2007/07/13 13:59:27 haavardj Exp $
##                
######################################################################


import logging
from packer import FirefliesPacker, FirefliesUnpacker

from twisted.internet.protocol import Factory, Protocol, ClientFactory, ServerFactory
from twisted.protocols.basic import Int32StringReceiver
from twisted.internet import reactor, task, defer
from Crypto.Hash import MD5
import sha
import fireflies, members, time, cert, setrecon
from cert import TimestampMixin
import copy, sys

setrecon.init(fireflies.defaultConfig['BITSIZE'], fireflies.defaultConfig['MBAR'])

NODE_STATUS_EMPTY = 0
NODE_STATUS_TERMINAL = 1
NODE_STATUS_NONTERMINAL = 2

DATA_CERTIFICATE_ID = 0x1
DATA_NOTE_ID = 0x2
DATA_ACCUSATION_ID = 0x3


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
    'reconcile_hash_vector': 0x23,
    'reconcile_hash_vector_req': 0x24,    
    'reconcile_extra': 0x25,
    'reconcile_extra_req': 0x26,
    'reconcile_done': 0x27,
    'reconcile_data': 0x28,
    'reconcile_data_req': 0x29,
    'reconcile_data_diff_req': 0x2A,
    'reconcile_add_children': 0x2B,
    'reconcile_next_v2': 0x2C,
    'reconcile_next_v2_req': 0x2D,
    'reconcile_data_diff_done': 0x2E,
    'digest_match': 0x2F

    }

code2cmd = {}
for k, v in cmd2code.items():
    code2cmd[v] = k



DUBLICATEPARTNERS = False
LOCKOUT = True

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
                node_type, = args
                p.pack_uint(node_type)

            elif cmd == "reconcile_next_v2":
                node_type, hash_vector, extra_hashes, setsize = args
                p.pack_uint(node_type)
                p.pack_vec_ZZ_p(hash_vector)
                p.pack_vec_ZZ_p(extra_hashes)
                p.pack_uint(setsize)

            elif cmd == "reconcile_extra":
                vec, size = args
                p.pack_vec_ZZ_p(vec)
                p.pack_uint(size)

            elif cmd == "reconcile_data":
                data, = args
                if isinstance(data, members.Accusation):
                    p.pack_uint(DATA_ACCUSATION_ID)
                    p.pack_accusation(data)
                elif isinstance(data, members.Note):
                    p.pack_uint(DATA_NOTE_ID)
                    p.pack_note(data)
                elif isinstance(data, cert.MemberCertificate):
                    p.pack_uint(DATA_CERTIFICATE_ID)
                    p.pack_cert(data)
                else:
                    raise ValueError("Unknown data type")
                # note, accus, or cert


            elif cmd in ["reconcile_hash_vector",
                         "reconcile_data_req",
                         "reconcile_data_diff_req"]:
                vec, = args
                p.pack_vec_ZZ_p(vec)
                    
            elif cmd in ["reconcile_next_req",
                         "reconcile_next_v2_req",
                         "reconcile_hash_vector_req",
                         "reconcile_extra_req",
                         "reconcile_done",
                         "reconcile_data_diff_done",
                         "reconcile_add_children",
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
                args = (p.unpack_bool(),)

            elif cmd == "reconcile_next":
                args = (p.unpack_uint(),)

            elif cmd == "reconcile_next_v2":
                args = (p.unpack_uint(),
                        p.unpack_vec_ZZ_p(),
                        p.unpack_vec_ZZ_p(),
                        p.unpack_uint())

            elif cmd == "reconcile_extra":
                args = (p.unpack_vec_ZZ_p(), p.unpack_uint())

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

            elif cmd in ["reconcile_hash_vector",
                         "reconcile_data_req",
                         "reconcile_data_diff_req"]:
                args = (p.unpack_vec_ZZ_p(),)

                    
            elif cmd in ["reconcile_next_req",
                         "reconcile_next_v2_req",
                         "reconcile_hash_vector_req",
                         "reconcile_extra_req",
                         "reconcile_done",
                         "reconcile_data_diff_done",
                         "reconcile_add_children",
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
            return "%s,%s" % (self.factory.peer.view.pprint(self.other.note), self.state) 
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




class ServerProtocol(GossipBase):

    def __init__(self):        
        self.other = None
        self.state = self.STATE_CONNECTING
        self._stop = False
        self._timer = None
        self.curNode = None
            
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
        def __die():
            sys.exit(-1)
        
        if (major, minor, patchlevel) > fireflies.protocol_version:
            self.logger.warning("authenticate<- %s Version error. I have an old version. Exiting.")
            reactor.callLater(10,__die)
        elif (major, minor, patchlevel) < fireflies.protocol_version:
            self.logger.warning("authenticate<- %s Version error. Other have an old version. Exiting.")
        self.sendCommand("version", *fireflies.protocol_version)

    def handle_authenticate(self, crt, note):
        view = self.factory.peer.view
        pprint = view.pprint

        if note.identity != crt.identity:
            self.logger.warning("authenticate<- %s Error. Note and crt identity do not match.", self)
            self.hangup()
        else:
            self.logger.debug("authenticate<- %s %s", self, pprint(crt))
            view.addCerts(crt)
            view.addNotes(note)
            self.other = view.sn2peer[crt.identity]
            self.setTimeout()
            self.sendCommand("authenticate", self.factory.peer.cert, self.factory.peer.note)

    def redirect(self, peer):
        self.factory.peer.view.stats.redirect += 1
        pprint = self.factory.peer.view.pprint
        self.logger.debug("redirect-> %s to %s", self, pprint(peer.cert))
        self.setTimeout()
        self.sendCommand("redirect", peer.cert, peer.note)

    def accept(self):
        self.logger.debug("accepted-> %s", self)
        self.sendCommand("accepted")
        self.state = self.STATE_IDLE
        
    def handle_partner(self, ringNr):
        self.cancelTimeout()
        view = self.factory.peer.view
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

        self.databuff = []
        self.set, self.appendfunc = self.factory.getSet(name)

        if self.curNode: self.curNode.unref()
        self.curNode = None
        self.nodes = []
        
        n = self.set.getRootPartition()
        hsh = sha.new()
        for x in n.hash_vector:
            hsh.update(str(x))

        if digest == hsh.digest():
            self.logger.debug("digest_match->%s True hash=%s", self, n.hash_vector)
            self.sendCommand("digest_match", True)
        else:
            n.ref()
            self.nodes = [n]
            self.logger.debug("digest_match->%s False hash=%s", self, n.hash_vector)
            self.sendCommand("digest_match", False)
        
    
    def handle_reconcile_next_req(self):
        """ Move to next partition.
        Sends:
         - reconcile_next (node_status)
         """

        assert False
        assert self.state == self.STATE_GOSSIPING, "state is %s should be %s" %(self.state, self.STATE_GOSSIPING)
        self.logger.debug("reconcile_next_req<-%s ", self)

        if self.curNode: self.curNode.unref()
        self.curNode = self.nodes.pop(0)
        
        if isEmptyNode(self.curNode):
            nt = NODE_STATUS_EMPTY
        elif self.curNode.isTerminal():
            nt = NODE_STATUS_TERMINAL
        else:
            nt = NODE_STATUS_NONTERMINAL

        self.logger.debug("reconcile_next->%s type=%d", self, nt)
        self.sendCommand("reconcile_next", nt)

    def handle_reconcile_next_v2_req(self):
        """ Move to next partition.
        Sends:
         - reconcile_next (node_status)
         """
        self.logger.debug("reconcile_next_v2_req<-%s", self)
        assert self.state == self.STATE_GOSSIPING, "state is %s should be %s" %(self.state, self.STATE_GOSSIPING)
        if self.curNode: self.curNode.unref()
        self.curNode = self.nodes.pop(0)

        if isEmptyNode(self.curNode):
            nt = NODE_STATUS_EMPTY
            hv = setrecon.vec_ZZ_p()
            ev = setrecon.vec_ZZ_p()
            ss = 0
        elif self.curNode.isTerminal():
            nt = NODE_STATUS_TERMINAL
            hv = self.curNode.hash_vector
            ev = self.curNode.extra_hashes
            ss = self.curNode.setsize
        else:
            nt = NODE_STATUS_NONTERMINAL
            hv = self.curNode.hash_vector
            ev = self.curNode.extra_hashes
            ss = self.curNode.setsize

        self.logger.debug("reconcile_next_v2->%s type=%d", self, nt)
        self.sendCommand("reconcile_next_v2", nt, hv, ev, ss)


    def handle_reconcile_hash_vector_req(self):
        """Request for the current hash vector.

        Sends:
         - reconcile_hash_vector (hash_vector)
        """
        assert False
        assert self.state == self.STATE_GOSSIPING
        self.sendCommand("reconcile_hash_vector", self.curNode.hash_vector)


    def handle_reconcile_extra_req(self):
        """Request for extra node information.

        Sends:
         - reconcile_extra( extra_hashes, setsize)
        """
        assert False
        assert self.state == self.STATE_GOSSIPING
        
        self.sendCommand("reconcile_extra", self.curNode.extra_hashes, self.curNode.setsize)


    def handle_reconcile_done(self):
        """Reconciliation is done.

        Sends:
         - reconcile_done ()
        """
        self.logger.debug("reconcile_done<-%s", self)
        assert self.state == self.STATE_GOSSIPING, "%s %s, invalid state %s" %(self.factory.peer, self, self.state)
        assert self.nodes == []
        self.logger.debug("reconcile_done->%s", self)
        self.sendCommand("reconcile_done")
        self.state = self.STATE_IDLE
        self.appendfunc(self.databuff)
        self.databuff = []

    def handle_reconcile_add_children(self):
        """Reconciliation failed. Add all sub-partitions.
        """
        self.logger.debug("reconcile_add_children<-%s", self)
        assert self.state == self.STATE_GOSSIPING
        c = []
        for x in range(self.set._recon.p):
            if not self.curNode.intree or self.curNode.hasChild(x)==False:
                c.append(None)
            else:
                n = self.curNode.getChild(x)
                n.ref()
                c.append(n)
        self.nodes = c + self.nodes

    #
    # Data transmission
    #

    def handle_reconcile_data(self, data):
        """Data from client.
        """

        self.logger.debug("reconcile_data<-%s %s", self, data)
        assert self.state == self.STATE_GOSSIPING
        self.databuff.append(data)


    def handle_reconcile_data_req(self, hashes):
        """Request for the data specified by hashes.

        Sends:
         - reconcile_data (data) (multiple)
         """
        self.logger.debug("reconcile_data_req<-%s", self)
        assert self.state == self.STATE_GOSSIPING
        if not self.curNode.intree: return
        for x in hashes:
            try:
                d = self.set.getByInternal(x)
            except KeyError, e:
                self.logger.warning("reconcile_data_req<-%s elm %s removed", self, x)
            else:
                self.sendCommand("reconcile_data", self.set.getByInternal(x))

    def handle_reconcile_data_diff_req(self, hashes):
        """Returns all data in this partition that are not in hashes.

        Sends:
         - reconcie_data (data) (multiple)
        """
        self.logger.debug("reconcile_data_diff_req<-%s", self)
        assert self.state == self.STATE_GOSSIPING
        if not isEmptyNode(self.curNode):
            assert self.curNode.ref_count() > 0
            
            td = self.curNode.terminal_data()
            hisdiff = setrecon.difference_set(hashes, td)
            mydiff = setrecon.difference_set(td, hashes)

            for x in hisdiff:
                try:
                    d = self.set.getByInternal(x)
                except KeyError, e:
                    self.logger.warning("reconcile_data->%s %s removed", self, x)
                else:
                    self.sendCommand("reconcile_data", self.set.getByInternal(x))

            if mydiff.length() > 0:
                self.sendCommand("reconcile_data_req", mydiff)

            
        self.sendCommand("reconcile_data_diff_done")

        




        
class ClientProtocol(GossipBase):

    def __init__(self, peer, ringNr):

        self.other = peer
        self.ringNr = ringNr
        self.state = self.STATE_CONNECTING
        self._timer = None
        self.timestamp = 0
        self._d = None
        self.curNode = None

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
            self.logger.warning("authenticate<- %s Version error. I have an old version. Exiting.")
            sys.exit(-1)
        elif (major, minor, patchlevel) < fireflies.protocol_version:
            self.logger.warning("authenticate<- %s Version error. Other have an old version. Exiting.")
            
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
        
        if crt.identity != self.other.id:
            self.logger.warning("authenticate<- %s Error. Expected %s. Got  %s.", self, pprint(self.other.cert), pprint(crt))
            self.hangup()
            return

        if  note.identity != self.other.id:
            self.logger.warning("authenticate<- %s Error. Note and crt identity do not match.", self)
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




    #
    # Reconcile stuff
    #
    
    def reconcile(self, name, set, appendfunc):

        assert self.state == self.STATE_IDLE
        self.state = self.STATE_GOSSIPING

        self._d = defer.Deferred()
        self.databuff = []
        self.set = set
        self.appendfunc = appendfunc
        n = set.getRootPartition()
        n.ref()
        self.nodes = [n]
        if self.curNode: self.curNode.unref()
        self.curNode = None

        hsh = sha.new()

        for x in n.hash_vector:
            hsh.update(str(x))
        
        self.logger.debug("reconcile->%s %s hash=%s", self, name, n.hash_vector)                
        self.sendCommand("reconcile", name, hsh.digest())        
        self.setTimeout()
        return self._d

    def handle_digest_match(self, match):

        self.cancelTimeout()
        self.logger.debug("digest_match<-%s %s", self, match)
        if match:
            while self.nodes:
                p = self.nodes.pop()
                p.unref()

        self.reconcile_next()

    def reconcile_next(self):
        """Moves to the next partition available partition, or marks
        the reconciliation as done if no more partitions are available.

        Sends
        -- reconciliation_done ()
        -- reconciliation_next_req ()
        """
        assert self.state == self.STATE_GOSSIPING, "state is %s should be %s" %(self.state, self.STATE_GOSSIPING)

        if self.nodes == []:
            self.setTimeout()
            self.logger.debug("reconcile_done->%s", self)
            self.sendCommand("reconcile_done")
        else:
            self.setTimeout()
            if self.curNode: self.curNode.unref()
            self.curNode = self.nodes.pop(0)
            self.logger.debug("reconcile_next_v2_req->%s", self)
            self.sendCommand("reconcile_next_v2_req")        

            
    def handle_reconcile_next(self, nodeType):
        """Start reconciling of the current partition.
    
        Sends:
         - reconcile_data (data)
         - reconcile_data_diff_req ([])
         - reconcile_hash_vector_req () 
        """
        assert False
        assert self.state == self.STATE_GOSSIPING
        myNode = self.curNode        
        if isEmptyNode(myNode) and nodeType==NODE_STATUS_EMPTY:
            self.reconcile_next()
            return

        if nodeType==NODE_STATUS_EMPTY:
            td = myNode.terminal_data()
            for x in td:
                self.logger.debug("reconcile_data->%s %s", self, str(x))
                try:
                    self.sendCommand("reconcile_data", self.set.getByInternal(x))
                except KeyError:
                    self.logger.warning("reconcile_data->%s skipping %s",self, x)
            self.reconcile_next()
            return

        if isEmptyNode(myNode):
            self.logger.debug("reconcile_data_diff_req->%s %s", self, str([]))
            self.sendCommand("reconcile_data_diff_req", setrecon.vec_ZZ_p())
            self.reconcile_next()
            return

        # Build others node
        self.otherNode = self.set.create_node()
        if nodeType == NODE_STATUS_TERMINAL:
            self.otherNode.node_type = 1
        else:
            self.otherNode.node_type = 0

        self.logger.debug("reconcile_hash_vector_req->%s", self)
        self.sendCommand("reconcile_hash_vector_req")


    def handle_reconcile_next_v2(self, nodeType, hash_vector, extra_hashes, size):
        """Start reconciling of the current partition.
    
        """

        self.cancelTimeout()
        
        self.logger.debug("reconcile_next_v2<-%s nt=%s  hv=%s  eh=%s ss=%s",
                          self,
                          nodeType,
                          hash_vector,
                          extra_hashes,
                          size)
        
        assert self.state == self.STATE_GOSSIPING
        myNode = self.curNode

        # Both nodes are empty means that we are done.
        if isEmptyNode(myNode) and (nodeType == NODE_STATUS_EMPTY):
            self.reconcile_next()
        
        #His node is empty, send all terminal data.
        elif nodeType==NODE_STATUS_EMPTY:
            assert not isEmptyNode(myNode)
            td = myNode.terminal_data()
            for x in td:
                self.logger.debug("reconcile_data->%s %s", self, str(x))
                try:
                    self.sendCommand("reconcile_data", self.set.getByInternal(x))
                except KeyError:
                    self.logger.warning("reconcile_data->%s skipping %s",self, x)
            self.reconcile_next()
          
        # My node is empty. Request all elements in this partition.
        elif isEmptyNode(myNode):
            self.logger.debug("reconcile_data_diff_req->%s %s", self, str([]))
            self.sendCommand("reconcile_data_diff_req", setrecon.vec_ZZ_p())
            #self.reconcile_next()

        # We have 2 non empty nodes. If one of them is terminal, we
        # can compute the difference directly. If both are none
        # terminal, we must use the set reconciliation algorithm.

        else:
            
            assert myNode.intree        
            assert not isEmptyNode(myNode)
            assert myNode.intree == True
            assert myNode.ref_count() > 1
            
            if nodeType == NODE_STATUS_TERMINAL:    
                td = myNode.terminal_data()
                mydiff = setrecon.difference_set(td, hash_vector)
                hisdiff = setrecon.difference_set(hash_vector, td)

                for x in hisdiff:
                    self.logger.debug("reconcile_data->%s %s", self, str(x))
                    try:
                        self.sendCommand("reconcile_data", self.set.getByInternal(x))
                    except KeyError:
                        self.logger.warning("reconcile_data->%s %s removed",self, x)

                if mydiff.length() > 0:
                    self.logger.debug("reconcile_data_req->%s %s", self, str(mydiff))
                    self.sendCommand("reconcile_data_req", mydiff)
                self.reconcile_next()

            
            # My node is terminal, but his is not. Send my data points to
            # the server, and it will send and request the missing data.
            elif myNode.isTerminal():
                self.logger.debug("reconcile_data_diff_req->%s %s", self, str(myNode.hash_vector))
                self.sendCommand("reconcile_data_diff_req", myNode.hash_vector)
            else:

                status, mymissing, hismissing = self.set.reconcile(myNode, hash_vector, extra_hashes, size)                
                if not status == 0:
                    self.logger.debug("reconcile_add_children->%s", self)
                    self.sendCommand("reconcile_add_children")
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
                    for x in hismissing:
                        self.logger.debug("reconcile_data->%s %s", self, str(x))
                        self.sendCommand("reconcile_data", self.set.getByInternal(x))

                    self.sendCommand("reconcile_data_req", mymissing)            
                self.reconcile_next()


    def handle_reconcile_data_diff_done(self):
        self.logger.debug("reconcile_data_diff_done<-%s", self)
        assert self.state == self.STATE_GOSSIPING
        self.reconcile_next()

    def handle_reconcile_data_req(self, hashes):
        self.logger.debug("reconcile_data_req<-%s", self)
        assert self.state == self.STATE_GOSSIPING
        if self.curNode.intree: 
            for x in hashes:
                try:
                    d = self.set.getByInternal(x)
                except KeyError, e:
                    self.logger.warning("reconcile_data_req<-%s elm %s removed", self, x)
                else:
                    self.sendCommand("reconcile_data", self.set.getByInternal(x))
        

    def handle_reconcile_hash_vector(self, hashes):
        """Handles response to reconcile_has_vector_req message.

        This event marks the nest step of the recon protocol.

        Sends
        - reconcile_data (data)
        - reconcile_data_req (hashes)
        """
        assert False
        self.logger.debug("reconcile_hash_vector<-%s, %s", self, str(hashes))
        assert self.state == self.STATE_GOSSIPING
        on = self.otherNode
        mn = self.curNode

        on.hash_vector = hashes

        if on.isTerminal():
            td = mn.terminal_data()
            mydiff = setrecon.difference_set(td, hashes)
            hisdiff = setrecon.difference_set(hashes, td)

            #print "hisdiff", self.set._recon.internal2external(hisdiff)
            #print "mydiff", self.set._recon.internal2external(mydiff)
                
            for x in hisdiff:
                self.logger.debug("reconcile_data->%s %s", self, str(x))
                try:
                    self.sendCommand("reconcile_data", self.set.getByInternal(x))
                except KeyError:
                    self.logger.warning("reconcile_data->%s skipping %s",self, x)
                    
            if mydiff.length() > 0:
                self.logger.debug("reconcile_data_req->%s %s", self, str(mydiff))
                self.sendCommand("reconcile_data_req", mydiff)         
            self.reconcile_next()
            return

        if mn.isTerminal():
            self.logger.debug("reconcile_data_diff_req->%s %s", self, str(mn.hash_vector))
            self.sendCommand("reconcile_data_diff_req", mn.hash_vector)
            self.reconcile_next()
            return

        self.logger.debug("reconcile_extra_req->%s", self)
        self.sendCommand("reconcile_extra_req")


    def handle_reconcile_extra(self, extra_hashes, setsize):
        assert False
        assert self.state == self.STATE_GOSSIPING
        on = self.otherNode
        mn = self.curNode

        on.extra_hashes = extra_hashes
        on.setsize = setsize

        # The node might have changed since the last time.
        if isEmptyNode(mn):
            self.logger.warning("reconcile_data_diff_req->%s node bacame empty: %s", self, [])
            self.sendCommand("reconcile_data_diff_req", setrecon.vec_ZZ_p())
            self.reconcile_next()
            return
        
        if mn.isTerminal():
            self.logger.warning("reconcile_data_diff_req->%s node became terminal %s", self, str(mn.hash_vector))
            self.sendCommand("reconcile_data_diff_req", mn.hash_vector)
            self.reconcile_next()
            return        

        status, mymissing, hismissing = self.set.reconcile(mn, on)

        if not status == 0:
            self.logger.debug("reconcile_add_children->%s", self)
            self.sendCommand("reconcile_add_children")
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
            for x in hismissing:
                self.logger.debug("reconcile_data->%s %s", self, str(x))
                self.sendCommand("reconcile_data", self.set.getByInternal(x))

            self.sendCommand("reconcile_data_req", mymissing)
            
        self.reconcile_next()


    def handle_reconcile_done(self):
        """Done reply from server. This extra message is needed to
        flush any data that might be on the wire.
        """
        self.cancelTimeout()
        self.logger.debug("reconcile_done<-%s %s", self, self.databuff)
        assert self.state == self.STATE_GOSSIPING
        self.state = self.STATE_IDLE
        assert self.nodes == []
        self.appendfunc(self.databuff)
        self.databuff = []
        
        self._d.callback(None)

    def handle_reconcile_data(self, data):
        self.logger.debug("reconcile_data<-%s", self)
        assert self.state == self.STATE_GOSSIPING
        self.databuff.append(data)


            
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

    def getSet(self, name):
        if name == "cSet":
            s = self.peer.view.cSet
            f = self.peer.view.addCerts
        elif name == "nSet":
            s = self.peer.view.nSet
            f = self.peer.view.addNotes
        elif name == "aSet":
            s = self.peer.view.aSet
            f = self.peer.view.addAccusations
        else:
            raise ValueError("No such set.")
        return s, f


    def clientConnected(self, protocol, rnr):
        """Client connected."""

        me = self.peer
        him = protocol.other
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
                if (cp.other.id == him.id) or self.view.gRings[rnr].between(cp.other, him, me):
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

    def reconcile(self, protocol):

        def _f(reason):
            self.logger.error("Reconcile failed %s", error)
        
        def _2(result):
            d = protocol.reconcile("aSet", self.peer.view.aSet, self.peer.view.addAccusations)
            d.addErrback(_f)
        def _1(result):
            d = protocol.reconcile("nSet", self.peer.view.nSet, self.peer.view.addNotes)
            d.addCallback(_2)
            d.addErrback(_f)
            
        d = protocol.reconcile("cSet", self.peer.view.cSet, self.peer.view.addCerts)
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

        if partnerOnX.identity == self.peer.identity:
            # No other peers in ring. Leave things as they are.
            pass
        else:
            if (not cg) or (cg.state == cg.STATE_TERMINATED):
                # We do not have an active connection on this ring, so
                # make one.
                ids = map(lambda t: t.other.id, filter(None, self.connections[0:x]))
                if (DUBLICATEPARTNERS) or (partnerOnX.identity not in ids):
                    if not partnerOnX.cert.address in self._initializing:
                        self.connect(partnerOnX, x)
                else:
                    self.connections[x] = None
            else:
                # We have an active connection on the current ring. We
                # can either close the current one and connect to a
                # new member, or keep the current connection.

                if partnerOnX != cg.other:
                    cg.hangup()
                    if not partnerOnX.cert.address in self._initializing:
                        self.connect(partnerOnX, x)
                elif cg.state == cg.STATE_IDLE:
                    self.reconcile(cg)
                else:
                    pass

        

