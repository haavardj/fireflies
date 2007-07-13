# -*- coding: iso-8859-1 -*-
######################################################################
## Filename:      gossip4.py
## Description:   Fireflies set-recon based gossip protocol 
## Author:        Håvard Dagenborg Johansen <haavardj@cs.uit.no>
## Modified at:   Wed Feb  1 18:12:09 2006
## Modified by:   Håvard Dagenborg Johansen <haavardj@cs.uit.no>
## Licence:       GPL (see the LICENSE file).
##  
##         Copyright© 2006, University of Tromsø (Norway)
##                
## $Id: gossip5.py,v 1.2 2007/07/13 14:00:00 haavardj Exp $
##                
######################################################################

import logging
from packer import FirefliesPacker, FirefliesUnpacker
from twisted.application import service
from twisted.internet.protocol import Factory, Protocol, ClientFactory, ServerFactory
from twisted.protocols.basic import Int32StringReceiver
from twisted.internet import reactor, task, defer
from Crypto.Hash import MD5, SHA
import sha
import fireflies.mesh
from cert import TimestampMixin
import copy, sys
import setrecon

setrecon.init(fireflies.defaultConfig['BITSIZE'], fireflies.defaultConfig['MBAR'])

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


        

class FirefliesProtocol(fireflies.mesh.MeshBaseProtocol):
    
    def __init__(self):  
        self.curNode = None
        self.nodes = []
        self.dataBuff = []
        self.reqBuff = []
        self.outBuff = []

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
                l, = args
                p.pack_uint(len(l))
                for crt, note in l:
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
            self.factory.logger.exception("Unable to send command %s. %s", cmd, why)
            
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
                n = p.unpack_uint()
                l = []
                for x in range(n):
                    l.append((p.unpack_cert(), p.unpack_note()) )
                args=(l,)
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
            self.factory.logger.exception("Unable to run command %s: %s", cmd, why)
    

    def reconcile_next(self):
        """Moves to the next partition available partition, or marks
        the reconciliation as done if no more partitions are available."""
        
        #assert self.state == self.STATE_GOSSIPING, "state is %s should be %s" % (self.state, self.STATE_GOSSIPING)
        self.factory.logger.debug("reconcile_next %s nodes=%d", self, len(self.nodes))

        if self.nodes == []:
            self.setTimeout()
            self.reqBuff = filter(lambda x:  x not in self.set, self.reqBuff)
            self.factory.logger.debug("reconcile_data_req->%s %d ", self, len(self.reqBuff))
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
            
            self.factory.logger.debug("reconcile_next->%s type=%d", self, nt)
            self.sendCommand("reconcile_next", nt, hv, ev, ss)      
            self.setTimeout()

    def handle_reconcile_next(self, nodeType, hash_vector, extra_hashes, size):
        """Start reconciling of the current partition.    
        """

        self.cancelTimeout()        
        #self.factory.logger.debug("reconcile_next<-%s nt=%s  hv=%s  eh=%s ss=%s",
        #                  self,
        #                  nodeType,
        #                  hash_vector,
        #                  extra_hashes,
        #                  size)
        
        assert self.state == self.STATE_GOSSIPING
        myNode = self.curNode

        # Both nodes are empty means that we are done.
        if (self.nt == NODE_STATUS_EMPTY) and (nodeType == NODE_STATUS_EMPTY):
            #self.factory.logger.debug("reconcile %s both empty" %self)
            self.reconcile_next()
        
        #His node is empty, send all terminal data.
        elif nodeType==NODE_STATUS_EMPTY:
            #self.factory.logger.debug("reconcile %s his empty" %self)
            td = self.set.internal2external(myNode.terminal_data())
            for x in td:
                assert x not in self.outBuff
                self.outBuff.append(x)
            self.reconcile_next()
          
        # My node is empty. Request all elements in this partition.
        elif self.nt == NODE_STATUS_EMPTY:
            #self.factory.logger.debug("reconcile %s my empty" %self)
            self.reconcile_next()

        # We have 2 non empty nodes. If one of them is terminal, we
        # can compute the difference directly. If both are none
        # terminal, we must use the set reconciliation algorithm.

        else:            

            # If his node is terminal, I can figure out what he is missing.
            if nodeType == NODE_STATUS_TERMINAL:
                #self.factory.logger.debug("reconcile %s his treminal" %self)
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
                    #self.factory.logger.debug("reconcile %s both nodes treminal" %self)
                    mymissing = self.set.internal2external(setrecon.difference_set(td, hash_vector))
                    for x in mymissing:
                        assert x not in self.reqBuff
                        self.reqBuff.append(x)
                self.reconcile_next()
            
            # My node is terminal, his is not. The other node will
            # inform me of missing elements.            
            elif self.nt == NODE_STATUS_TERMINAL:
                #self.factory.logger.debug("reconcile %s mynode not treminal" %self)
                self.reconcile_next()

            # Both nodes are non-terminal.
            else:
                #self.factory.logger.debug("reconcile %s both not terminal" % self)
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
                ##self.factory.logger.debug("reconcile %sreconcile\n\taHash=%s \n\taExtra=%s \n\taSize=%d \n\tbHas=%s \n\tbExtra=%s \n\tbSize=%d \n\tvalids=%s ", self,
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
                    #self.factory.logger.debug("reconcile %s reconcile failed valids", self)
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
                    #self.factory.logger.debug("reconcile %s reconcile worked hismissing=%s mymissing=%s", self, hismissing, mymissing)
                    for x in hismissing:
                        assert x not in self.outBuff
                        self.outBuff.append(x)                    
                self.reconcile_next()

    def handle_reconcile_data(self, data):
        """Data from client.
        """
        assert self.nodes == []
        assert self.state == self.STATE_GOSSIPING
        self.factory.logger.debug("reconcile_data<-%s %s", self, data)
        self.dataBuff.append(data)

    def handle_reconcile_data_req(self, hashes):
        self.cancelTimeout()         
        assert self.state == self.STATE_GOSSIPING
        assert self.nodes == [], "%s %s %s" % (self.factory.peer, self, self.nodes)
        
        self.factory.logger.debug("reconcile_data_req<-%s %d", self, len(hashes))

        for x in hashes:
            assert not x in self.outBuff
            self.outBuff.append(x)

        badness = self.factory.peer.getNote().badness
        while self.outBuff:
            x = self.outBuff.pop()
            
            if self.setName == "aSet" and badness == 1:
                #Passive attack, do not forward accusations.
                continue
                
            try:
                d = self.set[x]
            except KeyError, e:
                self.factory.logger.warning("reconcile_data->%s %s removed", self, x)
            else:

                if badness == 2 and self.setName == "nSet":
                    # If active attack, forward only our own notes.
                    if d.identity != self.factory.peer.identity:
                        continue                
                self.sendCommand("reconcile_data", d)

        if self.master:
            self.factory.logger.debug("reconcile_done->%s", self)
            self.sendCommand("reconcile_done")

        self.setTimeout()


    def handle_reconcile_done(self):
        assert not self.nodes
        self.factory.logger.debug("reconcile_done->%s", self)
        if not self.isMaster(): self.sendCommand("reconcile_done")
        self.appendfunc(self.dataBuff)
        self.dataBuff = []


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

        for x in n.hash_vector:
            hsh.update(str(x))
        
        self.factory.logger.debug("reconcile->%s %s hash=%s", self, name, str(hsh.hexdigest()))                
        self.sendCommand("reconcile", name, hsh.digest())        
        self.setTimeout()
        return self._d

    def handle_digest_match(self, match):
        assert self.state == self.STATE_GOSSIPING
        self.cancelTimeout()
        self.factory.logger.debug("digest_match<-%s %s", self, bool(match))
        if match:
            assert self.nodes == self.reqBuff == self.dataBuff == self.outBuff == []
            self.state = self.STATE_IDLE
            self._d.callback(None)
        else:
            n = self.set.getRootPartition()
            n.ref()
            self.nodes = [n]
            self.reconcile_next()


    def handle_reconcile(self, name, digest):
        """
        Protocol start. Name specifies the set to be reconciled.
        """

        self.factory.logger.debug("reconcile<-%s name=%s", self, name)
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
        for x in n.hash_vector:
            hsh.update(str(x))

        if digest == hsh.digest():
            self.factory.logger.debug("digest_match->%s True", self)
            self.sendCommand("digest_match", True)
            self.state = self.STATE_IDLE
        else:
            n.ref()
            self.nodes = [n]
            self.factory.logger.debug("digest_match->%s False", self)
            self.sendCommand("digest_match", False)
            self.reconcile_next()
        

    def redirect(self, peer):
        self.factory.peer.view.stats.redirect += 1
        pprint = self.factory.peer.view.pprint
        self.factory.logger.debug("redirect-> %s to %s", self, pprint(peer.cert))
        self.setTimeout()
        self.sendCommand("redirect", peer.cert, peer.getNote())
        
    def handle_redirect(self, crt, note):
        self.cancelTimeout()
        self.factory.logger.debug("redirect<- %s to %s", self, crt.address)
        self.factory.view.addCerts(crt)
        self.factory.view.addNotes(note)
        self.hangup()



class FirefliesGossipPeer(fireflies.mesh.ChanneledPeerFactory):
    protocol = FirefliesProtocol

class Gossip(fireflies.mesh.Mesh):

    TCPTimeout=360.0
    rate = 5.0
    peerClass = FirefliesGossipPeer
    

def isEmptyNode(node):
    if node:
        if node.intree:
            if node.ref_count() < 2: node.printNode(0)
            assert node.ref_count() > 1, "refcount is %d shoud be 2. intree=%s" %(node.ref_count(), node.intree)
        else:
            if node.ref_count() == 0: node.printNode(0)
            assert node.ref_count() > 0, "refcount is %d shoud be >0. intree=%s" %(node.ref_count(), node.intree)       
    return bool(   (node == None) or (node.setsize==0) or (node.intree == False))
        
