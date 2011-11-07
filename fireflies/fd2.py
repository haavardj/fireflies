# -*- coding: iso-8859-1 -*-
######################################################################
## Filename:      fd.py
## Description:   Fireflies failure detection protocol.
## Author:        Håvard Dagenborg Johansen <haavardj@cs.uit.no>
## Modified at:   Tue Feb  7 14:18:25 2006
## Modified by:   Håvard Dagenborg Johansen <haavardj@cs.uit.no>
## Licence:       GPL (see the LICENSE file).
##  
##         Copyright© 2006, University of Tromsø (Norway)
##                
## $Id: fd2.py,v 1.2 2011/11/07 13:26:34 haavardj Exp $
##                
######################################################################

"""Failure detection protocol using adaptive pinging.""" 

import logging, pickle
from twisted.internet.protocol import Factory, DatagramProtocol, Protocol, ClientFactory
from twisted.internet import reactor, task, error, defer
from twisted.application.service import Service, MultiService
from fireflies.state import Accusation, Note, Member
from zope.interface import Interface
import socket
from math import *

import crypto
import fireflies
import new, random

from packer import FirefliesPacker, FirefliesUnpacker
from util import long_to_bytes, bytes_to_long

ROUNDTIME = 5
PMISTAKE = 0.001
SMOOTHING = 0.999
TMIN = 3

MSG_PING = 0x23
MSG_PONG = 0x24        
    
class PingMsg(crypto.Signable):
    count = 0
    msgType = MSG_PING
    
    def __init__(self, sender, receiver):
        self.sender = sender
        self.receiver = receiver
        self.noun = PingMsg.count
        PingMsg.count += 1
        self.signature = ""
        
    def uidstr(self):
        return "ping-%x-%x-%d" % (self.sender, self.receiver, self.noun)

class PongMsg(crypto.Signable):
    msgType = MSG_PONG    
    sender = 0 
    receiver = 0
    noun = 0
    signature = ""
    
    def uidstr(self):
        return "pong-%x-%x-%d" % (self.sender, self.receiver, self.noun)

    
class FDMsgPacker(FirefliesPacker):
    """Serializer for Ping and Pong messages.""" 

    def pack_PingMsg(self, msg):
        self.pack_identity(msg.sender.uid)
        self.pack_identity(msg.receiver.uid)
        self.pack_uint(msg.noun)
        self.pack_signature(msg.signature)

    def pack_PongMsg(self, msg):
        self.pack_identity(msg.sender.uid)
        self.pack_identity(msg.receiver.uid)
        self.pack_uint(msg.noun)
        self.pack_signature(msg.signature)

    def pack_msgid(self, mid):
        assert mid >= 0 and mid < 256
        self.pack_fstring(1, chr(mid))

    def pack_msg(self, msg):
        tpe = type(msg)
        if isinstance(msg, PingMsg):
            self.pack_msgid(PingMsg.msgType)
            self.pack_PingMsg(msg)
        elif isinstance(msg, PongMsg):
            self.pack_msgid(PongMsg.msgType)
            self.pack_PongMsg(msg)
        else:
            raise Exception

class FDMsgUnpacker(FirefliesUnpacker):
    """Un-serializer for Ping and Pong messages."""
    
    def __ini__(self, data, mapper=None):
        xdrlib.Unpacker.__init__(self, data)
        self.uri2obj = mapper
    
    def get_remaining(self):
        self.get_buffer()[self.get_position():]
    
    def unpack_PingMsg(self):
        sender = self.unpack_objectByReference()
        receiver = self.unpack_objectByReference()
        noun = self.unpack_uint()
        signature = self.unpack_signature()
        state = {'sender': sender,
                 'receiver': receiver,
                 'noun': noun,
                 'signature': signature}
        return new.instance(PingMsg, state)

    def unpack_PongMsg(self):
        sender = self.unpack_objectByReference()
        receiver = self.unpack_objectByReference()
        noun = self.unpack_uint()
        signature = self.unpack_signature()
        state = {'sender': sender,
                 'receiver': receiver,
                 'noun': noun,
                 'signature': signature}
        return new.instance(PongMsg, state)

    def unpack_msgid(self):
        return ord(self.unpack_fstring(1))

    def unpack_msg(self):
        msgType = self.unpack_msgid()
        if msgType == PingMsg.msgType:
            return self.unpack_PingMsg()
        elif msgType == PongMsg.msgType:
            return self.unpack_PongMsg()
        else:
            raise Exception
        
    def unpack_objectByReference(self):
        identity = self.unpack_identity()
        if not self.uri2obj: return identity
        return self.uri2obj.get(identity)
           

class Serializer:
    
    def __init__(self):
        self.uri2obj = {}
        self.obj2uri = {}

    def registerObjectMapping(self, uri, obj):
        self.uri2obj[uri] = obj
        self.obj2uri[obj] = uri
        
    def serializer(self):
        s = FDMsgPacker()
        s.obj2uri = self.obj2uri
        return s

    def unserializer(self, data):
        s = FDMsgUnpacker(data)
        s.uri2obj = self.uri2obj
        return s
    
class Verifier:
        
    def verify(self, sender, obj):
        return True
    
    def sign(self, obj):
        return True
    
class SignedDatagramProtocol(DatagramProtocol):

    factory = None

    def datagramReceived(self, data, (host, port)):
        
        if len(data) < 1:
            self.logger.warning("Dropped invalid datagram")
            return        
        try:
            p = FDMsgUnpacker(data)
            signature = p.unpack_signature()
            s = crypto.SignableString(p.get_remaining())
            s.signature = signature                   
            senderID = p.unpack_identity()
            senderX509 = self.factory.getCertificate(senderID)
            isinstance(senderX509, crypto.MemberCertificate)
            if not s.verify(senderX509.get_pubkey()): return
            self.signedDatagramReceived(self, senderX509, data, (host,port))
            
        except KeyboardInterrupt:
            raise
        except Exception, why:
            self.logger.warning("Error in message from %s:%d: %s", host, port, why)                                               
            
    def signedDatagramReceived(self, sender, data, (host, port)):
        pass
                        
    def sendSignedDatagram(self, receiver, data):
        pass        
            
    def makeConnection(self, transport):
        print transport, type(transport), id(transport)
        
    
        
class MonitorManager(Service):
    
    interval = 1.0
    
    def __init__(self):
        self.objs = {}
        self.readyToPingQueue = defer.DeferredQueue()
        self.awaitingPong = set()
        self.timedOut = set()
    
    def startService(self):
        self.running = 1        
        for lc, td, d in self.objs.values():
            lc.start(self.interval, now=False)
        
    def stopService(self):
        self.running = 0
        for obj in self.objs.keys():
            self.cancel(obj)
            
        for d in self.readyToPingQueue.waiting:
            d.errback(None)
        
        assert not self.objs
        
    def __contains__(self, obj):
        return obj in self.objs
    
    def next(self):
        return self.readyToPingQueue.get()
                    
    def monitor(self, obj):
        if obj in self.objs:
            return self.objs[obj][2]
        
        td = ExpSmoothedTimeoutPolicy()
        d = defer.Deferred()
        lc = task.LoopingCall(self._objReady, obj) 
        self.objs[obj] = (lc, td, d)
        if self.running: 
            lc.start(self.interval, now=False)
        return d
    
    def _objReady(self, obj):
        if not obj in self.readyToPingQueue.pending:
            self.readyToPingQueue.put(obj)
        
    def cancel(self, obj):
        lc, td, d = self.objs.pop(obj)
        isinstance(d, defer.Deferred)
        isinstance(lc, task.LoopingCall)
        if obj in self.readyToPingQueue.waiting: 
            self.readyToPingQueue.remove(obj)

        if lc.running:
            assert self.running
            lc.stop()
        d.callback(obj)
        
    def _timedOut(self, obj):
        lc, td, d = self.objs.pop(obj)
        isinstance(d, defer.Deferred)
        isinstance(lc, task.LoopingCall)
        
        assert obj not in self.readyToPingQueue.waiting
        assert self.running
        assert lc.running

        if lc.running:
            lc.stop()        
        d.errback(error.TimeoutError("Monitored object does not respond."))
        
    def pinged(self, obj, nonce=0):
        lc, td, d = self.objs[obj]
        td.pinged()
        if td.isTimedOut():
            self._timedOut(obj)
        
    def ponged(self, obj, nonce=0):
        lc, td, d = self.pong[obj]
        td.ponged()
        
   

            
class ExpSmoothedTimeoutPolicy:
    
    avgLoss = 1.2
    pMistake = 0.001
    smoothing = 0.994
    tMin = 3
    nPing = 0
        
    def ponged(self):
        assert self.avgLoss >= 1.0, "avgLoss = %f" % self.avgLoss
        self.avgLoss = (self.smoothing * self.avgLoss) + ( (1. - self.smoothing) * (self.nPing))
        self.nPing = 0
        
    def pinged(self):        
        self.nPing += 1
                    
    def isTimedOut(self):
        p = min( 1./self.avgLoss, 1. - self.pMistake**(1./float(max(self.tMin, 1))))
        assert p < 1.0 and p > 0.0, "Psuc out of bounds."
         
        t = log(self.pMistake) / log(1. - p)
        if self.nPing > t:          
            return True
        else:
            return False

        
            
            
class OLDFailureDetector(Service):
    
    name = "fd"
    roundtime = 5
    pmistake = 0.001
    smoothing = 0.999
    tmin = 3
    

    def __init__(self, group):
        
        isinstance(group, fireflies.group.Group)
        self.peer = group.getMe()
        self.setServiceParent(group) 
        self.group = group
        self.mkey = group.getMyKey()
        self.view = group.getView()
        self.logger = logging.getLogger(group.getMe().getAddress())
         
        nrRings = self.view.getNumberOfRings()
        self.last = -1 % nrRings
        self._pinglist = [None] * nrRings
        isinstance(self.parent, fireflies.group.Group)

    def startService(self):
        Service.startService(self)
        
        self.protocol = PingPong()
        self.protocol.logger = self.logger
        self.protocol.factory = self
        address, port = self.parent.getMe().getAddress().split(":")
        port = int(port)
        self.logger.info("Binding fd to udp %s:%d", address, port)
        self._udpport = reactor.listenUDP(port, self.protocol, interface=address)

        def _d():            
            self._task = task.LoopingCall(self.update)
            self._task.start(float(self.roundtime)/float(self.view.getNumberOfRings())).addErrback(self._failback)
        reactor.callLater(0.1, _d)

    def _failback(self, reason):
        self.logger.exception(reason)
        
    def stopService(self):
        Service.stopService(self)
        
        if self._task:
            self._task.stop()
            self._task = None
        if self._udpport:
            self._udpport.stopListening()
            self._udpport = None
        self.protocol = None
        
    def update(self):

        nrRings = self.view.getNumberOfRings()
        me = self.group.getMe()
        view = self.group.view
        
        #if me.getNote():
        #    myBadness = mpeer.getNote().badness
        #else:
        #    self.logger.warning("Mynote is empty")
        
        myBadness = 0
            
        x = self.last = (self.last + 1) % nrRings

        if myBadness == 1: return 
        if len(view.getLiveMembers()) < 2:
            return

        mon = view.mRings[x].succ(me)
        isinstance(mon, Member)
        while mon.isFailed() or mon.isAccused():
            if mon == me: break
            mon = view.mRings[x].succ(mon)            
            
        # It's me!
        if mon == me: return 


        # We can be the monitor of the same peer on more than one
        # ring. By keeping track of which peer we ping on which ring,
        # we can avoid "double-pinging".
        self._pinglist[x] = mon.getIdentity()
        #if mon.id in self._pinglist[0:x]: return

        # If the monitoree has disabled the ring, we do not need to
        # ping that host.
        if mon.getNote().mask[x] == False:            
            # Prevents this from blocking other rings
            self._pinglist[x] = 0 
            return
        
        if myBadness == 2:
            a = mon.vAccusations.get(x, None)
            if a and a.accuser == me.getIdentity():
                return
            
            accusation = Accusation(mon.getIdentity(),
                                            mon.getNote().epoch,
                                            x,
                                            me.getIdentity()
                                            )
            
            accusation.sign(me.getPublicKey())
            view.stats.accusationsCreated += 1
            view.stats.accusationsCreatedByzantine += 1
            view.addAccusation(accusation)
            self.logger.warning("created %s aggressive attack", self.peer.view.pprint(accusation))
        elif myBadness == 0:
            
            #Do not accuse if this node has already made an accusation
            #on this ring.
            a = mon.vAccusations.get(x, None)
            if a and (a.accuser == me.getIdentity()):
                return
            a = mon.vAccusations.get(x, None)
            if a and (a.accuser == me.getIdentity()):
                return
            
            p = min( 1./mon.avgLoss, 1. - self.pmistake**(1./float(max(self.tmin, 1))))
            assert p < 1.0 and p > 0.0, "Psuc out of bounds."
            
            t = log(self.pmistake) / log(1. - p)

            #if (mon.nPing - t) >= random.random():
            if mon.nPing > t:
                accusation =  Accusation(mon.getIdentity(),
                                                 mon.getNote().epoch,
                                                 x,
                                                 me.getIdentity())
                accusation.sign(self.group.getMyKey())
                self.logger.warning("created %s t=%.2f nPing=%d", self.peer.view.pprint(accusation), t, mon.nPing)
                view.addAccusation(accusation)                
                view.stats.accusationsCreated += 1

                #assert mon.nPing > 0
                #mon.avgLoss = (g.SMOOTHING * mon.avgLoss) + ( (1. - g.SMOOTHING) * (mon.nPing))                
                mon.nPing = 0
                
            else:

                # If we pinged this peer on a lower ring, we dont ping
                # again on this ring.
                if mon.getIdentity() in self._pinglist[0:x]: return
                try:
                    self.protocol.ping(mon)
                except KeyboardInterrupt:
                    raise
                except Exception, why:
                    self.logger.exception("error pinging: %s", why)

                mon.nPing += 1
            
            #if ((self.peer.crypto.address == "127.0.0.1:12000") and
            #    (mon.crypto.address == "127.0.0.1:12001")):
            #    fireflies.stats.gStats.avgLoss = [mon.avgLoss, p, t]


    
        
            
class UDPPingerProtocol(DatagramProtocol):

    factory = None
    serializer = None
    verifier = None
        
    def handle_PingMsg(self, msg):
        #view = self.factory.view
        #mkey = self.factory.mkey
        
        #isinstance(msg, PingMsg)
        #if self.verifier.verifyReceiver(msg.receiver):
        #    self.logger.warning("ping<- %x wrong receiver %x", sender, receiver)
        #    return        
        #if not sender in view.sn2peer:
        #    self.logger.debug("ping<- %x Unknown host", sender)
        #    return

        #sender = view.sn2peer[sender]
        #assert isinstance(sender, Member)
        #if not msg.verify(sender.getPublicKey()):
        #    self.logger.warning("ping<- %s Invalid ping", sender)
        #    return
        #self.logger.debug("ping<- %s", self.factory.peer)
        
        self._replyPing(msg)
                
    def _replyPing(self, pingMsg):
        isinstance(pingMsg, PingMsg)

        #self.logger.debug("pong-> %s", self.factory.peer)
        
        msg = PongMsg()
        msg.sender = pingMsg.receiver
        msg.receiver = pingMsg.sender
        msg.noun = pingMsg.noun
        
        self.verifier.sign(msg)
        self.sendCommand(msg.receiver, msg)
        
        
    def handle_PongMsg(self, msg):
        view, smoothing, mkey = self.factory.view, self.factory.smoothing, self.factory.mkey
        
        if msg.receiver != self.factory.group.getMe().getIdentity():
            self.logger.warning("pong<- %x wrong receiver %x", msg.sender, msg.receiver)
            return        
        sender = view.sn2peer.get(msg.sender, None)
        if sender:
            #self.logger.debug("pong<- %s", self.factory.peer)
            if sender.nPing == 0:
                return
            assert sender.avgLoss >= 1.0
            sender.avgLoss = (smoothing * sender.avgLoss) + ( (1. - smoothing) * (sender.nPing))
            sender.nPing = 0
        else:
            self.logger.debug("pong<- %x Unknown peer", msg.sender)
            
    def ping(self, receiver):
        isinstance(self.factory, FailureDetector)
        me = self.factory.group.getMe()
                
        msg = PingMsg(me.getIdentity(), receiver.getIdentity())
        msg.sign(self.factory.group.getMyKey())
        self.sendCommand(receiver, msg)
        
    def pong(self, pingMsg):
        view, smoothing, mkey = self.factory.view, self.factory.smoothing, self.factory.mkey
        sender = view.sn2peer[pingMsg.sender]        
        assert isinstance(sender, Member)
        #self.logger.debug("pong-> %s", self.factory.peer)
        
        msg = PongMsg(pingMsg)
        msg.sign(self.factory.group.getMyKey())
        self.sendCommand(sender, msg)

    def sendCommand(self, receiver, msg):
        p = self.serializer.serializer()
        p.pack_msg(msg)
        data = p.get_buffer()
        h, p = receiver.address.host, receiver.address.port
        self.transport.write(data, (h, p))

    def datagramReceived(self, data, (host, port)):
        #self.factory.peer.view.stats.udpR += len(data)
        
        if len(data) < 1:
            self.logger.warning("Dropped invalid datagram")
            return        
        try:        
            p = self.serializer.unserializer(data)
            msg = p.unpack_msg()
            p.done()
            getattr(self, "handle_" + msg.__class__.__name__)(msg)
        except KeyboardInterrupt:
            raise
        except Exception, why:
            logging.warning("Error in message from %s:%d: %s", host, port, why)            
