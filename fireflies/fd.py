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
## $Id: fd.py,v 1.23 2011/09/22 07:51:42 haavardj Exp $
##                
######################################################################

"""Failure detection protocol using adaptive pinging.""" 

import logging, pickle
from twisted.internet.protocol import Factory, DatagramProtocol, Protocol, ClientFactory
from twisted.internet import reactor, task
from twisted.application.service import Service
from fireflies.state import Accusation, Note, Member
import socket
from math import *

import crypto
import fireflies
import new, random

from packer import FirefliesPacker, FirefliesUnpacker


ROUNDTIME = 5
PMISTAKE = 0.001
SMOOTHING = 0.999
TMIN = 3

MSG_PING = 0x23
MSG_PONG = 0x24    

class PingMsg(crypto.Signable):
    count = 0
    msgType = MSG_PING
    
    def __init__(self, fromSn, toSn):
        self.fromSn = fromSn
        self.toSn = toSn
        self.noun = PingMsg.count
        PingMsg.count += 1
        self.signature = 0
        
    def uidstr(self):
        return "ping-%x-%x-%d" % (self.fromSn, self.toSn, self.noun)

class PongMsg(crypto.Signable):
    msgType = MSG_PONG
    
    def __init__(self, ping):
        self.fromSn = ping.toSn
        self.toSn = ping.fromSn
        self.noun = ping.noun
        self.signature = 0
    
    def uidstr(self):
        return "pong-%x-%x-%d" % (self.fromSn, self.toSn, self.noun)


class FDMsgPacker(FirefliesPacker):
    """Serializer for Ping and Pong messages.""" 

    def pack_PingMsg(self, msg):
        self.pack_identity(msg.fromSn)
        self.pack_identity(msg.toSn)
        self.pack_uint(msg.noun)
        self.pack_signature(msg.signature)

    def pack_PongMsg(self, msg):
        self.pack_identity(msg.fromSn)
        self.pack_identity(msg.toSn)
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
    
    def unpack_PingMsg(self):
        fromSn = self.unpack_identity()
        toSn = self.unpack_identity()
        noun = self.unpack_uint()
        signature = self.unpack_signature()
        state = {'fromSn': fromSn,
                 'toSn': toSn,
                 'noun': noun,
                 'signature': signature}
        return new.instance(PingMsg, state)

    def unpack_PongMsg(self):
        fromSn = self.unpack_identity()
        toSn = self.unpack_identity()
        noun = self.unpack_uint()
        signature = self.unpack_signature()
        state = {'fromSn': fromSn,
                 'toSn': toSn,
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


class FailureDetector(Service):
    
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

        mon = view.mRings.getRings()[x].succ(me)
        isinstance(mon, Member)
        while mon.isFailed() or mon.isAccused():
            if mon == me: break
            mon = view.mRings.getRings()[x].succ(mon)            


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


class PingPong(DatagramProtocol):

    factory = None
        
    def handle_PingMsg(self, msg):
        view = self.factory.view
        mkey = self.factory.mkey
        
        toSn, fromSn, noun = msg.toSn, msg.fromSn, msg.noun
        if not toSn == self.factory.group.getMe().getIdentity():
            self.logger.warning("ping<- %x wrong receiver %x", fromSn, toSn)
            return        
        if not fromSn in view.sn2peer:
            self.logger.debug("ping<- %x Unknown host", fromSn)
            return

        sender = view.sn2peer[fromSn]
        assert isinstance(sender, Member)
        if not msg.verify(sender.getPublicKey()):
            self.logger.warning("ping<- %s Invalid ping", fromSn)
            return
        #self.logger.debug("ping<- %s", self.factory.peer)
        self.pong(msg)
                
    def handle_PongMsg(self, msg):
        view, smoothing, mkey = self.factory.view, self.factory.smoothing, self.factory.mkey
        
        if msg.toSn != self.factory.group.getMe().getIdentity():
            self.logger.warning("pong<- %x wrong receiver %x", msg.fromSn, msg.toSn)
            return        
        sender = view.sn2peer.get(msg.fromSn, None)
        if sender:
            #self.logger.debug("pong<- %s", self.factory.peer)
            if sender.nPing == 0:
                return
            assert sender.avgLoss >= 1.0
            sender.avgLoss = (smoothing * sender.avgLoss) + ( (1. - smoothing) * (sender.nPing))
            sender.nPing = 0
        else:
            self.logger.debug("pong<- %x Unknown peer", msg.fromSn)
            
    def ping(self, receiver):
        isinstance(self.factory, FailureDetector)
        me = self.factory.group.getMe()
        
        self.logger.debug("ping-> %s", receiver.getAddress())
        
        msg = PingMsg(me.getIdentity(), receiver.getIdentity())
        msg.sign(self.factory.group.getMyKey())
        self.sendCommand(receiver, msg)
        
    def pong(self, pingMsg):
        view, smoothing, mkey = self.factory.view, self.factory.smoothing, self.factory.mkey
        sender = view.sn2peer[pingMsg.fromSn]        
        assert isinstance(sender, Member)
        #self.logger.debug("pong-> %s", self.factory.peer)
        
        msg = PongMsg(pingMsg)
        msg.sign(self.factory.group.getMyKey())
        self.sendCommand(sender, msg)

    def dispatch(self, msg):        
        try:
            getattr(self, "handle_" + msg.__class__.__name__)(msg)
        except KeyboardInterrupt:
            raise
        except Exception, why:
            self.logger.exception("Command error %s", why)

    def sendCommand(self, receiver, msg):

        p = FDMsgPacker()
        p.pack_msg(msg)
        data = p.get_buffer()
        h, p = receiver.getAddress().split(":")
        p = int(p)
        
        self.factory.peer.view.stats.udpW += len(data)
        self.transport.write(data, (h, p))

    def datagramReceived(self, data, (host, port)):
        self.factory.peer.view.stats.udpR += len(data)
        if len(data) < 1:
            self.logger.warning("Dropped invalid datagram")
            return        
        try:        
            p = FDMsgUnpacker(data)
            msg = p.unpack_msg()
            p.done()
            self.dispatch(msg)
        except KeyboardInterrupt:
            raise
        except Exception, why:
            self.logger.warning("Error in message from %s:%d: %s", host, port, why)            

