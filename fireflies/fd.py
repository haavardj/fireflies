# -*- coding: utf-8 -*-
######################################################################
## Filename:      fd.py
## Description:   Fireflies failure detection protocol.
## Author:        Håvard Dagenborg Johansen <haavardj@cs.uit.no>
## Modified at:   Tue Feb  7 14:18:25 2006
## Modified by:   Håvard Dagenborg Johansen <haavardj@cs.uit.no>
## Licence:       MIT (see the LICENCE file).
##  
##         Copyright© 2006, Håvard Dagenborg
##                
## $Id: fd.py,v 1.32 2014/06/16 07:49:47 haavardj Exp $
##                
######################################################################

"""Failure detection protocol using adaptive pinging.""" 

import logging, pickle
from twisted.internet.protocol import Factory, DatagramProtocol, Protocol, ClientFactory
from twisted.application.service import Service
import twisted.internet
from fireflies.state import Accusation, Note, Member
import socket
from math import *

from . import crypto
import fireflies
import fireflies.group
import fireflies.state
import random
import secrets

from .packer import FirefliesPacker, FirefliesUnpacker

noisy = 0
MSG_PING = 0x23
MSG_PONG = 0x24

# Most unanswered ping nonces remembered per monitored member.
MAX_OUTSTANDING = 64


class ExpSmoothedTimeoutPolicy:
    """Adaptive ping timeout for one monitored member.

    avgLoss is an exponentially smoothed estimate of how many pings it
    takes to get a pong (1.0 means no loss). From it, isTimedOut()
    computes how many unanswered pings make the probability of a false
    accusation fall below pMistake, assuming independent losses:
    t = log(pMistake) / log(1 - p), with p = min(1/avgLoss,
    1 - pMistake**(1/tMin)). The member has timed out after more than
    t unanswered pings. tMin bounds t from below.
    """

    # Assumed loss rate per message before any pong has been seen.
    initialLossRate = 0.001

    def __init__(self, pMistake=0.0001, smoothing=0.999, tMin=3):
        self.pMistake = pMistake
        self.smoothing = smoothing
        self.tMin = tMin
        # A ping and its pong must both arrive. avgLoss is 1 + the
        # expected number of failures before the first success.
        pSucc = (1 - self.initialLossRate)**2
        self.avgLoss = ((1 - pSucc) / pSucc) + 1
        self.nPing = 0

    def threshold(self):
        """Number of unanswered pings after which the member has timed out."""
        p = min(1. / self.avgLoss, 1. - self.pMistake**(1. / float(max(self.tMin, 1))))
        assert 0.0 < p < 1.0, "Psuc out of bounds."
        return log(self.pMistake) / log(1. - p)

    def isTimedOut(self):
        return self.nPing > self.threshold()

    def pinged(self):
        self.nPing += 1

    def ponged(self):
        """Fold the number of pings this pong took into avgLoss."""
        if self.nPing == 0:
            return
        assert self.avgLoss >= 1.0, "avgLoss = %f" % self.avgLoss
        self.avgLoss = (self.smoothing * self.avgLoss) + ((1. - self.smoothing) * self.nPing)
        self.nPing = 0

    def reset(self):
        """Forget unanswered pings without updating avgLoss (after an accusation)."""
        self.nPing = 0


def outboundPartnersOnRing(member, ring):
    isinstance(member, fireflies.state.Member)
    isinstance(ring, fireflies.ring.Ring)
    
    succ = ring.succ(member)
    while succ != member:
        isinstance(succ, Member)
        
        if succ.isLive():
            if not succ.isEnabledOnRing(ring):
                return None
            else: 
                return succ
        succ = ring.succ(succ)       
    return None

def partners(member):
    isinstance(member, fireflies.state.Member)
    
    p = []    
    for ring in member.group.view.mRings:
        m = outboundPartnersOnRing(member, ring)
        if m and m not in p:
            p.append(m)
    return p


class PingMsg(crypto.Signable):
    msgType = MSG_PING

    def __init__(self, fromSn, toSn):
        self.fromSn = fromSn
        self.toSn = toSn
        # Random nonce. The pong must echo it, so an old pong cannot be
        # replayed to answer a new ping.
        self.noun = secrets.randbits(32)
        self.signature = b""
        
    def uidstr(self):
        return "ping-%s-%s-%d" % (self.fromSn, self.toSn, self.noun)

class PongMsg(crypto.Signable):
    msgType = MSG_PONG
    
    def __init__(self, ping):
        self.fromSn = ping.toSn
        self.toSn = ping.fromSn
        self.noun = ping.noun
        self.signature = b""
    
    def uidstr(self):
        return "pong-%s-%s-%d" % (self.fromSn, self.toSn, self.noun)

def _restore(cls, state):
    """Create an instance of cls from state without calling __init__
    (replaces Python 2's new.instance)."""
    obj = cls.__new__(cls)
    obj.__dict__.update(state)
    return obj


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
        self.pack_fstring(1, bytes([mid]))

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
        return _restore(PingMsg, state)

    def unpack_PongMsg(self):
        fromSn = self.unpack_identity()
        toSn = self.unpack_identity()
        noun = self.unpack_uint()
        signature = self.unpack_signature()
        state = {'fromSn': fromSn,
                 'toSn': toSn,
                 'noun': noun,
                 'signature': signature}
        return _restore(PongMsg, state)

    def unpack_msgid(self):
        return self.unpack_fstring(1)[0]

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
    
    # How often a monitor should ping (seconds).
    roundtime = 30
    
    # The probability of accusing a live member due to packet
    # loss. Lower number is better but increases the time it takes to
    # detect a failed member.
    pMistake = 0.0001
    
    # What factor the pinging protocol will use to smooth the expected
    # average loss rate.
    smoothing = 0.999
    
    # Do not accuse a member unless it has been pinged this many times.    
    tmin = 3
        

    def __init__(self, group):
        self.group = group
        isinstance(group, fireflies.group.Group)
        self.setServiceParent(group)
        self.pinglist = []
        isinstance(self.parent, fireflies.group.Group)

        # Per monitored member: timeout policy, and nonces of pings that
        # have not been answered. Kept when monitoring stops so the
        # loss estimate survives ring changes.
        self.policies = {}
        self.outstanding = {}

    @property
    def logger(self):
        return self.group.logger

    def getPolicy(self, member):
        policy = self.policies.get(member)
        if policy is None:
            policy = ExpSmoothedTimeoutPolicy(self.pMistake, self.smoothing, self.tmin)
            self.policies[member] = policy
        return policy

    def expectPong(self, member, nonce):
        """Record that a ping with nonce was sent to member."""
        pending = self.outstanding.setdefault(member, {})
        pending[nonce] = None
        while len(pending) > MAX_OUTSTANDING:
            del pending[next(iter(pending))]

    def acceptPong(self, member, msg):
        """Return True and update the timeout policy if msg is a valid pong
        from member: it echoes the nonce of an unanswered ping and is signed
        by member. Otherwise return False."""
        pending = self.outstanding.get(member)
        if not pending or msg.noun not in pending:
            self.group.stats.pongsRejected += 1
            self.logger.warning("pong<- %s discarded: no outstanding ping with nonce %d", member, msg.noun)
            return False
        if not msg.verify(member.getPublicKey()):
            self.group.stats.pongsRejected += 1
            self.logger.warning("pong<- %s discarded: invalid signature", member)
            return False
        # One pong answers all outstanding pings; earlier nonces can
        # no longer be used.
        pending.clear()
        self.getPolicy(member).ponged()
        return True

    def startService(self):
        Service.startService(self)
        
        self.protocol = PingPong()
        self.protocol.factory = self
        address, port = self.parent.getMe().getAddress().split(":")
        port = int(port)
        self.logger.info("Binding fd to udp %s:%d", address, port)
        self._udpport = twisted.internet.reactor.listenUDP(port, self.protocol, interface=address)

        self._task = twisted.internet.task.LoopingCall(self.update)
        
        #interval = self.roundtime / float(self.group.view.getNumberOfRings())
        self._task.start(5, now=False).addErrback(self._failback)
        
        self.monitoring = {}


    def _failback(self, reason):
        self.logger.exception(reason)
        
    def stopService(self):
        Service.stopService(self)
        address, port = self.parent.getMe().getAddress().split(":")
        port = int(port)
        self.logger.info("Stopping fd on udp %s:%d", address, port)
        
        #if self._task and self._task.running:
        self._task.stop()
        #self._task = None

        for m,t in list(self.monitoring.items()):
            assert isinstance(t, twisted.internet.task.LoopingCall)
            assert isinstance(m, Member)
            t.stop()
        self.monitoring = {}
            
        if self._udpport:
            self._udpport.stopListening()
            self._udpport = None                       
        self.protocol = None

    def failPinging(self, error, member):
        self.logger.warning("Pinging failed %s %s", member, error)
        
    def update(self):
        
        assert self._task and self._task.running
        me = self.group.getMe()

        myPartners = partners(self.group.getMe())
        
        for currentPartner, timer in list(self.monitoring.items()):
            if not currentPartner in myPartners:
                self.logger.info("Stop monitoring %s", currentPartner)
                assert isinstance(timer, twisted.internet.task.LoopingCall)
                timer.stop()
                self.monitoring.pop(currentPartner)
        
        for partner in myPartners:
            if not partner in self.monitoring:
                self.logger.info("Start monitoring %s", partner)
                timer = twisted.internet.task.LoopingCall(self.doPing, partner)
                timer.start(self.roundtime, now=False).addErrback(self.failPinging, partner)
                self.monitoring[partner] = timer
            else:
                assert self.monitoring[partner].running


    def doPing(self, member):
        assert isinstance(member, fireflies.state.Member)
        me = self.group.getMe()
        assert member != me
        if not fireflies.view.canAccuse(me, member):
            return
        
        if member.isAccusedBy(me): 
            return
        
                                           
        #Aggressive attack. Generate accusation.        
        if self.group.badness == 2:

            accusation = Accusation(member.identity,
                                    member.getNote().epoch,
                                    me.identity)
            
 
            accusation.sign(self.group.getMyKey())
            self.group.stats.accusationsCreatedByzantine += 1
            self.group.stats.accusationsCreated += 1
            self.group.view.addAccusation(accusation)
            self.logger.warning("created %s attack", member)

        elif self.group.badness == 0:
            #Do not accuse if this node has already made an accusation
            #on this ring.
            policy = self.getPolicy(member)

            if policy.isTimedOut():

                #Passive attack. Do nothing.
                if self.group.badness == 1:
                    self.logger.warning("passive %s attack", member)
                else:
                    accusation = Accusation(member.identity, member.getNote().epoch, me.identity)
                    accusation.sign(self.group.getMyKey())
                    self.logger.warning("created %s t=%.2f nPing=%d", accusation, policy.threshold(), policy.nPing)
                    self.group.view.addAccusation(accusation)
                    self.group.stats.accusationsCreated += 1

                    assert policy.nPing > 0
                    policy.reset()
                    self.outstanding.pop(member, None)

            else:

                # If we pinged this peer on a lower ring, we dont ping
                # again on this ring.
                try:
                    self.protocol.ping(member)
                except KeyboardInterrupt:
                    raise
                except Exception as why:
                    self.logger.exception("error pinging: %s", why)

                policy.pinged()


class PingPong(DatagramProtocol):

    factory = None
    
    @property
    def logger(self):
        return self.factory.logger
        
    def handle_PingMsg(self, msg):
        view = self.factory.group.view
        mkey = self.factory.group.getMyKey()
        
        toSn, fromSn, noun = msg.toSn, msg.fromSn, msg.noun
        if not toSn == self.factory.group.getMe().identity:
            self.logger.warning("ping<- %s wrong receiver %s", fromSn, toSn)
            return        
        if not fromSn in view.sn2peer:
            if noisy: self.logger.debug("ping<- %s Unknown host", fromSn)
            return

        sender = view.sn2peer[fromSn]
        assert isinstance(sender, Member)
        if not msg.verify(sender.getPublicKey()):
            self.logger.warning("ping<- %s Invalid ping", fromSn)
            return
        if noisy: self.logger.debug("ping<- %s", sender)
        self.pong(msg)
                
    def handle_PongMsg(self, msg):
        view = self.factory.group.view

        if msg.toSn != self.factory.group.getMe().identity:
            self.logger.warning("pong<- %s wrong receiver %s", msg.fromSn, msg.toSn)
            return
        sender = view.sn2peer.get(msg.fromSn, None)
        if sender:
            if noisy: self.logger.debug("pong<- %s", sender)
            self.factory.acceptPong(sender, msg)
        else:
            if noisy: self.logger.debug("pong<- %s Unknown peer", msg.fromSn)

    def ping(self, receiver):
        isinstance(self.factory, FailureDetector)
        me = self.factory.group.getMe()

        if noisy: self.logger.debug("ping-> %s", receiver)

        msg = PingMsg(me.identity, receiver.identity)
        msg.sign(self.factory.group.getMyKey())
        self.factory.expectPong(receiver, msg.noun)
        self.sendCommand(receiver, msg)
        return msg

    def pong(self, pingMsg):
        view = self.factory.group.view
        sender = view.sn2peer[pingMsg.fromSn]
        assert isinstance(sender, Member)
        
        msg = PongMsg(pingMsg)
        msg.sign(self.factory.group.getMyKey())
        if noisy: self.logger.debug("ping-> %s", sender)

        self.sendCommand(sender, msg)


    def sendCommand(self, receiver, msg):

        p = FDMsgPacker()
        p.pack_msg(msg)
        data = p.get_buffer()
        h, p = receiver.getAddress().split(":")
        p = int(p)
        
        receiver.group.stats.udpW += len(data)
        self.transport.write(data, (h, p))

    def datagramReceived(self, data, addr):
        (host, port) = addr
        if not self.factory.running: 
            self.logger.warning("Datagram received while stopped")
            return 
        
        assert self.factory.running == self.factory.group.running
             
        self.factory.group.stats.udpR += len(data)
        if len(data) < 1:
            self.logger.warning("Dropped invalid datagram")
            return        
        try:        
            p = FDMsgUnpacker(data)
            msg = p.unpack_msg()
            p.done()
            getattr(self, "handle_" + msg.__class__.__name__)(msg)            
        except KeyboardInterrupt:
            return
        except Exception as why:
            self.logger.warning("Error in message from %s:%d: %s", host, port, why)            

