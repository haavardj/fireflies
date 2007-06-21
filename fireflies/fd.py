# -*- coding: iso-8859-1 -*-
######################################################################
## Filename:      fd.py
## Description:   Fireflies failure detection service.
## Author:        Håvard Dagenborg Johansen <haavardj@cs.uit.no>
## Modified at:   Tue Feb  7 14:18:25 2006
## Modified by:   Håvard Dagenborg Johansen <haavardj@cs.uit.no>
## Licence:       GPL (see the LICENSE file).
##  
##         Copyright© 2006, University of Tromsø (Norway)
##                
## $Id: fd.py,v 1.6 2007/06/21 06:35:14 haavardj Exp $
##                
######################################################################

import fireflies
import fireflies.packer

from fireflies.group import Group
from fireflies.members import Member

import logging

from math import *
from twisted.internet.protocol import Factory, DatagramProtocol, Protocol, ClientFactory
from twisted.internet import reactor, defer
from twisted.application.service import MultiService, Service
from twisted.application import internet
from zope.interface import Interface, implements
from Crypto.Util.number import long_to_bytes, bytes_to_long
from twisted.python import components

ROUNDTIME = 60
PMISTAKE = 0.001
SMOOTHING = 0.999
TMIN = 3


class IPingProtocol(Interface):    
    def ping(member):
        """Ping member. Returns a deferred that triggers when pong is received."""

class IFailureDetector(Interface):

    def monitor(self, member):
        """Monitor a member. Returns a deferred that will trigger it the member failes."""
        
    def stopMonitoring(self, member):
        """Stop Monitoring a member."""
        
def calculateThreshold(lossrate):    
    __pSucc = (1 - lossrate)**2 
    return ((1-__pSucc)/__pSucc) + 1

class FDMember:
    task = None
    nrPing = 0
    avgLossrate = calculateThreshold(0.20)
    
    def __init__(self, member):
        self.member = member
        self.d = defer.Deferred()
            

class FailureDetector(MultiService):

    DEFAULT_LOSSRATE = 0.1
    rate = 20
    pmistake = 0.010
    smoothing = 0.990
    tmin = 2
    
    def __init__(self, group, member, key, rate=20.0, pmistake=0.010, smoothing = 0.990, tmin=2.0):
        MultiService.__init__(self)
        isinstance(group, fireflies.group.Group)                
        self.group = group
        self.members = member
        self.key = key
        
        self.members = {}
        self.protocol = None
        
    def monitor(self, member):
        m = FDMember(member)
        m.task = internet.task.LoopingCall(self.rate, self._timeToPing, m, now=False)        
        self.members[member.getIdentity()] = m
        return m.d
    
    def stopMonitoring(self, member):
        m = self.members[member.getIdentity()]
        m.task.stop()
        del self.members[member.getIdentity()]
    
    def _timeToPing(self, m):        
        isinstance(m, FDMember)
        
        p = min( 1./m.avgLossrate, 1. - self.pmistake**(1./float(max(self.tmin, 1))))
        assert p < 1.0 and p > 0.0, "Psuc out of bounds."
        t = log(self.pmistake) / log(1. - p)
            
        #self.logger.info("%s time-to-ping nPing %d", mon, nPing)

        if m.nrPing > t:
            member.d.callback()
            self.stopMonitoring(member)
            #self.logger.warning("created %s t=%.2f nPing=%d", self.rings.pprint(accusation), t, nPing)
            #view.stats.accusationsCreated += 1
            # mon.avgLoss = (g.SMOOTHING * mon.avgLoss) + ( (1. - g.SMOOTHING) * (mon.nPing))                
        else:
            try:
                d = self.protocol.ping(m.member)
                d.addCallback(self._pong, m)
            except KeyboardInterrupt:
                raise
            except Exception, why:
                self.logger.exception("error pinging: %s", why)
            m.nrPing += 1
         
    def _pong(self, m):
        
        #self.logger.debug("pong<- %s", member)
        assert isinstance(m, FDMember)
        if m.nrPing == 0:
            return            
        assert m.avgLossrate >= 1.0
        m.avgLossrate = (self.smoothing * m.avgLossrate) + ( (1. - self.smoothing) * (m.avgLossrate))
        m.nrPing = 0


#
# Low Level ping protocol
# 

_cmd2code = {
    'ping': 0x1,
    'pong': 0x2
    }

_code2cmd = {}
for k, v in _cmd2code.items():
    _code2cmd[v] = k
del k
del v

class Ping(object, fireflies.crypto.RSASignable):
    
    def __init__(self, toSn, fromSn, nounce):
        self.fromSn = fromSn
        self.toSn = toSn
        self.nounce = nounce
        self.signature = 0

    def __setstate__(self, data):
        for k,v in data.items():
            setattr(self, k, v)
         
    def uidstr(self):
        return "ping-%x-%x-%d" % (bytes_to_long(self.fromSn), bytes_to_long(self.toSn), self.nounce)

class Pong(object, fireflies.crypto.RSASignable):
    
    def __init__(self, ping):
        assert isinstance(ping, Ping)
        self.ping = ping
        self.signature = 0

    def __setstate__(self, data):
        for k,v in data.items():
            setattr(self, k, v)        
        
    def uidstr(self):
        return "pong-%s" % (self.ping.uidstr())

class FDPacker(fireflies.packer.FirefliesPacker):
    """Serializer for Ping and Pong messages.""" 
    
    def __init__(self):
        fireflies.packer.FirefliesPacker.__init__(self)

    def pack_ping(self, ping):
        self.pack_serial(ping.fromSn)
        self.pack_serial(ping.toSn)
        self.pack_uint(ping.nounce)
        self.pack_signature(ping.signature)

    def pack_pong(self, pong):
        self.pack_ping(pong.ping)
        self.pack_signature(pong.signature)

class FDUnpacker(fireflies.packer.FirefliesUnpacker):
    """Un-serializer for Ping and Pong messages."""

    def __init__(self, data):
        fireflies.packer.FirefliesUnpacker.__init__(self, data)
    
    def unpack_ping(self):
        fromSn = self.unpack_serial()
        toSn = self.unpack_serial()
        nounce = self.unpack_uint()
        signature = self.unpack_signature()

        d = {'fromSn': fromSn,
             'toSn': toSn,
             'nounce': nounce,
             'signature': signature}
        
        c = object.__new__(Ping)
        c.__setstate__(d)
        return c

    def unpack_pong(self):
        ping = self.unpack_ping()
        signature = self.unpack_signature()
        
        d = {'ping': ping,
             'signature': signature}
        c = object.__new__(Pong)
        c.__setstate__(d)
        return c
    
class UDPPingPong(DatagramProtocol):
    """Ping-Pong protocol."""
    
    implements(IPingProtocol)
    
    def __init__(self, service):
        self.service = self.factory = service
    
    def handle_ping(self, fromIP, fromPort, ping):
        f = self.factory 
        assert isinstance(f, FailureDetector)
        assert isinstance(ping, Ping)
        g = f.group        
        mk = g.key        

        #self.logger.info("ping<- %s", fromIP)
        
        if not ping.toSn == g.peer.getSerial():
            self.logger.warning("ping<- %s wrong receiver %s", fromIP, bytes_to_long(g.peer.getSerial()))
            return        
        try:
            sender = g.getMemberBySerial(ping.fromSn)                                                  
        except KeyError:            
            self.logger.debug("ping<- %x Unknown host", bytes_to_long(fromSn))
            return

        assert isinstance(sender, fireflies.members.Member)        
        if not sender.getCertificate().verify(ping):
            self.logger.warning("ping<- %s invalid signature", fromIP)
            return

        host, port = sender.getAddress().split(":")
        port = int(port)

        if fromIP != host:
            self.logger.warning("ping<- %s from ip does not match note %s", fromIP, host)
            
        pong = Pong(ping)
        g.key.sign(pong)
        
        p = FDPacker()
        p.pack_uint(_cmd2code["pong"])
        p.pack_pong(pong)        
        data = p.get_buffer()
        #self.factory.rings.stats.udpW += len(data)
        self.transport.write(data, (host, port))
             
    def handle_pong(self, fromIP, fromPort, pong):
        f = self.factory 
        assert isinstance(f, FailureDetector)
        assert isinstance(pong, Pong)
        g = f.group
        sk = g.key
        
        if pong.ping.fromSn != g.peer.getSerial():
            self.logger.warning("pong<- %x wrong receiver %x", 
                                bytes_to_long(pong.ping.fromSn), 
                                bytes_to_long(pong.ping.toSn))
            return

        
        if not g.peer.getCertificate().verify(pong.ping):
            self.logger.warning("pong<- %s wrong singatur on ping", fromIP)
            return

        try:
            sender = g.getMemberBySerial(pong.ping.toSn)
        except KeyError:
            self.logger.debug("pong<- %s Unknown peer", fromIP)            
            return
        
        assert isinstance(sender, fireflies.members.Member)
        
        if not sender.getCertificate().verify(pong):
            self.logger.warning("pong<- %s wrong signature", fromIP)
            return

        #self.logger.info("pong<- %s", fromIP)
        f._pong(sender, pong.ping.nounce)
                                
        
    def ping(self, member):
        """Send a ping containing nounce to member."""
        
        if not isinstance(Member, fireflies.members.Member): raise ValueError        
        f = self.factory
        g = f.group
        sk = g.key
        d = defer.Deferred()
                
        ping = Ping(member.getSerial(), g.peer.getSerial(), nounce)
        sk.sign(ping)
        p = FDPacker()
        p.pack_uint(_cmd2code["ping"])
        p.pack_ping(ping)        
        data = p.get_buffer()
        #self.factory.rings.stats.udpW += len(data)
        h, p = toMember.getAddress().split(":")
        p = int(p)
        self.transport.write(data, (h, p))
        self.logger.warning("ping-> %s %d", toMember, nounce)       
        return d

    def datagramReceived(self, data, (from_ip, from_port)):
       # self.factory.peer.view.stats.udpR += len(data)

        if len(data) < 1:
            self.logger.warning("Dropped invalid datagram")
            return        
        try:
            p = FDUnpacker(data)
            type = _code2cmd[p.unpack_uint()]
            if type == "ping":
                args = (p.unpack_ping(),)
            elif type == "pong":
                args = (p.unpack_pong(),)             
            p.done()
            getattr(self, "handle_" + type)(from_ip, from_port, *args)
        except KeyboardInterrupt:
            raise
        except Exception, why:
            self.logger.exception("Error in message from %s:%d: %s", from_ip, from_port, why)            

