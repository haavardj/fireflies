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
## $Id: fd.py,v 1.4 2006/05/08 09:47:55 haavardj Exp $
##                
######################################################################

import fireflies
import fireflies.packer
import logging
from math import *
from twisted.internet.protocol import Factory, DatagramProtocol, Protocol, ClientFactory
from twisted.internet import reactor
from twisted.application.service import MultiService, Service
from twisted.application import internet
from zope.interface import Interface, implements
from Crypto.Util.number import long_to_bytes, bytes_to_long
    
ROUNDTIME = 60
PMISTAKE = 0.001
SMOOTHING = 0.999
TMIN = 3
__pSucc = (1 - 0.20)**2 
DEFAULT_AVGLOSS = ((1-__pSucc)/__pSucc) + 1
del __pSucc
        
def _filterDupMonitors(l):
    """Return a list monitores of the same length as l but any duplicate and
    disabled monitores set to None."""
    r = []
    for x, n in enumerate(l):
        if (not n) or (n in r) or (n._note.mask[x] == False): r.append(None)
        else: r.append(n)
    return r


class MonitoringPolicy:
    """Implements a monitoring policy.

    This react to group membership events and makes the failure detector update
    whom it is monitoring. This policy also creates accusations whenever the failure detector
    suspect that some member has failed."""

    implements(fireflies.interfaces.IGroupEvents, fireflies.interfaces.IFailureEvents)

    def __init__(self, group, fd):
        if not isinstance(fd, fireflies.fd.FailureDetector): raise ValueError
        if not isinstance(group, fireflies.group.Group): raise ValueError
        self.fd = fd
        self.group = group
        self.fd.updateMonitorList()
        
        self.fd.subscribe(self)
        self.group.subscribe(self)
    
    #IFailureEvents
    def _cb_suspect(self, member, ring): 
        assert isinstance(member, fireflies.members.Member)
        accusation = fireflies.members.Accusation(member.getSerial(),
                                                  member._note.epoch,
                                                  ring,
                                                  self.group.peer.getSerial())                                                  
        self.group.key.sign(accusation)
        self.group.mRings.addAccusation(accusation)
        self.fd.updateMonitorList()
        
    #IGroupEvents
    def _cb_member_joined(self, member):
        self.fd.updateMonitorList()
        
    def _cb_member_leaves(self, member):
        self.fd.updateMonitorList()
        
    def _cb_member_accused(self, member):
        self.fd.updateMonitorList()
    
    def _cb_member_rebuts(self, member):
        self.fd.updateMonitorList()

    def _cb_member_failes(self, member):
        self.fd.updateMonitorList()
    
    def _cb_member_lives(self, member):
        self.fd.updateMonitorList()


class FailureDetector(Service):

    def __init__(self, group, 
                 rate=ROUNDTIME,
                 pmistake=PMISTAKE,
                 smoothing=SMOOTHING,
                 tmin=TMIN):

        if 0: isinstance(group, fireflies.group.Group)
        #MultiService.__init__(self)
        
        self._group = group
        self.rate = rate
        self.pmistake = pmistake
        self.smoothing = smoothing
        self.tmin = tmin
        
        self.__listeners = []         
        self.__policy = MonitoringPolicy(group, self)        
        self.logger = logging.getLogger(group.peer.getAddress())
        self.__last = -1        
        self.__memberInfo = {}
        self._monitoring = [None] * self._group.mRings.getNrRings()        
        self._protocol = PingPong(self)
        self._protocol.logger = self.logger
        
        port = int(group.key.address.split(":")[1])
        
        #internet.UDPServer(port, self._protocol).setServiceParent(self)
        #internet.TimerService(rate/self._group.mRings.getNrRings(), self._update).setServiceParent(self)
        
    #
    # IFailureDetectionService
    #        
    def subscribe(self, obj):
        if not fireflies.interfaces.IFailureEvents.providedBy(obj): raise TypeError
        if obj in self.__listeners: raise ValueError
        self.__listeners.append(obj)

    def unsubscribe(self, obj):
        self.__listeners.remove(obj)
        
    #
    # IService interface
    #
    def privilegedStartService(self):
        pass
    
    def startService(self):
        self.running = 1
        Service.startService(self)                         
        self.logger.info("Starting Failure detection")

    def stopService(self):
        self.running = 0 
        Service.stopService(self)
        self.protocol = None
        self.unsubscribe(self.__policy)
        self.__policy.group = None
        self.__policy.fd = None
        self.logger.info("Stopping Failure detection")

    # 
    # Other stuff
    #            
    def _trigger_suspicion(self, member, ring):
        for l in self.__listeners:            
            reactor.callLater(0, l._cb_suspect, member, ring)

    def _failback(self, reason):
        self.logger.exception(reason)

    def updateMonitorList(self):        
        self._monitoring = _filterDupMonitors(self._group.mRings.succ(self._group.peer, lambda x: not (x.isAccused() )))
        
    def _update(self):
        """Ping next member."""

        nrRings = self._group.mRings.getNrRings()        
        mkey = self._group.key        
        myBadness = self._group.badness
        if myBadness == 1: return 
        if self._group.mRings.getNrMembers() < 2:
            return

        ringToPing = self.__last = (self.__last + 1) % nrRings
        mon = self._monitoring[ringToPing]
        if not mon: return 
        if mon == self._group.peer: return        
        assert isinstance(mon, fireflies.members.Member)
 
        # We might want to monitor and accuse even if mon is accused on a
        # different ring, or this member can make a better accusation.
        # Currently, we don't do that.
         
        if myBadness == 2:
            
            self._trigger_suspicion(member, ringToPing)
            # accusation = members.Accusation(mon.getSerial(),
            #                                mon.note.lifeline,
            #                                ring.nr,
            #                                self.member.getSerial())
            # self.signingKey.sign(accusation)

            # view.stats.accusationsCreated += 1
            # view.stats.accusationsCreatedByzantine += 1
            # view.addAccusations(accusation)
            # self.logger.warning("created %s aggressive attack", self.rings.pprint(accusation))
            
        elif myBadness == 0:
            
            nPing, avgLoss = self.__memberInfo.get(mon, (0, DEFAULT_AVGLOSS))            
            p = min( 1./avgLoss, 1. - self.pmistake**(1./float(max(self.tmin, 1))))
            assert p < 1.0 and p > 0.0, "Psuc out of bounds."
            t = log(self.pmistake) / log(1. - p)
            
            #self.logger.info("%s time-to-ping nPing %d", mon, nPing)

            if nPing > t:
                self._trigger_suspicion(mon, ringToPing)
                #self.logger.warning("created %s t=%.2f nPing=%d", self.rings.pprint(accusation), t, nPing)
                #view.stats.accusationsCreated += 1
                # mon.avgLoss = (g.SMOOTHING * mon.avgLoss) + ( (1. - g.SMOOTHING) * (mon.nPing))                
                nPing = 0
    
            else:
                try:
                    #TODO: Ping using noun.
                    self._protocol.ping(mon, 1)
                except KeyboardInterrupt:
                    raise
                except Exception, why:
                    self.logger.exception("error pinging: %s", why)

                nPing += 1
            self.__memberInfo[mon] = (nPing, avgLoss)


    def _pong(self, member, noun):
        """Called by the low-level protocol when a pong is received."""
        
        #self.logger.debug("pong<- %s", member)
        assert isinstance(member, fireflies.members.Member)
        nPing, avgLoss = self.__memberInfo[member]
        if nPing == 0:
            return
            
        assert avgLoss >= 1.0
        avgLoss = (self.smoothing * avgLoss) + ( (1. - self.smoothing) * (nPing))
        nPing = 0
        self.__memberInfo[member] = (nPing, avgLoss)


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
    
    def __init__(self, toSn, fromSn, noun):
        self.fromSn = fromSn
        self.toSn = toSn
        self.noun = noun
        self.signature = 0

    def __setstate__(self, data):
        for k,v in data.items():
            setattr(self, k, v)
         
    def uidstr(self):
        return "ping-%x-%x-%d" % (bytes_to_long(self.fromSn), bytes_to_long(self.toSn), self.noun)

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
        self.pack_uint(ping.noun)
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
        noun = self.unpack_uint()
        signature = self.unpack_signature()

        d = {'fromSn': fromSn,
             'toSn': toSn,
             'noun': noun,
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
    
class PingPong(DatagramProtocol):
    """Ping-Pong protocol."""
    
    def __init__(self, service):
        #DatagramProtocol.__init__(self)
        self.service = self.factory = service
    
    def handle_ping(self, fromIP, fromPort, ping):
        f = self.factory 
        assert isinstance(f, FailureDetector)
        assert isinstance(ping, Ping)
        g = f._group        
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
        g = f._group
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
        f._pong(sender, pong.ping.noun)
                                
        
    def ping(self, toMember, noun):
        """Send a ping containing noun to member."""
        
        if not isinstance(toMember, fireflies.members.Member): raise ValueError        
        f = self.factory
        assert isinstance(f, FailureDetector)
        g = f._group
        sk = g.key
        
        ping = Ping(toMember.getSerial(), g.peer.getSerial(), noun)
        sk.sign(ping)        
        p = FDPacker()
        p.pack_uint(_cmd2code["ping"])
        p.pack_ping(ping)        
        data = p.get_buffer()
        #self.factory.rings.stats.udpW += len(data)
        h, p = toMember.getAddress().split(":")
        p = int(p)
        self.transport.write(data, (h, p))
        self.logger.warning("ping-> %s %d", toMember, noun)
   

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

