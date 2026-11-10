import logging
from fireflies.channel import TypedChannel, RemoteMethod
from fireflies.protocols import UnsecuredDatagramProtocol
import random
from math import *    
from twisted.internet import defer, task
from fireflies.channel import TypedChannel


class FailureDetector(TypedChannel):
    
    name = "pinger"
    roundTime = 5
    pmistake = 0.001
    smoothing = 0.999
    tmin = 3
    log = logging.getLogger("FailureDetector")
    protocol = None
    
    def startService(self):
        super(FailureDetector, self).startService()   
        me = self.getRootService().me
        self.log.info("Binding to UDP:%s", me.address)
        
        self.protocol = UnsecuredDatagramProtocol()
        self.protocol.factory = self
        self._port = twisted.internet.reactor.listenUDP(me.address.port, self.protocol, interface=me.address.host)        
        
    def stopService(self):
        super(FailureDetector, self).stopService()
        self._port.stopListening()
                
    def message_ping(self, member, remoteOID):
        print "got ping", member, remoteOID
        self.sendMessage(member, remoteOID, "pong")
        
    def sendMessage(self, member, remoteOID, type, *args, **kwargs):
        self.protocol.sendMessage(self, member, self.localOID(), remoteOID, type, *args, **kwargs)    

    def monitor(self, member):
        t = MemberMonitor(member)
        t.setServiceParent(self)
        

class MemberMonitor(TypedChannel):
    
    avgLoss = .1
    pMistake = 0.001
    smooting = 0.999
    tMin = 3
    nPing = 0
    interval = 2
    member = None

    def __init__(self, member):
        self.member = member
        self.name = member.identity()
            
    def startService(self):
        self._task = task.LoopingCall(self.update)
        self._task.start(self.interval, now=False)
        super(TypedChannel, self).startService()
    
    def stopService(self):
        self._task.stop()
        super(TypedChannel, self).stopService()
        
    def update(self):
        self.ping()
        
    def message_pong(self):
        assert self.avgLoss >= 1.0
        self.avgLoss = (self.smooting * self.avgLoss) + ( (1. - self.smoothing) * (self.nPing))
        self.nPing = 0
    
    def ping(self):        
        p = min( 1./self.avgLoss, 1. - self.pMistake**(1./float(max(self.tMin, 1))))
        assert p < 1.0 and p > 0.0, "Psuc out of bounds."
            
        t = log(self.pMistake) / log(1. - p)

        if self.nPing > t:
            self.member.accuse()                  
            self.nPing = 0
            
        else:
            self.parent.sendMessage(self.member, "ping")
            self.nPing += 1
