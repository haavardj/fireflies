        
class ChanneledPeerFactory(Peer):        
    """Maintains the active/inactive and allowed/disallowed states of a member
    based on a set of channels. A channel can be any class of object.

    This class implements the following rules:
      - The member is only active if it is activated on one or more channels.
      - The memmer is only allowed if it is allowed on one or more channels.     
    """
    
    def __init__(self, member):
        Peer.__init__(self, member)
        self.activeL = []
        self.allowL = []
        
    def activateOn(self, x):
        assert x not in self.activeL
        empty = not bool(self.activeL)
        self.activeL.append(x)
        if empty: 
            assert not self.isActive()
            self.activate()
    
    def deactivateOn(self, x): 
        assert x in self.activeL
        assert self.isActive()
        self.activeL.remove(x)
        if not self.activeL:
            self.deactivate()
    
    def allowOn(self, x):
        assert x not in self.allowL
        empty = not bool(self.allowL)
        self.allowL.append(x)
        if empty: 
            assert not self.isAllowed()
            self.allow()
        else:
            assert self.isAllowed()
        
    def disallowOn(self, x): 
        assert x in self.allowL
        assert self.isAllowed()
        self.allowL.remove(x)
        if not self.allowL:
            self.disallow()




class Mesh(twisted.internet.protocol.ServerFactory):
    
    
    group = None
    peerFactoryClass = ChanneledPeerFactory
        
    def __init__(self, me, k=8):
        self.k = k
        if not isinstance(me, fireflies.members.Member): raise ValueError
        self.me = me
        self.group = me.group
        self.group.ensureNumRings(k)
        self.logger = logging.getLogger(me.getAddress())      
        
        self.outbound = [None] * k
        self.inbound = [None] * k
        self.peerPool = {}
        
    def startFactory(self):
        self.group.register(self, membershipEv=True)
        reactor.callLater(0, self.update)
        
    def evRecover(self, member, reason):
        self.update()
    
    def evCrash(self, member, reason):
        self.update()

    def getPeerFromMember(self, member):
        if not self.peerPool.has_key(member): 
            self.peerPool[member] = self.peerFactoryClass(member)
        return self.peerPool[member]

    def update(self):
        for x, ring in enumerate(self.group.rings[0:self.k]):
            # Set outbound
            cg = self.outbound[x]
            partnerOnX = ring.succ(self.me, lambda x: not x.isFailed())
            if (not partnerOnX) or (partnerOnX == self.me):
                if cg: cg.deactivateOn(x)
                self.outbound[x] = None                
            else:
                f = self.getPeerFromMember(partnerOnX)
                if (not cg) or (cg != f): 
                    if cg: cg.deactivateOn(x)
                    f.activateOn(x)
                    self.outbound[x] = f
    
            # Set inbound
            cg = self.inbound[x]
            partnerOnX = ring.pred(self.me, lambda x: not x.isFailed())
            if (not partnerOnX) or (partnerOnX == self.me):
                if cg: cg.disallowOn(x)
                self.inbound[x] = None
            else:
                f = self.getPeerFromMember(partnerOnX)
                if (not cg) or (cg != f): 
                    if cg: cg.disallowOn(x)
                    f.allowOn(x)
                    self.inbound[x] = f
                    
    def _failback(self, reason):
        self.logger.exception(reason)

    def buildProtocol(self, address):
        p = self.protocol()
        p.mesh = self.mesh
        p.server = False
        return p

