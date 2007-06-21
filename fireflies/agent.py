import fireflies.members, fireflies.agent, fireflies.crypto, fireflies.group
from twisted.application import internet, service
from twisted.internet import defer

class Agent(service.MultiService):
       
    fd = None
    group = None
    mesh = None
    member = None
    memberKey = None
    
    def __init__(self, groupCA):
        service.MultiService.__init__(self)
        self.group = fireflies.group.Group(groupCA)
        
    def setMember(self, memberCA, memberKey, memberNote=None):
        if not isinstance(memberCA, fireflies.crypto.MemberCertificate): raise ValueError
        if not isinstance(memberKey, fireflies.crypto.MemberKey): raise ValueError
        self.memberKey = memberKey
        if not memberNote:
            memberNote= fireflies.members.createInitialNote(memberCA.serial, self.group.getGroupCertificate().config['T']) 
        self.group.addCertificate(memberCA)
        self.member = self.group.getMemberBySerial(memberCA.serial)
        isinstance(self.member, fireflies.members.Member)
        self.group.addNote(memberNote)        
        return self.member

    def setFailureDetector(self, fd):
        assert not self.fd
        self.fd = fd
        self.fd.setServiceParent(self)

    def setGossipMesh(self, mesh):
        assert not self.mesh
        self.mesh = mesh
        self.mesh.setServiceParent(self)


def join(groupCertificate, memberKey, memberCertificate, memberNote):
    """Join a fireflies group.
    
    @type groupCertificate: C{firefles.crypto.CACertificate}
    @type memberKey: C{ireflies.crypto.MemberKey}
    @type memberCertificate: C{fireflies.crypto.MemberCertificate}
    @rtype: C{Agent}
    """
    
    if not isinstance(groupCertificate, fireflies.crypto.CACertificate): raise ValueError
    if not isinstance(memberKey, fireflies.crypto.MemberKey): raise ValueError
    if not isinstance(memberCertificate, fireflies.crypto.MemberCertificate): raise ValueError
    if not isinstance(memberNote, fireflies.members.Note): raise ValueError    
    agent = Agent(groupCertificate)
    member = agent.setMember(memberCertificate, memberKey, memberNote)
    #host, port = agent.member.getAddress().split(":")
    #port = int(port)
    #internet.UDPServer(port, f.protocol, interface=host).setServiceParent(app)
    #g = fireflies.gossip.Gossip(agent.group)
    #g.setPrivate(member, memberKey)
    #agent.setGossipMesh(g)
    #internet.TCPServer(port, gossip.FFServerFactory(p), interface=host).setServiceParent(agent)
    return agent

def joinFromSerializedAgent(path):
    raise NotImplementedError

def joinFromGroupPrivate(groupKey, groupCertificate, port=fireflies.defaultPort, interface=""):   
    """Join a fireflies group.
    
    @type groupCertificate: C{firefles.crypto.CACertificate}
    @type groupKey: C{ireflies.crypto.CAKey}
    @type port: C{int}
    @type interface: C{string}
    @rtype: C{Agent}
    """
        
    if not isinstance(groupKey, fireflies.crypto.CAKey): raise ValueError
    if not isinstance(groupCertificate, fireflies.crypto.CACertificate): raise ValueError    
    if interface == "":
        import socket
        interface = socket.gethostbyname(socket.getfqdn())
    memberKey = fireflies.crypto.MemberKey("%s:%d" % (interface, port))
    memberCertificate = memberKey.getCertificate()
    groupKey.sign(memberCertificate)
    memberNote = fireflies.members.createInitialNote(memberCertificate.serial, groupCertificate.config['t'])    
    memberKey.sign(memberNote)
    return join(groupCertificate, memberKey, memberCertificate, memberNote)
      