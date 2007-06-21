#import fireflies.group, fireflies.members
from zope.interface import Interface, implements
from twisted.python import components
from twisted.internet import reactor, task
import twisted.application.service
import twisted.protocols
import twisted.protocols.basic
import twisted, logging

import fireflies
import fireflies.members

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
    'version': 0x9,
    'patch': 0xa,
    'notify': 0xb,
    'key': 0xc,
    'recover': 0xd,
    'request': 0xe
}

code2cmd = {}
for k, v in cmd2code.items():
    code2cmd[v] = k



class TimeoutMixin:
    """Implements a timeout mechanism."""
    
    __timeoutCall = None
    timeout = 120.0
    
    def startTimer(self, timeout=timeout):
        if self.__timeoutCall != None: raise RuntimeError
        self.__timeoutCall = reactor.callLater(timeout, self.__timedOut)

    def stopTimer(self):
        self.__timeoutCall.cancel()
        self.__timeoutCall = None
    
    def __timedOut(self):
        assert self.__timeoutCall != None
        self.__timeoutCall = None
        self.timedOut()
        
    def timedOut(self):
        raise NotImplementedError


serializer_registry = {}



class Message:
    data = ""
    type = 0
        
    def setData(self, data): 
        self.data = data
        
    def getData(self):
        return data

    
import xdrlib    

class FirefliesMessagingProtocol(twisted.protocols.basic.Int32StringReceiver):

    MAX_LENGTH = 1000000

    def sendMessage(self, message):
        p = fireflies.packer.FirefliesPacker()
        p.pack_uin(message.type)
        p.pack_string(message.getData())
        self.sendString(p.get_buffer())

    def stringReceived(self, data):
        up = fireflies.packer.FirefliesUnpacker(data)
        type = up.unpack_uint()
        data = up.unpack_string()
        up.done()
        m = Message()
        m.setData(data)
        self.messageReceived(m)

    def messageReceived(self, message):
        raise NotImplementedError


class FirefliesChannelingProtocol(FirefliesMessagingProtocol):

    def __init__(self):
        self.channels = {0:self}
        self.cId = 1
    
    def registerChannel(self, channel):
        self.channels[self.cId] = channel
        self.cId += 1
        

        
        

class FirefliesProtocol(twisted.protocols.basic.Int32StringReceiver, TimeoutMixin):
  
    server = True
    attached = False
    group = None
    peer = None
    cid = 0
    
    portal = None
    pending_requests = {}
    
    def connectionMade(self):
        self.cid = FirefliesProtocol.cid
        FirefliesProtocol.cid += 1
     

        self.sendMessage(VersionMessage(*fireflies.protocol_version))
     
        self.sendMessage(AuthenticateMessage(self.portal.getCredentials()))
     
  
        logging.debug("authenticate-> %s %s-%s server=%s", self, crt, note, str(self.server))
        self.startTimer()

    def redirect(self, elms):
        self.sendCommand("redirect", elms)
        self.hangup()

    def timedOut(self):
        if self.transport: self.transport.loseConnection()
        
    def connectionLost(self, reason=twisted.internet.protocol.connectionDone):
        self.factory.logger.debug("%s connectionLost server=%s attached=%s", self, self.server, self.attached)
        if self.attached: self.factory.detach(self)
        self.attached = False

    def handle_version(self, major, minor, patchlevel):
        #
        # TODO: The node will die if it has an old version
        # number. This is VERY INSECURE and will be removed. However,
        # it is nice for testing on PlanetLab.
        # 
        if (major, minor, patchlevel) > fireflies.protocol_version:
            self.factory.logger.warning("authenticate<- %s Version error. I have an old version. Exiting.", self)
            self.hangup()
            reactor.callLater(2, reactor.stop)
        elif (major, minor, patchlevel) < fireflies.protocol_version:
            self.factory.logger.warning("authenticate<- %s Version error. Other have an old version. Exiting.", self)

    def handle_authenticate(self, crt, note):
        self.stopTimer()
        group = self.mesh.group
        isinstance(group, fireflies.group.Group) 
        self.factory.logger.debug("authenticate<- %s %s %s server=%s", self, crt, note, str(self.server))

        if note.serial != crt.serial:
            self.mesh.logger.warning("authenticate<- %s Error. Note and crt serial do not match.", self)
            self.hangup()
            return

        group.addCertificate(crt)
        group.addNote(note)
        self.peer = self.mesh.getPeerFromMember(group.getMemberByCertificate(crt))
        isinstance(self.peer, PeerFactory)
                
        if self.isServer():
            reactor.callLater(self.peer.attach, self)


    def handle_redirect(self, l):
        view = self.factory.service.group
        isinstance(view, fireflies.group.Group)                
        for cert, note in l:
            view.addCertificate(cert)
            view.addNote(note)
        self.hangup()
            
    def handle_accepted(self):
        self.factory.logger.debug("accepted<- %s server=%s", self, self.server)
        if self.server:
            if not self.factory.isActive():
                self.factory.logger.debug("%s hangup. Not active server=True", self)
                self.hangup()
                return
        else:
            if not self.factory.isAllowed(): 
                self.factory.logger.debug("%s hangup. Not allowed server=False", self)
                self.hangup()
                return            
            
        if self.factory.attach(self):
            self.attached = True
            self.factory.logger.info("%s Attached. server=%d", self, self.server)
            if self.server: 
                self.factory.logger.debug("accepted->%s. server=%s", self, self.server)
                self.sendCommand("accepted")
                
            self.partnerConnected() 
        else:
            self.factory.logger.debug("%s hangup. Attach failed. server=%d", self, self.server)
            self.hangup()

    def partnerConnected(self): 
        raise NotImplementedError

    def sendString(self, data):
        #self.factory.service.peer.view.stats.tcpW += (len(data) + 4)
        return twisted.protocols.basic.Int32StringReceiver.sendString(self, data)

    def sendMessage(self, data):
        self.sendString(data)

    def sendCommand(self, cmd, *args):
        try:
            p = FirefliesPacker()

            p.pack_fstring(1, chr(cmd2code[cmd]))

            if cmd in ["partner"]:
                nr, = args
                p.pack_uint(nr)
            elif cmd == "authenticate":
                crt, note  = args
                p.pack_cert(crt)
                p.pack_note(note)
                #p.pack_uint(rn)
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
            elif cmd in ["accepted"]:
                # No arguments.
                pass                
            else:
                raise Exception, "Unknown command"

            self.sendString(p.get_buffer())

        except KeyboardInterrupt:
            raise
        except Exception, why:
            self.factory.logger.exception("Unable to send command %s. %s", cmd, why)

    def dataReceived(self, recd):
        #self.factory.service.peer.view.stats.tcpR += len(recd)
        return twisted.protocols.basic.Int32StringReceiver.dataReceived(self, recd)
 
    def stringReceived(self, data):
        return self.messageReceived(data)

    def messageReceived(self, data):
        try:
            cmd = "N/A"
            p = FirefliesUnpacker(data)
            cmd = code2cmd[ord(p.unpack_fstring(1))]
            args = ()
            if cmd in ["partner"]:
                args = (p.unpack_uint(),)
            elif cmd == "authenticate":
                args = (p.unpack_cert(), p.unpack_note()) #, p.unpack_uint())
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
            elif cmd in ["accepted"]:
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
         
    def hangup(self):
        if not self.transport: return
        self.transport.loseConnection()
        self.factory.logger.debug("%s hangup", self)

    def timedoutConnection(self):
        self.factory.logger.warning("%s timeout", self)
        self.hangup()
                
    def __repr__(self):
        if self.factory and (self.factory.member != self.factory.service.member):
            return "C:%d-%s" % (self.cid, self.factory.member.getCertificate().address)
        elif self.transport:
            addr = self.transport.getPeer()
            return "C:%d-%s:%d" % (self.cid, addr.host, addr.port)
        else:
            return "C:%d:-" % (self.cid)

    def isServer(self):
        return self.server
    





class PeerListeningFactoryWrapper:
    
    def __init__(self, factory):
        self.factory = factory
        
    def buildProtocol(self, address):
        p = self.factory.buildProtocol(address)
        p.server = True
        return p
    
