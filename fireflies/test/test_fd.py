from fireflies import ring, fd, crypto, group
import random
from twisted.trial import unittest
from twisted.internet import defer, reactor, error, address
from zope.interface import implements


def main():
    unittest.main()
    
def createTestCA(name=""):
    if not name:
        name = str(random.randint(0,2**128))        
    caKey = crypto.makePrivateKey(callback=lambda x: None)
    caCert = crypto.makeCACert(caKey, name, 13) 
    return caCert, caKey

_lastAddused = 0
def createTestNode(caCert, caKey):
    global _lastAddused
    
    if _lastAddused > 255: 
        raise NotImplementedError, "We do not support more than 255 testmembers."

    _lastAddused += 1
    addr = "127.0.0.%d:12321" % _lastAddused
    key = crypto.makePrivateKey(callback=lambda x: None)
    req = crypto.makeRequest(addr, key)
    cert = crypto.makeCert(req, caCert, caKey, sn=0)         
    return group.Group(caCert, key, cert)   


class ExpSmoothedTimeoutPolicyTest(unittest.TestCase):
    
    def testPingCount(self):
        m = fd.ExpSmoothedTimeoutPolicy()
        
        for x in range(10):
            m.pinged()            
            self.assertEqual(x+1, m.nPing)
            
    def testAvgLossEstimation(self):        
        m = fd.ExpSmoothedTimeoutPolicy()  
        m.smoothing = 0.994
        
        for y in [0, 1, 2, 3, 4, 10, 100]:
            m.avgLoss = float(y) +1
            for x in range(100):
                m.pinged()                    
                for j in range(y): m.pinged()                    
                m.ponged()
            self.failUnlessAlmostEqual(m.avgLoss, y+1.0, 4)

    def testAvgLossEstimationFromCloseStart(self):        
        m = fd.ExpSmoothedTimeoutPolicy()  
        m.smoothing = 0.990
        
        for y in [0, 1, 2, 3, 4, 10, 100]:
            m.avgLoss = y + 1 * (1+ random.random())
            for x in range(1000):
                m.pinged()                    
                for j in range(y): m.pinged()                    
                m.ponged()
            self.failUnlessAlmostEqual(m.avgLoss, y+1.0, 4)

    def testTimedOut(self):
        m = fd.ExpSmoothedTimeoutPolicy()        

        for x in range(100):
            m.pinged()           
        self.assertTrue(m.isTimedOut())
        m.ponged()
        self.assertFalse(m.isTimedOut())

class MonitorableObject:
    def ping(self): pass
    def fail(self): pass
    
class PingConsumer:
    
    def __init__(self, producer):
        self.producer = producer
        
    def consume(self, obj):
        self.producer.pinged(obj)
        if self.producer.running: 
            reactor.callLater(0, self.reqNext)
            
    def reqNext(self):
        d = self.producer.next()
        d.addCallback(self.consume)


class UDPPingProtocolFromService:
    
    def __init__(self, service):
        self.service = service

    def consume(self, obj):
        self.service.pinged(obj)               
        if self.service.running: reactor.callLater(0, self.reqNext)
            
    def reqNext(self):
        d = self.service.next()
        d.addCallback(self.service)
        
    def startConsuming(self):
        self.reqNext()
        
            
class MonitorManagerTest(unittest.TestCase):
    
    def setUp(self):
        pass        

    def testAddRemove(self):        
        man = fd.MonitorManager()
        man.interval = 0.1
        o1 = MonitorableObject()
        d = man.monitor(o1)
        self.failUnlessIn(o1, man)
        man.cancel(o1)        
        self.failIfIn(o1, man)
        return d

    def testPingUntilFailed(self):                
        
        man = fd.MonitorManager()
        man.interval = 0.1
        obj = MonitorableObject()
        d = man.monitor(obj)        
        
        man.startService()        
        c = PingConsumer(man)
        reactor.callLater(0, c.reqNext)
        
        def _cb(result):
            man.stopService()
            return result
        
        def _eb(err):
            err.trap(error.TimeoutError)
            man.stopService()
        
        d.addCallback(_cb)
        d.addErrback(_eb)            
        return d
                
    def monfailed(self, err):
        err.trap(error.TimeoutError)
            
        
class RandomTestMember:

    uid = ""
    
    
    def __init__(self, host, port):
        self.uid = random.getrandbits(128)
        self.address = address.IPv4Address("TCP", host, port)
                
    @property
    def fingerprint(self):
        return self.uid
    

class SimulatedDatagramTransport:
    
    def __init__(self, receiver):
        self.receiver = receiver
    
    def write(*args):
        self.receiver.datagramReceived(*args)
        
class QueueTransport(defer.DeferredQueue):
    def write(self, *args):
        self.put(args)
        


class SignedDatagramProtocolTest(unittest.TestCase):
    
    def setUp(self):
    
        self.protocol1 = fd.SignedDatagramProtocol()
        self.protocol2 = fd.SignedDatagramProtocol()
        port1 = reactor.listenUDP(12345, self.protocol1, interface="127.0.0.1")
        port2 = reactor.listenUDP(12345, self.protocol2, interface="127.0.0.2")        
        self.ports = [port1, port2]
        for p in self.ports:
            print id(p), p, type(p)
        
        
    def testData(self):
        pass
        
        
    def tearDown(self):
        l = map(lambda x: defer.maybeDeferred(x.stopListening), self.ports)
        return defer.DeferredList(l)
        
class UDPPingerProtocolSimulatedTest(unittest.TestCase): 
    
#    def setUp(self):
        
        #caCert, caKey = createTestCA()                
        #self.m1Node = createTestNode(caCert, caKey)      
        #self.m2Node = createTestNode(caCert, caKey)      

        #self.m1Node.addCertificate(self.m2Node.getMe().getCertificate())
        #self.m2Node.addCertificate(self.m1Node.getMe().getCertificate())
        
        #self.m1FD = fd.FailureDetector(self.m1Node)
        #self.m2FD = fd.FailureDetector(self.m2Node)
 
        #self.m1FD.setServiceParent(self.m1Node)
        #self.m2FD.setServiceParent(self.m2Node)
        
        #l = [
            #defer.maybeDeferred(self.m1Node.startService),
            #defer.maybeDeferred(self.m2Node.startService)
         #   ]
               
        
 #       return defer.DeferredList(l)
        
  #  def tearDown(self):
        #l = [
        #    defer.maybeDeferred(self.m1Node.stopService),
        #    defer.maybeDeferred(self.port1.stopListening),
            #defer.maybeDeferred(self.m2Node.stopService)            
      #      ]
        #return defer.DeferredList(l)


    def PASStestShort(self):
        
        manager = fd.MonitorManager()
        serializer = fd.Serializer()        
        protocol = fd.UDPPingerProtocol()
        protocol.factory = manager
        protocol.verifier = fd.Verifier()
        protocol.serializer = serializer
        

    def testReceivePingMsg(self):
        manager = fd.MonitorManager()
        serializer = fd.Serializer()        
        protocol = fd.UDPPingerProtocol()
        protocol.factory = manager
        protocol.verifier = fd.Verifier()
        protocol.serializer = serializer
        m1 = RandomTestMember("127.0.0.1", 12345)
        m2 = RandomTestMember("127.0.0.2", 12345)
	
        serializer.registerObjectMapping(m1.fingerprint, m1)
        serializer.registerObjectMapping(m2.fingerprint, m2)
        
        manager.monitor(m1)
        manager.monitor(m2)
        
        msg = fd.PingMsg(m1, m2)
        p = serializer.serializer()
        p.pack_msg(msg)
        data = p.get_buffer()

        def _(result):
            data, (host, port) = result
                    
        protocol.transport = QueueTransport()
        d = protocol.transport.get()
        d.addCallback(_)
        
        protocol.datagramReceived(data, (m1.address.host, m1.address.port))
        return d
        
if __name__ == "__main__":
    main()
