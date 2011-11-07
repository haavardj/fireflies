import twisted
from twisted.trial import unittest
from twisted.internet import reactor, defer, error

from fireflies import crypto, group, fd, protocols,state
import M2Crypto
import logging


logging.basicConfig()
logging.getLogger().setLevel(logging.DEBUG)

def disconnect(val, peer):
    peer.deactivate()
    return val           

def anyMember(m, view):
    return filter(lambda x: x != m, view.members).pop()


class FDTest(unittest.TestCase):

    timeout = 10

    def setUp(self):
        
        self.caKey = crypto.makePrivateKey(callback=lambda x: None)
        self.caCert = crypto.makeCACert(self.caKey, "test", 25)   
        
        self.m1Key = crypto.makePrivateKey(callback=lambda x: None)
        req = crypto.makeRequest("127.0.0.1:12321", self.m1Key)
        self.m1Cert = crypto.makeCert(req, self.caCert, self.caKey, sn=0)     
        self.m1Node = group.Group(self.caCert, self.m1Key, self.m1Cert)       
        note = state.createInitialNote(self.m1Node.getMe())
        note.sign(self.m1Key)
        self.m1Node.getView().addNote(note)
        
        
        self.m2Key = crypto.makePrivateKey(callback=lambda x: None)
        req = crypto.makeRequest("127.0.0.2:12322", self.m2Key)
        self.m2Cert = crypto.makeCert(req, self.caCert, self.caKey, sn=1)        
        self.m2Node = group.Group(self.caCert, self.m2Key, self.m2Cert)   
        note = state.createInitialNote(self.m2Node.getMe())
        note.sign(self.m2Key)
        self.m2Node.getView().addNote(note)


        self.m1Node.getView().addCertificate(self.m2Node.getMe().getCertificate())
        self.m2Node.getView().addCertificate(self.m1Node.getMe().getCertificate())

        self.m1Node.getView().addNote(self.m2Node.getMe().getNote())
        self.m2Node.getView().addNote(self.m1Node.getMe().getNote())


 
        self.m1FD = fd.FailureDetector(self.m1Node)
        self.m2FD = fd.FailureDetector(self.m2Node)
        self.m1FD.setServiceParent(self.m1Node)
        self.m2FD.setServiceParent(self.m2Node)
        
        l = [
            defer.maybeDeferred(self.m1Node.startService),
            defer.maybeDeferred(self.m2Node.startService)
            ]
        return defer.DeferredList(l)
            
    def tearDown(self):
        l = [
            defer.maybeDeferred(self.m1Node.stopService),
            defer.maybeDeferred(self.m2Node.stopService)            
            ]
        return defer.DeferredList(l)
    
    def PASStestNOOP(self):
        pass

    def testPing(self):
        
        d = defer.Deferred()
        reactor.callLater(10, d.callback, None)        
        return d


        
        
        
