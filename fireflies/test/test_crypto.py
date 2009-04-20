#from twisted.trial import unittest
from twisted.trial import unittest
import fireflies
from fireflies import crypto


def noGeygens(): pass

class CertificateTest(unittest.TestCase):
        
    def setUp(self):
        self.caKey = crypto.makePrivateKey(callback=noGeygens)
        self.caCert = crypto.makeCACert(self.caKey, "test", 25)         
        self.mKey = crypto.makePrivateKey(callback=noGeygens)
        self.req = fireflies.crypto.makeRequest(str(0), self.mKey)
        self.mCert = fireflies.crypto.makeCert(self.req, self.caCert, self.caKey, sn=0)

    def testRequest(self):
        self.failUnless(self.req.verify(self.mKey))
        self.failUnless(self.req.verify(self.mCert.get_pubkey()))
        self.failIf(self.req.verify(self.caKey))
        self.failIf(self.req.verify(self.caCert.get_pubkey()))
                
    def testUniqueness(self):
        self.failIfEqual(self.caCert.as_der(), self.mCert.as_der())
        
    def testKeys(self):
        self.failUnless(self.caCert.verify(self.caCert.get_pubkey()))
        self.failUnless(self.caCert.verify(self.caKey))
        self.failIf(self.caCert.verify(self.mCert.get_pubkey()))
        self.failIf(self.caCert.verify(self.mKey))
        
        self.failUnless(self.mCert.verify(self.caCert.get_pubkey()))
        self.failUnless(self.mCert.verify(self.caKey))
        self.failIf(self.mCert.verify(self.mCert.get_pubkey()))
        self.failIf(self.mCert.verify(self.mKey))
        
    def testIdentity(self):
        
        pkey = self.caCert.get_pubkey()        
        id1 = crypto.subjectKeyIdentifierToID(crypto.computeKeyIdentifier(pkey))
        id2 = crypto.identityFromCertificate(self.caCert)
        self.failUnless(id2 == id1)

        pkey = self.mCert.get_pubkey()        
        id3 = crypto.subjectKeyIdentifierToID(crypto.computeKeyIdentifier(pkey))
        id4 = crypto.identityFromCertificate(self.mCert)
        self.failUnless(id2 == id1)
        
        self.failIf(id1 == id3)
        

    def testSignable(self):
        s1 = crypto.SignableString("testString")
        s1.sign(self.mKey)
        s2 = crypto.SignableString("testString")
        s2.sign(self.mKey)
        s3 = crypto.SignableString("testString")
        s3.sign(self.caKey)

        self.failUnlessEqual(s1.get_fingerprint(), s2.get_fingerprint(), s3.get_fingerprint())
        self.failUnless(s1.signature, s2.signature)
        self.failIfEqual(s1.signature, s3.signature)
 
        self.failUnless(s1.verify(self.mCert.get_pubkey()))
        self.failUnless(s2.verify(self.mKey))                        
        self.failUnless(s3.verify(self.caKey))                        
        
        self.failIf(s1.verify(self.caKey))
        
        
def main():
    unittest.main()




if __name__ == "__main__":
    main()