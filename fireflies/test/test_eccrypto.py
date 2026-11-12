
from twisted.trial import unittest

from fireflies import crypto


def noGeygens(): pass



class SubjectKeyIdentifierBugTest(unittest.TestCase):

    def setUp(self):
        self.caKey = crypto.makePrivateECKey()
        self.caCert = crypto.makeCACert(self.caKey, "test", 25, 5)         
        self.mKey = crypto.makePrivateECKey()
        self.req = crypto.makeRequest(str(0), self.mKey)
        self.mCert = crypto.makeCert(self.req, self.caCert, self.caKey, sn=1)

    
    def testAccess(self):
        
        for x in range(10):
            mKey = crypto.makePrivateECKey()
            req = crypto.makeRequest(str(x), mKey)
            mCert = crypto.makeCert(req, self.caCert, self.caKey, sn=x + 1)            
            mCert.verify(self.caCert.get_pubkey())
            crypto.identityFromCertificate(mCert)


class CertificateTest(unittest.TestCase):
        
    def setUp(self):
        self.caKey = crypto.makePrivateECKey()
        self.caCert = crypto.makeCACert(self.caKey, "test", 25, 5)         
        self.mKey = crypto.makePrivateECKey()
        self.req = crypto.makeRequest("127.0.0.1:1", self.mKey)
        self.mCert = crypto.makeCert(self.req, self.caCert, self.caKey, sn=1)

    def testRequest(self):
        self.assertTrue(self.req.verify(self.mKey))
        self.assertTrue(self.req.verify(self.mCert.get_pubkey()))
        self.assertFalse(self.req.verify(self.caKey))
        self.assertFalse(self.req.verify(self.caCert.get_pubkey()))
                
    def testUniqueness(self):
        self.assertNotEqual(self.caCert.as_der(), self.mCert.as_der())
        
    def testKeys(self):
        self.assertTrue(self.caCert.verify(self.caCert.get_pubkey()))
        self.assertTrue(self.caCert.verify(self.caKey))
        self.assertFalse(self.caCert.verify(self.mCert.get_pubkey()))
        self.assertFalse(self.caCert.verify(self.mKey))
        
        self.assertTrue(self.mCert.verify(self.caCert.get_pubkey()))
        self.assertTrue(self.mCert.verify(self.caKey))
        self.assertFalse(self.mCert.verify(self.mCert.get_pubkey()))
        self.assertFalse(self.mCert.verify(self.mKey))
        
    def testCaCertSigned(self):
        self.mCert.verify(self.caCert.get_pubkey())        
        
    def testIdentity(self):
        
        pkey = self.caCert.get_pubkey()        
        id1 = crypto.subjectKeyIdentifierToID(crypto.computeSubjectKeyIdentifier(pkey))
        id2 = crypto.identityFromCertificate(self.caCert)
        self.assertTrue(id2 == id1)

        pkey = self.mCert.get_pubkey()        
        id3 = crypto.subjectKeyIdentifierToID(crypto.computeSubjectKeyIdentifier(pkey))
        id4 = crypto.identityFromCertificate(self.mCert)
        self.assertTrue(id4 == id3)
        
        self.assertFalse(id1 == id3)
        

    def testSignable(self):
        s1 = crypto.SignableString("testString")
        s1.sign(self.mKey)
        s2 = crypto.SignableString("testString")
        s2.sign(self.mKey)
        s3 = crypto.SignableString("testString")
        s3.sign(self.caKey)


        self.assertEqual(s1.get_fingerprint(), s2.get_fingerprint(), s3.get_fingerprint())
        self.assertTrue(s1.signature, s2.signature)
        self.assertNotEqual(s1.signature, s3.signature)
 
        self.assertTrue(s1.verify(self.mCert.get_pubkey()))
        self.assertTrue(s2.verify(self.mKey))                        
        self.assertTrue(s3.verify(self.caKey))                        
        
        self.assertFalse(s1.verify(self.caKey))
        
    def testSignatureLenght(self):
 
        import fireflies.packer
        p = fireflies.packer.FirefliesPacker()
        p.pack_cert(self.caCert)
        
        print(len(p.get_buffer()))
