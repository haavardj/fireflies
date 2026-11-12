"""Group state, wire format and persistence (no C++ extension needed)."""

import shutil
import tempfile

from twisted.trial import unittest

import fireflies
import fireflies.fd
import fireflies.group
from fireflies import crypto, packer, persist, state, xdr
from fireflies.test.helpers import makeCA, makeMember, noteOf

from typing import TYPE_CHECKING, Any

# The mixins below use TestCase methods; tell the type checker so without
# making them test cases trial would collect.
if TYPE_CHECKING:
    _TestCase = unittest.TestCase
else:
    _TestCase = object


class XDRTest(unittest.TestCase):

    def testRoundTrip(self):
        p = xdr.Packer()
        p.pack_uint(7)
        p.pack_int(-3)
        p.pack_bool(True)
        p.pack_fstring(3, b"abc")
        p.pack_string(b"hello")
        p.pack_string("text")
        buf = p.get_buffer()
        self.assertEqual(len(buf) % 4, 0)

        u = xdr.Unpacker(buf)
        self.assertEqual(u.unpack_uint(), 7)
        self.assertEqual(u.unpack_int(), -3)
        self.assertTrue(u.unpack_bool())
        self.assertEqual(u.unpack_fstring(3), b"abc")
        self.assertEqual(u.unpack_string(), b"hello")
        self.assertEqual(u.unpack_string(), b"text")
        u.done()

    def testLeftoverData(self):
        p = xdr.Packer()
        p.pack_uint(1)
        p.pack_uint(2)
        u = xdr.Unpacker(p.get_buffer())
        u.unpack_uint()
        self.assertRaises(xdr.Error, u.done)

    def testShortData(self):
        self.assertRaises(EOFError, xdr.Unpacker(b"\x00\x00").unpack_uint)


class _GroupTestBase(_TestCase):

    ecc = False

    def setUp(self):
        self.caCert, self.caKey = makeCA(self.ecc)
        self.certs, self.keys = [], []
        for i in range(3):
            c, k = makeMember(self.caCert, self.caKey, "127.0.0.1:%d" % (12000 + i), i + 1, self.ecc)
            self.certs.append(c)
            self.keys.append(k)
        self.group = fireflies.group.Group(self.caCert, self.keys[0], self.certs[0])
        for c in self.certs[1:]:
            self.group.view.addCertificate(c)
        self.me = self.group.getMe()
        self.other = self.group.view.getMemberByCertificate(self.certs[1])

    def tearDown(self):
        # Group.notify schedules callbacks; cancel them.
        from fireflies.util import reactor
        for call in reactor.getDelayedCalls():
            call.cancel()


class _GroupStateTests(_GroupTestBase):

    def testMembers(self):
        self.assertEqual(len(self.group.getAllMembers()), 3)
        self.assertEqual(self.me.getAddress(), "127.0.0.1:12000")
        self.assertEqual(self.me.address.port, 12000)
        self.assertEqual(self.group.nrMonitoringRings(), 7)
        self.assertEqual(self.group.nrGossipingRings(), 3)

    def testMemberHashAndOrder(self):
        again = self.group.view.getMemberByIdentity(self.me.identity)
        self.assertEqual({self.me: 1}[again], 1)
        self.assertNotEqual(self.me, self.other)
        self.assertEqual(sorted([self.other, self.me]),
                         sorted([self.me, self.other]))

    def testInitialNote(self):
        n = noteOf(self.me)
        self.assertTrue(n.verify(self.me.getPublicKey()))
        self.assertFalse(n.verify(self.other.getPublicKey()))
        self.assertTrue(state.isValidMask(n.mask, 7))

    def testNextEpoch(self):
        self.group.nextEpoch()
        self.assertEqual(self.me.getEpoch(), 2)

    def testRejectForeignCertificate(self):
        otherCA, otherKey = makeCA(self.ecc, "other")
        c, k = makeMember(otherCA, otherKey, "127.0.0.1:13000", 1, self.ecc)
        self.assertRaises(ValueError, self.group.view.addCertificate, c)

    def testRejectBadNoteSignature(self):
        n = self.me.nextNote()
        n.sign(self.keys[1])
        self.assertRaises(ValueError, self.group.view.addNote, n)


class _WireFormatTests(_GroupTestBase):

    def roundTrip(self, cmd: str, *args: Any) -> Any:
        return packer.unpackMessage(packer.PackMessage(cmd, *args))

    def testNote(self):
        n = noteOf(self.me)
        cmd, (n2,) = self.roundTrip("partner", n)
        self.assertEqual(cmd, "partner")
        self.assertEqual(n2.uidstr(), n.uidstr())
        self.assertEqual(n2.get_fingerprint(), n.get_fingerprint())
        self.assertTrue(n2.verify(self.me.getPublicKey()))

    def testAccusation(self):
        a = state.Accusation(self.me.identity, 1, self.other.identity)
        a.sign(self.keys[1])
        cmd, (a2,) = self.roundTrip("data", a)
        self.assertEqual(a2, a)
        self.assertEqual(hash(a2), hash(a))
        self.assertTrue(a2.verify(self.other.getPublicKey()))

    def testCertificate(self):
        cmd, (c,) = self.roundTrip("reconcile_data", self.certs[2])
        self.assertEqual(c, self.certs[2])

    def testRedirect(self):
        cmd, (lst,) = self.roundTrip("redirect", [(self.certs[1], self.me.getNote())])
        self.assertEqual(lst[0][0], self.certs[1])
        self.assertEqual(lst[0][1].uidstr(), noteOf(self.me).uidstr())

    def testControlMessages(self):
        self.assertEqual(self.roundTrip("version", 0, 3, 0), ("version", (0, 3, 0)))
        self.assertEqual(self.roundTrip("reconcile", "nSet", b"\x00\xff"),
                         ("reconcile", ("nSet", b"\x00\xff")))
        self.assertEqual(self.roundTrip("digest_match", True), ("digest_match", (True,)))
        self.assertEqual(self.roundTrip("accepted"), ("accepted", ()))

    def testMask(self):
        for mask in ([True], [False, True, True], [True] * 9 + [False] * 8, [False] * 255):
            p = packer.FirefliesPacker()
            p.pack_mask(mask)
            u = packer.FirefliesUnpacker(p.get_buffer())
            self.assertEqual(u.unpack_mask(), mask)
            u.done()

    def testPing(self):
        ping = fireflies.fd.PingMsg(self.me.identity, self.other.identity)
        ping.sign(self.keys[0])
        for msg in (ping, fireflies.fd.PongMsg(ping)):
            if isinstance(msg, fireflies.fd.PongMsg):
                msg.sign(self.keys[1])
            p = fireflies.fd.FDMsgPacker()
            p.pack_msg(msg)
            u = fireflies.fd.FDMsgUnpacker(p.get_buffer())
            m2 = u.unpack_msg()
            u.done()
            self.assertEqual(type(m2), type(msg))
            self.assertEqual(m2.uidstr(), msg.uidstr())
        self.assertTrue(m2.verify(self.other.getPublicKey()))


class _PersistTests(_GroupTestBase):

    def setUp(self):
        _GroupTestBase.setUp(self)
        self.dir = tempfile.mkdtemp()
        self.store = persist.Store(self.dir)

    def tearDown(self):
        _GroupTestBase.tearDown(self)
        shutil.rmtree(self.dir, ignore_errors=True)

    def testCA(self):
        self.store.saveCACert(self.caCert)
        self.store.saveCaPrivKey(self.caKey, "secret")
        self.assertEqual(self.store.loadCACertificate(), self.caCert)
        self.assertEqual(self.store.loadCAKey("secret").as_der(), self.caKey.as_der())
        self.assertRaises(ValueError, self.store.loadCAKey, None)

    def testUnencryptedKeyIgnoresPassword(self):
        self.store.savePrivateKey(self.keys[1], None)
        k = self.store.loadPrivateKeyForCert(self.certs[1], "unused")
        self.assertEqual(k.as_der(), self.keys[1].as_der())

    def testNewMemberCertificate(self):
        self.store.saveCACert(self.caCert)
        key = crypto.makePrivateKey(self.ecc)
        c1 = self.store.newMemberCertificate(crypto.makeRequest("10.0.0.1:1", key), self.caKey)
        c2 = self.store.newMemberCertificate(crypto.makeRequest("10.0.0.2:1", key), self.caKey)
        self.assertEqual(c2.get_serial_number(), c1.get_serial_number() + 1)
        self.assertEqual(self.store.loadMemberCertificateByAddress("10.0.0.2:1"), c2)
        self.assertTrue(self.store.hasMemberCertificate(c1))

    def testGroup(self):
        a = state.Accusation(self.me.identity, 1, self.other.identity)
        a.sign(self.keys[1])
        self.store.saveAccusation(a)
        self.store.saveGroup(self.group)
        self.assertEqual(len(self.store.loadMemberCertificates()), 3)
        self.assertEqual(self.store.loadNoteFromCert(self.certs[0]).uidstr(),
                         noteOf(self.me).uidstr())
        self.assertEqual(self.store.loadAccusations(), [a])


class RSAGroupStateTest(_GroupStateTests, unittest.TestCase):
    pass


class ECGroupStateTest(_GroupStateTests, unittest.TestCase):
    ecc = True


class RSAWireFormatTest(_WireFormatTests, unittest.TestCase):
    pass


class ECWireFormatTest(_WireFormatTests, unittest.TestCase):
    ecc = True


class RSAPersistTest(_PersistTests, unittest.TestCase):
    pass


class ECPersistTest(_PersistTests, unittest.TestCase):
    ecc = True
