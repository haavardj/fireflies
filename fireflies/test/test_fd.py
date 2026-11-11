"""Failure detector: timeout policy and pong authentication."""

import random

from fireflies.util import reactor
from twisted.trial import unittest

import fireflies
import fireflies.group
import fireflies.view
from fireflies import fd
from fireflies.test.helpers import makeCA, makeMember


class ExpSmoothedTimeoutPolicyTest(unittest.TestCase):

    def testPingCount(self):
        m = fd.ExpSmoothedTimeoutPolicy()
        for x in range(10):
            m.pinged()
            self.assertEqual(x + 1, m.nPing)

    def testAvgLossEstimation(self):
        m = fd.ExpSmoothedTimeoutPolicy()
        m.smoothing = 0.994
        for y in [0, 1, 2, 3, 4, 10, 100]:
            m.avgLoss = float(y) + 1
            for x in range(100):
                m.pinged()
                for j in range(y): m.pinged()
                m.ponged()
            self.assertAlmostEqual(m.avgLoss, y + 1.0, 4)

    def testAvgLossEstimationFromCloseStart(self):
        m = fd.ExpSmoothedTimeoutPolicy()
        m.smoothing = 0.990
        for y in [0, 1, 2, 3, 4, 10, 100]:
            m.avgLoss = y + 1 * (1 + random.random())
            for x in range(1000):
                m.pinged()
                for j in range(y): m.pinged()
                m.ponged()
            self.assertAlmostEqual(m.avgLoss, y + 1.0, 4)

    def testTimedOut(self):
        m = fd.ExpSmoothedTimeoutPolicy()
        for x in range(100):
            m.pinged()
        self.assertTrue(m.isTimedOut())
        m.ponged()
        self.assertFalse(m.isTimedOut())

    def testThresholdAtLeastTMin(self):
        m = fd.ExpSmoothedTimeoutPolicy(tMin=3)
        for x in range(3):
            self.assertFalse(m.isTimedOut())
            m.pinged()

    def testPongWithoutPingKeepsEstimate(self):
        m = fd.ExpSmoothedTimeoutPolicy()
        before = m.avgLoss
        m.ponged()
        self.assertEqual(m.avgLoss, before)

    def testResetKeepsEstimate(self):
        m = fd.ExpSmoothedTimeoutPolicy()
        before = m.avgLoss
        for x in range(5): m.pinged()
        m.reset()
        self.assertEqual((m.nPing, m.avgLoss), (0, before))


class FakeTransport:

    def __init__(self):
        self.sent = []

    def write(self, data, addr):
        self.sent.append((data, addr))


def unpack(data):
    u = fd.FDMsgUnpacker(data)
    msg = u.unpack_msg()
    u.done()
    return msg


def pack(msg):
    p = fd.FDMsgPacker()
    p.pack_msg(msg)
    return p.get_buffer()


class PongAuthenticationTest(unittest.TestCase):
    """Member A monitors member B. C is a third member (the attacker)."""

    def setUp(self):
        ca, caKey = makeCA()
        creds = [makeMember(ca, caKey, "127.0.0.1:%d" % (25000 + i), i + 1) for i in range(3)]
        self.keys = [k for c, k in creds]
        self.groups = [fireflies.group.Group(ca, k, c) for c, k in creds]
        for g in self.groups:
            for other in self.groups:
                if other is not g:
                    g.view.addCertificate(other.getMe().getCertificate())
            for other in self.groups:
                if other is not g:
                    g.view.addNote(other.getMe().getNote())
        self.fds = []
        for g in self.groups:
            d = fd.FailureDetector(g)
            d.protocol = fd.PingPong()
            d.protocol.factory = d
            d.protocol.transport = FakeTransport()
            d.running = g.running = True
            self.fds.append(d)
        self.fdA, self.fdB, self.fdC = self.fds
        self.A, self.B, self.C = self.groups
        # B and C as seen from A.
        self.bAtA = self.A.view.getMemberByIdentity(self.B.getMe().identity)
        self.cAtA = self.A.view.getMemberByIdentity(self.C.getMe().identity)

    def tearDown(self):
        for call in reactor.getDelayedCalls():
            call.cancel()

    def deliver(self, src, dst):
        """Deliver everything src has sent to dst."""
        sent, src.protocol.transport.sent = src.protocol.transport.sent, []
        for data, addr in sent:
            dst.protocol.datagramReceived(data, ("127.0.0.1", 1))
        return [d for d, a in sent]

    def pingB(self):
        ping = self.fdA.protocol.ping(self.bAtA)
        self.fdA.getPolicy(self.bAtA).pinged()
        return ping

    def forgedPong(self, ping, key):
        pong = fd.PongMsg(ping)
        if key is not None:
            pong.sign(key)
        return pack(pong)

    def policy(self):
        return self.fdA.getPolicy(self.bAtA)

    def testGenuinePong(self):
        self.pingB()
        self.deliver(self.fdA, self.fdB)
        self.deliver(self.fdB, self.fdA)
        self.assertEqual(self.policy().nPing, 0)
        self.assertEqual(self.A.stats.pongsRejected, 0)

    def testPongSignedByOtherMemberRejected(self):
        ping = self.pingB()
        self.fdA.protocol.datagramReceived(self.forgedPong(ping, self.keys[2]), ("127.0.0.1", 1))
        self.assertEqual(self.policy().nPing, 1)
        self.assertEqual(self.A.stats.pongsRejected, 1)

    def testUnsignedPongRejected(self):
        ping = self.pingB()
        self.fdA.protocol.datagramReceived(self.forgedPong(ping, None), ("127.0.0.1", 1))
        self.assertEqual(self.policy().nPing, 1)
        self.assertEqual(self.A.stats.pongsRejected, 1)

    def testReplayedPongRejected(self):
        self.pingB()
        self.deliver(self.fdA, self.fdB)
        (oldPong,) = self.deliver(self.fdB, self.fdA)
        self.assertEqual(self.policy().nPing, 0)

        self.pingB()
        self.fdA.protocol.datagramReceived(oldPong, ("127.0.0.1", 1))
        self.assertEqual(self.policy().nPing, 1)
        self.assertEqual(self.A.stats.pongsRejected, 1)

    def testPongWithoutPingRejected(self):
        self.pingB()
        # B signs a pong for a ping A never sent.
        unsolicited = fd.PingMsg(self.A.getMe().identity, self.B.getMe().identity)
        self.fdA.protocol.datagramReceived(self.forgedPong(unsolicited, self.keys[1]),
                                           ("127.0.0.1", 1))
        self.assertEqual(self.policy().nPing, 1)
        self.assertEqual(self.A.stats.pongsRejected, 1)

    def testLatePongForEarlierPingAccepted(self):
        first = self.pingB()
        self.pingB()
        pong = fd.PongMsg(first)
        pong.sign(self.keys[1])
        self.fdA.protocol.datagramReceived(pack(pong), ("127.0.0.1", 1))
        self.assertEqual(self.policy().nPing, 0)

    def testOutstandingNoncesBounded(self):
        for x in range(fd.MAX_OUTSTANDING + 10):
            self.pingB()
        self.assertEqual(len(self.fdA.outstanding[self.bAtA]), fd.MAX_OUTSTANDING)

    def _monitoredByA(self):
        me = self.A.getMe()
        for m in (self.bAtA, self.cAtA):
            if fireflies.view.canAccuse(me, m):
                return m
        raise unittest.SkipTest("A may not accuse B or C with these ring masks.")

    def _drive(self, answer, rounds=200):
        """Run doPing on a member A may accuse. After each ping, answer(ping)
        returns a datagram to give A, or None."""
        target = self._monitoredByA()
        for x in range(rounds):
            self.fdA.doPing(target)
            sent, self.fdA.protocol.transport.sent = self.fdA.protocol.transport.sent, []
            if self.A.stats.accusationsCreated:
                return target
            for data, addr in sent:
                reply = answer(target, unpack(data))
                if reply is not None:
                    self.fdA.protocol.datagramReceived(reply, ("127.0.0.1", 1))
        return target

    def testGenuinePongsPreventAccusation(self):
        keyOf = {self.bAtA: self.keys[1], self.cAtA: self.keys[2]}
        def answer(target, ping):
            pong = fd.PongMsg(ping)
            pong.sign(keyOf[target])
            return pack(pong)
        self._drive(answer)
        self.assertEqual(self.A.stats.accusationsCreated, 0)

    def testForgedPongsDoNotPreventAccusation(self):
        attackerKey = self.keys[0]  # anyone but the target; A's own key will do
        target = self._drive(lambda target, ping: self.forgedPong(ping, attackerKey))
        self.assertEqual(self.A.stats.accusationsCreated, 1)
        self.assertTrue(target.isAccusedBy(self.A.getMe()))
        self.assertTrue(self.A.stats.pongsRejected > 0)

    def testReplayedPongsDoNotPreventAccusation(self):
        target = self._monitoredByA()
        keyOf = {self.bAtA: self.keys[1], self.cAtA: self.keys[2]}
        recorded = []
        def answer(target, ping):
            if not recorded:
                pong = fd.PongMsg(ping)
                pong.sign(keyOf[target])
                recorded.append(pack(pong))
            return recorded[0]
        self._drive(answer)
        self.assertEqual(self.A.stats.accusationsCreated, 1)
