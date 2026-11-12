"""View: accusation rules from the TOCS paper."""

from twisted.trial import unittest

import fireflies.group
from fireflies import state
from fireflies.test.helpers import makeCA, makeMember, noteOf
from fireflies.util import reactor


class Rule8Test(unittest.TestCase):
    """One monitoring ring, four members. The observer is one of them; the
    other three are consecutive on the ring: X -> Y -> Z."""

    def setUp(self):
        ca, caKey = makeCA(mRings=1, gRings=1)
        creds = [makeMember(ca, caKey, "127.0.0.1:%d" % (25200 + i), i + 1) for i in range(4)]
        groups = [fireflies.group.Group(ca, k, c) for c, k in creds]
        self.observer = groups[0]
        view = self.observer.view
        for g in groups[1:]:
            view.addCertificate(g.getMe().getCertificate())
            view.addNote(noteOf(g.getMe()))
        self.keys = {g.getMe().identity: k for g, (c, k) in zip(groups, creds, strict=True)}
        self.view = view
        ring = view.mRings.getRings()[0]
        me = view.getMemberByIdentity(self.observer.getMe().identity)
        self.x = ring.succ(me)
        self.y = ring.succ(self.x)
        self.z = ring.succ(self.y)
        assert len({me, self.x, self.y, self.z}) == 4

    def tearDown(self):
        for call in reactor.getDelayedCalls():
            call.cancel()

    def accuse(self, accuser, accused):
        note = accused.getNote()
        a = state.Accusation(accused.identity, note.epoch, accuser.identity)
        a.sign(self.keys[accuser.identity])
        self.view.addAccusation(a)

    def failY(self):
        self.accuse(self.x, self.y)
        self.assertTrue(self.y.isAccused())
        self.view._toRebuttalTimer(self.y)
        self.view._timers.pop(self.y, None)
        self.assertTrue(self.y.isFailed())

    def test_skipOverFailed(self):
        """X may accuse Z by skipping the failed Y."""
        self.failY()
        self.accuse(self.x, self.z)
        self.assertTrue(self.z.isAccusedBy(self.x))

    def test_cannotSkipLive(self):
        """While Y is live, X may not accuse Z."""
        self.accuse(self.x, self.z)
        self.assertFalse(self.z.isAccused())

    def test_rebuttalInvalidatesSkippingAccusation(self):
        """Rule 8: when Y comes back, X's accusation of Z, which skipped Y,
        is no longer valid and is removed."""
        self.failY()
        self.accuse(self.x, self.z)
        self.assertTrue(self.z.isAccused())

        old = noteOf(self.y)
        rebuttal = state.Note(self.y.identity, old.epoch + 1, list(old.mask))
        rebuttal.sign(self.keys[self.y.identity])
        self.view.addNote(rebuttal)

        self.assertTrue(self.y.isLive())
        self.assertFalse(self.z.isAccused())
        self.assertFalse(self.view.hasActiveTimer(self.z))
