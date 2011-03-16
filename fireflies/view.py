######################################################################
## Filename:      view.py
## Description:   Classes and functions related to management of group views.
## Author:        Haavard Dagenborg Johansen <haavardj@cs.uit.no>
## Modified at:   Tue Jan 24 10:39:41 2006
## Modified by:   Haavard Dagenborg Johansen <haavardj@cs.uit.no>
## Licence:       GPL (see the LICENSE file).
##  
##         Copyright 2007, Haavard D Johansen (Norway)
##                
## $Id: view.py,v 1.18 2011/03/16 12:45:52 haavardj Exp $
##                
######################################################################

"""This module provides the classes and functions that implements the rules for membership changes
as specified by the Fireflies protocol.
"""


#from math import *
from twisted.internet import reactor
import logging
import fireflies
from fireflies.state import Note, Accusation, Member
from fireflies.crypto import identityFromCertificate
import fireflies.stats
from fireflies import ring
from fireflies.util import minMajority
import M2Crypto

_mRingIDCache = {}
def _mRingID(member, ringNr):
    """Return the hash of member's identifier concatenated with ringNr."""
    
    try:
        return _mRingIDCache[member.getIdentity()][ringNr]
    except KeyError:
        memberId = member.getIdentity()
        ids = _mRingIDCache.get(memberId, {})
        idOnRing = SHA.new("%s-gossip-%d" % (memberId, ringNr)).digest()
        ids[ringNr] = idOnRing
        _mRingIDCache[memberId] = ids
        return idOnRing


class View:
    """
    A member's view of a process group.  
    """

    timeout = 10
    
    def __init__(self, group, rebuttalTimeout=10):
        """
        @param group: The group to wich this view belongs.
        @type group: fireflies.group.Group
        """

        isinstance(group, fireflies.group.Group)
        self.rebuttalTimeout = rebuttalTimeout

 
        
        self.toleranceLevel = minMajority(group.pByz, group.maxGroupSize, group.faultToleranceLevel)
        self.numberOfRings = self.toleranceLevel* 2 + 1
        
        self.group = group
        self.sn2peer = {} # Maps identity nr's to peer objects.

        self.stats = fireflies.stats.Stats()
        
        self.aRing = ring.Ring() # List of live members. Sorted by their identity number.
        self.pRing = ring.Ring() # List of all members.
        self.fRing = ring.Ring() # List of failed members. Sorted by their identity number.

        self.mRings = ring.SetOfNamedRings()
        for x in range(self.numberOfRings):
            self.mRings.insertRing(ring.NameHashedRing(x))

        self.logger = logging.getLogger(self.group.getGroupName())
        self._timers = {}

    def _startRebuttalTimer(self, member):
        """Start crash timout timer.
        @param member: The member suspected of having failed.
        @type member: fireflies.state.Member
        """
        if member in self._timers.keys(): raise ValueError("Timer already started.")
        self._timers[member] = reactor.callLater(self.rebuttalTimeout, self._toRebuttalTimer, member)
        
    def _toRebuttalTimer(self, member):
        assert isinstance(member, Member)
        self.logger.info("%s failed", member)
        assert member.isLive()
        assert member.isAccused()
        self._timers.pop(member)
        self._fail(member)
        
    def _stopRebuttalTimer(self, member):
        """Stop crash timout timer.
        @param member: The member that is no longer of having failed.
        @type member: fireflies.state.Member
        """

        t = self._timers.pop(member)
        t.cancel()

    def hasActiveTimer(self, member):
        """Check if a timer is actove for a member.
        @param member: The member
        @type member: fireflies.state.Member
        @return: True if a timer is active for the spesified member.
        @rtype: bool
        """
        return member in self._timers
    
    def getLiveMembers(self):
        """@return: Return an iterable object of all currently live members."""
        return self.aRing

    def getFailedMembers(self):
        """@return: Return an iterable object of all currently failed members."""
        return self.fRing

    def getAllMembers(self):
        """@return: Return an iterable object of of all (live + failed) members."""
        return self.pRing

    def getMemberByCertificate(self, cert):
        return self.getMemberByIdentity(identityFromCertificate(cert))

    def getMemberByIdentity(self, id):
        return self.sn2peer[id]

    def getMembersByAddress(self, address):
        return filter(lambda x: x.cert.address == address, self.pRing)

    def rebuttalTime(self):
        return self.rebuttalTime
    
    def getByzantineToleranceNumber(self):
        """Returns the Byzantine tolerance factor t."""
        return self.byzantineToleranceNumber

    def getNumberOfRings(self):
        return self.numberOfRings                  

    def _new(self, member):
        """Transition member state from unknown to failed."""

        assert member not in self.fRing
        assert member not in self.pRing
        assert member not in self.aRing
        assert member.getIdentity() not in self.sn2peer
        member.setFailed(True) # Members always joins in failed state.
        self.sn2peer[member.getIdentity()] = member
        self.pRing.insert(member)
        self.fRing.insert(member)
        self.mRings.insert(member)

    def _recover(self, member):
        """Transition member state from failed to live."""
        
        assert member in self.fRing
        assert member in self.pRing
        assert member not in self.aRing
        assert member.getIdentity() in self.sn2peer
        assert member in self.mRings

        self.fRing.remove(member)
        self.aRing.insert(member)
        member.setFailed(False)

        #if member.isAccused():
        #    self.logger.warning("revived peer is accused. Setting timeout.")
        #    self._startRebuttalTimer(member)

        #self.logger.info("joined %s s=%d t=%d", member, len(self.aRing), len(self.pRing))        
        #member.stats.revived += 1
        #self.group.notify("member.recover", member, fireflies.EV_RECOVER_INVALIDATED)
        
    def _fail(self, member):
        """Transition member state from live to failed."""
        
        assert member not in self.fRing
        assert member in self.pRing
        assert member in self.aRing
        assert member.getIdentity() in self.sn2peer
        assert member in self.mRings

        self.aRing.remove(member)
        self.fRing.insert(member)
        member.setFailed(True)

    def addCertificate(self, elm):
        """Adds a member certificate to a view.
        
        @param elm: Certificate to be added.
        @type elm: MemberCertificate
        
        @raise e: 
          - TypeError if elm is not a MemberCertificate object.Exceptions:
           -ValueError: The certificate already exists.
        """
        
        if not isinstance(elm, M2Crypto.X509.X509): raise TypeError, type(elm)
        self.stats.certsTotal += 1

        if not elm.verify(self.group.getPublicKey()):
            #self.stats.certsInvalid += 1
            #self.logger.warning("discard %s invalid CA signature.", c)
            raise ValueError("Certificate not correctly signed %s." % str(elm))

        mId = identityFromCertificate(elm)
        try:
            m = self.getMemberByIdentity(mId)
        except KeyError:
            m = None
            
        if m:
            m.stats.certsRedundant += 1
            self.logger.debug("discard %s redundant", elm)
        else:                
            m = Member(elm, self.group)
            self._new(m)
            self.group.notify("data.certificate", elm, True)
            self.group.notify("member.crash", m, fireflies.EV_CRASH_NEW)
            #self.cSet.append(elm)
            self.logger.info("new %s", m)
        return m

    def addNote(self, note):
        """Add a note.
        @param note: Note to be added.
        @type note: L{fireflies.state.Note}
        @raise e:
          - TypeError: not is not a Note object.
          - ValueError: 
              - Invalid signature.
              - Unknown member. 
          - ByzantineErroe: Mask is not valid.
        """  
        
        if not isinstance(note, Note): raise TypeError
        
        #self.stats.notesTotal +=1 
        if not note.identity in self.sn2peer:
            self.stats.notesInvalid += 1
            self.logger.warning("discard %s unknown peer", note)
            raise ValueError
        
        m = self.getMemberByIdentity(note.identity)
    
        assert isinstance(m, Member)
        if m.getNote(): assert m.getNote().identity == note.identity
                
        if not note.verify(m.getCertificate().get_pubkey()):
            raise ValueError("Invalid Signature")
        
        if not fireflies.state.isValidMask(note.mask, self.group.getByzantineToleranceLevel()): 
            #self.logger.warning("discard %s invalid mask", self.pprint(note))
            raise fireflies.ByzantineError("Invalid mask %s from %s" % (str(note.mask), note))
        
        if m.getEpoch() > note.epoch:
            # Old note
            return
        if m.getEpoch() == note.epoch:
            # We have the note. Return silently.
            return 
 
        if not m.isFailed():
            assert m.getEpoch() > 0
            if m.isAccused():
                assert self.hasActiveTimer(m)
                self._stopRebuttalTimer(m)
                m.clearAccusations()
                self.logger.info("note received %s (timer stopped)", note)
            else:
                self.logger.info("note received %s (not accused)", note)
            m.setNote(note)
            
        else:
            
            assert not self.hasActiveTimer(m)

            if m.getEpoch() == 0: 
                assert not m.isAccused()
                self.logger.info("recover %s first note", m)
                m.setNote(note)
                self._recover(m)
            else:
                assert m.isAccused()
                m.clearAccusations()
                m.setNote(note)
                self._recover(m)
                self.group.notify("member.recover", m, fireflies.EV_RECOVER_REBUTTAL)
 
                # The member goes from an accused to not accused state. As such,
                # it may invalidate other accusations. 
                # Let m_j be m's first live successor on ring r.
                # All accusations for members between m and m_j
                #   If m between accuser and accuse: invalidate accusation.  
                #   If accused now is cleared, rerun for this member.            
                check = [m,]
                while check:
                    m = check.pop()      
                    for ring in self.mRings:     
                        for q in ring.collectSucc(m, lambda x: not x.isAccused()):
                            #isinstance(q, fireflies.member.Member)
                            if not q.isAccusedOn(ring.nr): continue                        
                            qa = q.getAccusation(ring.nr)
                            assert isinstance(qa, Accusation)
                            accuser = self.getMemberByIdentity(qa.accuser)
                            accused = self.getMemberByIdentity(qa.accused)
                            if ring.isBetween(accuser, q, accused):
                                assert q.isAccused()
                                assert q.isAccusedOn(ring.nr)
                                q.invalidateAccusationOnRing(ring.nr)
                                self.logger.debug("%s accusation invalidated", m)
                                if not q.isAccused():                                 
                                    if q.isFailed():
                                        self._recover(q)
                                        self.logger.info("%s live (accusations invalidated)", q)
                                        self.group.notify("member.recover", q, EV_RECOVER_INVALIDATED)
                                    else:
                                        self._stopRebuttalTimer(q)
                                        self.logger.debug("%s rebuts (accusation invalidated)", m)
                                    check.append(q)
  

    def addAccusation(self, accusation): 
        """Add an accusations.

        @param accusation: Accusation to be added.
        @type accusation: L{fireflies.state.Accusation}
        @raise e:
            - TypeErrror: If accusation is not a Accusation object.
            - ValueError: If accuser or accused is not known. This would
            typical happen if certificates, notes, and accusations are not
            added in the correct order. These error could also indicate
            malicous behaviour.            
            - ByzantineError: If accusation prepresents malicious behaviour.
            This happens if:
              - the accusation is not correctly signed,
              - the accused has disabled the ring, or
              - the accused epoch is larger than in the current held note.
        """        
        
        if not isinstance(accusation, Accusation): raise TypeError            
        #self.stats.accusationsTotal += 1        
        
        accusedID = accusation.accused
        accuserID = accusation.accuser

        # Check that we know about accused. This should not really
        # happen if we gossip notes before accusations and
        # certificates before notes.
        if not accusedID in self.sn2peer:
            self.stats.accusationsInvalid += 1
            self.logger.warning("discard %s Unknown accused", accusation)
            raise ValueError

        accused = self.sn2peer[accusedID]
        assert isinstance(accused, Member)            
        # Ditto for the accuser
        if not accuserID in self.sn2peer:
            #self.stats.accusationsInvalid += 1
            self.logger.warning("discard %s Unknown accuser", accusation)
            raise ValueError
        
        accuser = self.sn2peer[accuserID]
        assert isinstance(accuser, Member)  
        
        if not accusation.verify(accuser.getPublicKey()):
            #    accuser.stats.accuseByzantine += 1
            #    accused.stats.accusedByzantine += 1
            #    self.stats.accusationsInvalid += 1
            self.logger.warning("discard %s Invalid signature", accusation)
            raise fireflies.ByzantineError("Invalid signature")
        
        if not accuser.getNote():
            #self.stats.accusationsInvalid += 1
            self.logger.debug("discard %s invalid note", accusation)
            raise ValueError
            
        # Check that accusation is recent.
        if not accused.getNote():
            #self.stats.accusationsInvalid += 1
            self.logger.warning("discard %s byzantine behaviour", accusation)
            raise ValueError
        
        if accusation.epoch < accused.getNote().epoch:
            #self.stats.accusationsRedundant += 1
            self.logger.warning("discard %s newer note", accusation)
            return None
        
        if accusation.epoch > accused.getNote().epoch:
            #self.stats.accusationsInvalid += 1
            self.logger.warning("discard %s accusing newer note.", saccusation)
            raise None

        # Check that the accuser is not specifying an invalid ring.
        # No correct member should do this.
        if accusation.nr >= self.getNumberOfRings():
            #self.stats.accusationInvalid += 1
            accuser.accuseByzantine += 1
            accused.accusedByzantine += 1
            self.logger.warning("discard %s byzantine behavior. Not on a valid ring", accusation)
            raise ByzantineError(accuserID)

        # Check that the ring is enabled.
        # No correct member should violate this.
        if not accused.getNote().mask[accusation.nr]:
            self.stats.accusationInvalid += 1
            accuser.accuseByzantine += 1
            accused.accusedByzantine += 1
            self.logger.warning("discard %s byzantine behavior. Ring disabled by accused", accusation)
            raise ByzantineError(accuserID)

        # Make some shortcuts :-)
        rnr = accusation.nr
        ring = self.mRings[rnr]
 
        # If member currently is accused on ring, keep the new one only if it
        # is from a closer predecessor.
        if accused.hasAccusationOn(rnr):
            assert accused.isAccused()
            currentAccusation = accused.getAccusation(rnr)
            currentAccuser = self.getMemberByIdentity(currentAccusation.accuser)
            assert isinstance(currentAccusation, Accusation)
            assert isinstance(currentAccuser, Member)
            
            if ring.isBetween(currentAccuser, accuser, accused):
                accused.setAccusation(accusation)
                self.logger.info("%s accused by %s on ring %d (replacing %s)", accused, accuser, accusation.nr, currentAccuser)

        elif accuser == ring.pred(accused, func=lambda x: (not x.isAccused()) or (x == accuser)):
            accused.setAccusation(accusation)
            if (not self.hasActiveTimer(accused)) and accused.isLive():
                self.logger.info("%s accused by %s on ring %d (timer started)", accused, accuser, accusation.nr)
                self._startRebuttalTimer(accused)


    def pprint(self, data):
        if type(data) == Note:
            if data.identity in self.sn2peer:
                peer = self.sn2peer[data.identity]
                return "N:%s-%d" % (peer.getAddress(), data.epoch)
            else:
                return  str(data)
            
        elif type(data) == Accusation:
            if data.accused in self.sn2peer:
                accused = self.sn2peer[data.accused].getAddress()
            else: accused = "%x" % bytes_to_long(data.accused)
            if data.accuser in self.sn2peer:
                accuser = self.sn2peer[data.accuser].getAddress()
            else: accuser = "%x" % bytes_to_long(data.accuser)

            return "A:%s-%d,%d,%s" % (accused,
                                      data.epoch,
                                      data.nr,
                                      accuser
                                      )
        else:
            return str(data)

