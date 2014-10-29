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
## $Id: view.py,v 1.32 2014/10/29 17:58:07 haavardj Exp $
##                
######################################################################

"""This module provides the classes and functions that implements the rules for membership changes
as specified by the Fireflies protocol.
"""


#from math import *
import twisted.internet
import logging
import fireflies
from fireflies.state import Note, Accusation, Member
from fireflies.crypto import identityFromCertificate, shortIdentity
import fireflies.stats
from fireflies import ring
import M2Crypto

LOGDISCARDING=False

def canSkip(member):
    return not member.isLive()

def validPredecessor(accuser, accused, ring):
    """Return true if 'accuser' is allowed to accuse 'accused' on the given ring. 
    This implies that the accused is the first live predecessor of 'accused' on the given ring.
    """    
        
    if False: 
        isinstance(accuser, Member)
        isinstance(accused, Member)
        isinstance(ring, fireflies.ring.Ring)
    
    assert accuser.group == accused.group
    
    pred = ring.pred(accused)
    if False: isinstance(pred, Member)
    while pred != accuser:    
        if not canSkip(pred): return False
        pred = ring.pred(pred)       
    return True
    

def canAccuseOnRing(accuser, accused, ring):
    """Return true if 'accuser' is allowed to accuse 'accused' on the given ring. 
    This implies that the accused is the first live predecessor of 'accused' on the given ring.
    """    
        
    if False: 
        isinstance(accuser, Member)
        isinstance(accused, Member)
        isinstance(ring, fireflies.ring.Ring)

    if not accused.isEnabledOnRing(ring): return False
    
    assert accuser.group == accused.group
    
    pred = ring.pred(accused)
    while pred != accuser:    
        if not canSkip(pred): return False
        pred = ring.pred(pred)       
    return True
                
def canAccuse(accuser, accused, rings=None):
    """Return true if 'accuser' is allowed to accuse 'accused'."""
    
    assert accuser.group == accused.group
    
    if not rings: 
        rings = accused.group.view.mRings

    for ring in rings:
        if canAccuseOnRing(accuser, accused, ring): 
            return True
    return False

class AccusationTable(fireflies.ring.RankTable):
    """Extends the RankTable with a validity check. Also, items that
    are not valid accusers of base are given rank 0.    
    """   
        
    @property
    def valid(self):
        """Return true if item can make accusations for base. This means that the ranktable
        contains at least one entry that is not INVALID."""
        return bool(filter(lambda x: x != self.INVALID, self))
    
    def computeRanks(self):
        for nr, ring in enumerate(rings):
            
            if canAccuseOnRing(self.item, self.base, ring):
                self[nr] = ring.rank(self.base, self.item) 
            else:
                self[nr] = self.INVALID
            
                
def isBetterAccuserOnRing(new, old, member, ring):
    """Returns true if new is a closer/better accuser than old for member on the given ring."""

    return ring.isBetween(old, new, member)


class View:
    """
    A member's view of a process group.  
    """
    
    def __init__(self, group):
        """
        @param group: The group to wich this view belongs.
        @type group: fireflies.group.Group
        """

        isinstance(group, fireflies.group.Group)
                
        self.group = group
        self.sn2peer = {} # Maps identity nr's to peer objects.
        
        self.aRing = ring.Ring() # List of live members. Sorted by their identity number.
        self.pRing = ring.Ring() # List of all members.
        self.fRing = ring.Ring() # List of failed members. Sorted by their identity number.

        self.mRings = ring.RingSet()
        for x in range(self.group.nrMonitoringRings()):
            self.mRings.insertRing(ring.NameHashedRing(x))

        self._timers = {}

    def _startRebuttalTimer(self, member):
        """Start crash timout timer.
        @param member: The member suspected of having failed.
        @type member: fireflies.state.Member
        """
        if member in self._timers.keys(): raise ValueError("Timer already started.")
        self._timers[member] = twisted.internet.reactor.callLater(self.group.tRebuttal, self._toRebuttalTimer, member)
        
    def _toRebuttalTimer(self, member):
        assert isinstance(member, Member)

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

    @property
    def logger(self):
        return self.group.logger

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

    def _new(self, member):
        """Transition member state from unknown to failed."""

        assert member not in self.fRing
        assert member not in self.pRing
        assert member not in self.aRing
        assert member.identity not in self.sn2peer
        member.setFailed(True) # Members always joins in failed state.
        self.sn2peer[member.identity] = member
        self.pRing.insert(member)
        self.fRing.insert(member)
        self.mRings.insertItem(member)


    def _recover(self, member):
        """Transition member state from failed to live."""
        
        assert member in self.fRing
        assert member in self.pRing
        assert member not in self.aRing
        assert member.identity in self.sn2peer
        #for r in self.mRings.getRings():
        #    assert member in r

        self.fRing.remove(member)
        self.aRing.insert(member)
        member.setFailed(False)
        self.logger.info("%s recovers", member)
        
        self.group.stats.revived += 1


    def _fail(self, member):
        """Transition member state from live to failed."""
        
        assert member not in self.fRing
        assert member in self.pRing
        assert member in self.aRing
        assert member.identity in self.sn2peer
        assert self.mRings.hasItem(member)
        self.aRing.remove(member)
        self.fRing.insert(member)
        member.setFailed(True)
        self.logger.info("%s fails", member)
        
        self.group.stats.failed += 1


    def addCertificate(self, elm):
        """Adds a member certificate to a view.
        
        @param elm: Certificate to be added.
        @type elm: MemberCertificate
        
        @raise e: 
          - TypeError if elm is not a MemberCertificate object.Exceptions:
           -ValueError: The certificate already exists.
        """

        self.group.stats.certsTotal += 1
        if not isinstance(elm, M2Crypto.X509.X509): raise TypeError, type(elm)

        if not elm.verify(self.group.getPublicKey()):
            self.group.stats.certsInvalid += 1
            #self.logger.warning("discard %s invalid CA signature.", c)
            raise ValueError("Certificate not correctly signed %s." % str(elm))

        mId = identityFromCertificate(elm)
        try:
            m = self.getMemberByIdentity(mId)
        except KeyError:
            m = None
            
        if m:
            self.group.stats.certsRedundant += 1
            if fireflies.NOISELEVEL > 2: self.logger.debug("discard %s redundant", elm)
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
        
        self.group.stats.notesTotal += 1
        if not isinstance(note, Note): raise TypeError
        
        if not note.identity in self.sn2peer:
            self.group.stats.notesInvalid += 1
            self.logger.warning("warning: discard %s invalid unknown peer", note)
            raise ValueError, "Unknown peer"
        
        member = self.getMemberByIdentity(note.identity)
    
        assert isinstance(member, Member)
        if member.getNote(): assert member.getNote().identity == note.identity
                
        if not note.verify(member.getCertificate().get_pubkey()):
            self.group.stats.notesInvalid += 1
            raise ValueError, "Invalid Signature"
        
        if not fireflies.state.isValidMask(note.mask, self.group.nrMonitoringRings()): 
            self.group.stats.notesInvalid += 1
            self.logger.warning("warning: discard %s invalid mask", note)
            raise fireflies.ByzantineError, "Invalid mask %s from %s" % (str(note.mask), note)

        # Old note        
        if member.getEpoch() > note.epoch:
            self.group.stats.notesRedundant+= 1
            if LOGDISCARDING: self.logger.debug("discard %s old", self.pprint(note))
            return
        
        if member.getEpoch() == note.epoch:

            # I have two notes with same epoch but different content. This is wrong behaviour as 
            # notes epochs should be monotonically increasing. However, if local state is deleted 
            # from disk during a restart, this could happen. If note is mine, then we rebutt, which will
            # incalidate both of the inconsistent notes.
            
            if member.getNote().uidstr() != note.uidstr():
                self.logger.warning("warning: %s note with same epoch but different content.", self.pprint(note))
                
                if member == self.group.getMe():
                    self.group.nextEpoch()
                    self.logger.info("add %s rebuttal due to currupted note", self.pprint(note))
            else:
                self.group.stats.notesRedundant += 1
            
                #self.logger.debug("discard %s current", self.pprint(note))
            return
 
        if not member.isFailed():
            assert member.getEpoch() > 0
            if member.isAccused():
                assert self.hasActiveTimer(member)
                self._stopRebuttalTimer(member)
                member.clearAccusations()
                self.logger.info("add %s timer stopped", self.pprint(note))
            else:
                self.logger.info("add %s", self.pprint(note))
            member.setNote(note)
            
        else:
            
            assert not self.hasActiveTimer(member)
            
            if member.getEpoch() == 0: 
                self.logger.info("add %s first note", member)
            else:
                assert member.isAccused()
                self.logger.info("add %s rebuttal", member)                
            
            member.clearAccusations()

            member.setNote(note)
            self._recover(member)            
            self.group.notify("member.recover", member, fireflies.EV_RECOVER_REBUTTAL)
                
            # The member goes from an accused to non-accused state. 
            # This might invalidate other accusations and we need to check it.
            self.checkAccusationValidity(member)
                                                                


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
        assert isinstance(accusation, Accusation)
        self.group.stats.accusationsTotal += 1        
        
        accusedID = accusation.accused
        accuserID = accusation.accuser

        # Check that we know about accused. This should not really
        # happen if we gossip notes before accusations and
        # certificates before notes.
        if not accusedID in self.sn2peer:
            self.group.stats.accusationsInvalid += 1
            self.logger.warning("warning: discard %s Unknown accused", self.pprint(accusation))
            raise ValueError, "Unknown Accused"

        accused = self.group.getMemberByIdentity(accusedID)
        assert isinstance(accused, Member)            

        # Ditto for the accuser
        if not accuserID in self.sn2peer:
            self.group.stats.accusationsInvalid += 1
            self.logger.warning("warning: discard %s Unknown accuser", self.pprint(accusation))
            raise ValueError, "Unkown Accuser"
        
        accuser = self.group.getMemberByIdentity(accuserID)
        assert isinstance(accuser, Member)  
        
        if not accusation.verify(accuser.getPublicKey()):
            accuser.stats.accuseByzantine += 1
            accused.stats.accusedByzantine += 1
            self.logger.warning("warning: discard %s Invalid signature", self.pprint(accusation))
            return #ValueError, "Invalid Signature" #None #raise fireflies.ByzantineError("Invalid signature")
        
        if not accuser.getNote():
            self.group.stats.accusationsInvalid += 1            
            self.logger.info("discard %s invalid note", self.pprint(accusation))
            return #ValueError, "Invalid accuser note"
            
        # Check that accusation is recent.
        if not accused.getNote():
            accuser.stats.accuseByzantine += 1
            accused.stats.accusedByzantine += 1            
            self.logger.warning("warning: discard %s byzantine behaviour", self.pprint(accusation))
            return #ValueError, "Invalid accused note"
        
        if accusation.epoch < accused.getNote().epoch:
            self.group.stats.accusationsRedundant += 1
            if LOGDISCARDING: self.logger.debug("discard %s old note", self.pprint(accusation))
            return 
        
        if accusation.epoch > accused.getNote().epoch:
            self.group.stats.accusationsInvalid += 1
            self.logger.warning("warning: discard %s newer note", self.pprint(accusation))
            return 

        # Check that the ring is enabled.
        # No correct member should violate this.
        if not canAccuse(accuser, accused):
            accuser.stats.accuseByzantine += 1
            accused.stats.accusedByzantine += 1                
            return

        if accused.isAccusedBy(accuser):
            if LOGDISCARDING: self.logger.debug("discard %s duplicate", self.pprint(accusation))
            assert accusation in accused.getAccusations()
            return
        
        newAT = AccusationTable(accuser, accused, self.mRings)
        
        # Not a valid accuser, discard.
        if not newAT.valid:
            accuser.stats.accusationsInvalid += 1            
            self.logger.warning("warning: dicard %s accuser not current monitor", self.pprint(accusation))
            return
            
        if not accused.isAccused():
            # Simply add the accusation and start the rubuttaltimer.
            assert not self.hasActiveTimer(accused)
            assert accused.isLive()                
            accused.setAccusation(accusation)
            self.logger.info("add %s first (timer started)", self.pprint(accusation))
            self._startRebuttalTimer(accused)                            
            return

        else:
            # Other accusations already exist. We need to check if the new one
            # is completely covered by existion ones, or if some of the existing
            # ones are completely covered by the new ones.            
            
            assert self.hasActiveTimer(accused) or accused.isFailed()

            nrRemoved = 0
            accusers = map(lambda x: self.group.getMemberByIdentity(x.accuser), accused.getAccusations())
            for a in accusers:
                assert isinstance(a, Member), "a=%s" % a
                oldAT = AccusationTable(a, accused, self.mRings)
                
                assert newAT != oldAT
                
                if newAT >= oldAT:
                    nrRemoved+=1
                    self.logger.info("discard old accuser %s covered by new accuser %s", self.pprint(a), accuser)
                    try:
                        assert accused.isAccusedBy(a)
                        accused.invalidateAccusationBy(a)
                    except ValueError, why:
                        self.logger.exception("Exception: Cannot invalidate accusation %s: ", why)
                        raise
                    
            accusers = map(lambda x: self.group.getMemberByIdentity(x.accuser), accused.getAccusations())

            # Accusers might be empty now, but only if some accusations have been removed above.
            assert accusers or nrRemoved > 0            
            
            # List of AccusationTable, one for each existing accuser.
            ats = map(lambda x: AccusationTable(x, accused, self.mRings), accusers)

            # Combine remaining AccusationTables to that each entry 
            # list the rank of the accuser on that particular ring.
            r = AccusationTable(0, accused, self.mRings)
            r = reduce(lambda x, y: x+y, ats, r)
            
            if r < newAT:
                # One item in newAT is larger than r, so this accusation should be kept.
                accused.setAccusation(accusation)
                self.logger.info("add %s", self.pprint(accusation))
            elif r >= newAT: 
                # If an existing accusation was previously removed, this implies 
                # that newAT is larger than at least one existing one.
                assert nrRemoved == 0
                self.logger.info("discard %s covered by exising ones", accusation)               
            elif r == newAT:
                self.logger.info("discard %s have equal", self.pprint(accusation))   
                assert nrRemoved == 0
        
            

    def checkAccusationValidity(self, member):
        """Checks if a member or list of members are invalidating any accusation. 
        This check is only valid for non-accused member.
        Calling it with an accused member will trigger a ValueError exception.
        
        Any invalid accusations found are removed. This might in turn trigger membership state change
        and induce further checks.
        """
        
        if member.isAccused():
            raise ValueError, "We can only check non-accused members."

        # A non-accused member should always be live.
        assert member.isLive()

        if not isinstance(member, list):        
            check = [member,]
        else:
            check = list(member)
            
        while check:
            member = check.pop()      

            # Only non-accused and live members should ever be considered.
            assert not member.isAccused()
            assert member.isLive()
            
            # Accused successors of member might potentially have accusation that
            # are no longer valid valid. However, for each ring, we do not need to 
            # check succesors after a live one, since no accusations crossing that member
            # should exist.
                        
            accusedSuccessors = set()            
            for ring in self.mRings.getRings():
                x = ring.succ(member)
                
                # this will always terminate. At latest when complete ring has been traversed
                # and x == member (member.isLive() is always True thus member.isAccused() is False)
                while x.isAccused(): 
                    accusedSuccessors.add(x)
                    x = ring.succ(x)
            
            for accused in accusedSuccessors:
                    
                for a in x.getAccusations():
                    isinstance(a, Accusation)
                    accuser = self.getMemberByIdentity(a.accuser)
                    assert accused == self.getMemberByIdentity(a.accused)
                    
                    at = fireflies.view.AccusationTable(accuser, accused, self.mRings.getRings())
                    
                    # Remove accusations that are no longer valid.
                    # If the accused has no more accusations, then it is considered live. 
                    # This implies that the successor of the accused also must be checked.
                    if not at.valid():
                        x.invalidateAccusation(a)
                        self.logger.info("del %s invalidated by %s", self.pprint(a), member)
                        
                        if not x.isAccused():
                            if x.isFailed():
                                self._recover(x)
                                self.logger.info("%s live (accusations invalidated)", x)
                                self.group.notify("member.recover", x, fireflies.EV_RECOVER_INVALIDATED)
                            else:
                                self._stopRebuttalTimer(x)
                                self.logger.info("%s invalidated", self.pprint(a))

                            check.append(x) 
      

    def pprint(self, data):
        if isinstance(data, Note):
            if data.identity in self.sn2peer:                
                peer = self.sn2peer[data.identity]
                return "N:%s:%s-%d" % (shortIdentity(data.identity),peer.getAddress(), data.epoch)
            else:
                return  str(data)
            
        elif isinstance(data, Accusation):
            if data.accused in self.sn2peer:
                accused = self.sn2peer[data.accused].getAddress()
            else: accused = str(shortIdentity(data.accused))
            if data.accuser in self.sn2peer:
                accuser = self.sn2peer[data.accuser].getAddress()
            else: accuser = str(shortIdentity(data.accuser))

            return "A:%s-%d,%s" % (accused,
                                   data.epoch,
                                   accuser
                                   )
        else:
            return str(data)

