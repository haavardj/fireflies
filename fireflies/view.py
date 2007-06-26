# -*- coding: iso-8859-1 -*-
######################################################################
## Filename:      view.py
## Description:   Fireflies group view.
## Author:        Håvard Dagenborg Johansen <haavardj@cs.uit.no>
## Modified at:   Tue Jan 24 10:39:41 2006
## Modified by:   Håvard Dagenborg Johansen <haavardj@cs.uit.no>
## Licence:       GPL (see the LICENSE file).
##  
##         Copyright© 2007, Håvard D Johansen (Norway)
##                
## $Id: view.py,v 1.1 2007/06/26 08:57:24 haavardj Exp $
##                
######################################################################


from Crypto.Hash import SHA
from Crypto.Util.number import bytes_to_long
from math import *
from twisted.internet import reactor
import logging, setrecon
import random
import fireflies
import fireflies.stats
import fireflies.ring

from fireflies import Member, Note, Accusation
import fireflies.members
from fireflies.members import isValidMask

PARTITION_FACTOR = 3
RECON_EXTRA = 5
HISTORYSIZE = 100

EV_RECOVER_REBUTTAL = 1

class FFReconSet(setrecon.ReconSet):
    def elmToZZp(self, elm):
        return setrecon.to_ZZ_p(setrecon.to_ZZFromBytes(elm.shash()))

_mRingIDCache = {}
def _mRingID(member, ringNr):
    """Return a members's identifier on a ring nr."""
    
    if False: isinstance(member, Member)    
    try:
        return _mRingIDCache[member.getSerial()][ringNr]
    except KeyError:
        memberId = member.getSerial()
        ids = _mRingIDCache.get(memberId, {})
        idOnRing = SHA.new("%s-gossip-%d" % (memberId, ringNr)).digest()
        ids[ringNr] = idOnRing
        _mRingIDCache[memberId] = ids
        return idOnRing
   
    
class SerialRing(fireflies.ring.Ring):
    """A ring of Peer object. The ring is sorted according to the peer
    id attribute."""

    def _sortKey(self, item):
        return item.id
       
class MemberRing(fireflies.ring.NumberedRing):
     
    def _sortKey(self, item):
        return _mRingID(item, self.nr)

class MemberRings(fireflies.ring.NumberedSetOfRings):    
    ringClass = MemberRing


class View:

    timeout = 2
    
    def __init__(self, group, rebuttalTimeout=5, byzantineToleranceNumber=7):
        """Create a new view with cacert as authority."""

        self.cSet = FFReconSet(PARTITION_FACTOR, RECON_EXTRA)
        self.nSet = FFReconSet(PARTITION_FACTOR, RECON_EXTRA)
        self.aSet = FFReconSet(PARTITION_FACTOR, RECON_EXTRA)

        self.rebuttalTimeout = rebuttalTimeout
        self.byzantineToleranceNumber = byzantineToleranceNumber
        self.numberOfRings = byzantineToleranceNumber * 2 + 1
        
        self.group = group
        self.sn2peer = {} # Maps serial nr's to peer objects.

        self.stats = fireflies.stats.Stats()
        
        self.aRing = SerialRing() # List of live members. Sorted by their serial number.
        self.pRing = SerialRing() # List of all members.
        self.fRing = SerialRing() # List of failed members. Sorted by their serial number.

        self.mRings = MemberRings(self.numberOfRings)

        self.logger = logging.getLogger(self.group.getGroupName())
        self._dirty = False
        self._timers = {}

    def _startRebuttalTimer(self, member):
        if member in self._timers: raise ValueError("Timer already started.")
        self._timers[member] = reactor.callLater(self.timeout, self._toRebuttalTimer, member)
        
    def _toRebuttalTimer(self, member):
        assert isinstance(member, fireflies.members.Member)
        self.logger.info("%s failed", member)
        member._setFailed(True)
        self._timers.pop(member)
        self.aRing.remove(member)
        self.fRing.insert(member)
        
    def _stopRebuttalTimer(self, member):
        t = self._timers.pop(member)
        t.cancel()

    def hasActiveTimer(self, member):
        return member in self._timers

    def getMember(self, serial):
        return self.sn2peer[serial]

    def getMembersByAddress(self, address):
        return filter(lambda x: x.cert.address == address, self.pRing)

    def rebuttalTime(self):
        return self.rebuttalTime
    
    def getByzantineToleranceNumber(self):
        """Returns the Byzantine tolerance factor t."""
        return self.byzantineToleranceNumber

    def getNumberOfRings(self):
        return self.numberOfRings                  

    def revive(self, member):
        """Make a failed member live.

        Raises ValueError if the member is not failed.
        """
        
        if member.view != self: raise ValueError("Member not in view.")
        assert member in self.pRing

        self.fRing.remove(member)
        self.aRing.insert(member)
        member._setFailed(False)
        member.nPing = 0
        if member.isAccused():
            self.logger.warning("revived peer is accused. Setting timeout.")
            self._startRebuttalTimer(member)

        self.logger.info("joined %s s=%d t=%d", member, len(self.aRing), len(self.pRing))        
        member.stats.revived += 1

        self.group.notify("member.recover", member, fireflies.EV_RECOVER_INVALIDATED)

            
    def addAccusations(self, accusations, delayCheck=False):
        """Add accusations to the view."""
        
        if not type(accusations) == type([]):
            accusations = [accusations, ]

        for accusation in accusations:

            assert isinstance(accusation, Accusation)            
            self.stats.accusationsTotal += 1
            
            accusedID = accusation.accused
            accuserID = accusation.accuser

            # Check that we know about accused. This should not really
            # happen if we gossip notes before accusations and
            # certificates before notes.
            if not accusedID in self.sn2peer:
                self.stats.accusationsInvalid += 1
                self.logger.warning("discard %s Unknown accused", self.pprint(accusation))
                continue
            accused = self.sn2peer[accusedID]
            
            # Ditto for the accuser
            if not accuserID in self.sn2peer:
                self.stats.accusationsInvalid += 1
                self.logger.warning("discard %s Unknown accuser", self.pprint(accusation))
                continue
            accuser = self.sn2peer[accuserID]

            if not accuser.cert.verify(accusation):
                accuser.stats.accuseByzantine += 1
                accused.stats.accusedByzantine += 1
                self.stats.accusationsInvalid += 1
                self.logger.warning("discard %s Invalid signature", self.pprint(accusation))
                continue

            if not accuser.note:
                self.stats.accusationsInvalid += 1
                self.logger.debug("discard %s invalid note", self.pprint(accusation))
                continue
            
            # Check that accusation is recent.
            if not accused.note:
                self.stats.accusationsInvalid += 1
                self.logger.warning("discard %s byzantine behaviour", self.pprint(accusation))
                continue
            
            if accusation.epoch < accused.note.epoch:
                self.stats.accusationsRedundant += 1
                self.logger.warning("discard %s newer note", self.pprint(accusation))
                continue

            if accusation.epoch > accused.note.epoch:
                self.stats.accusationsInvalid += 1
                self.logger.warning("discard %s accusing newer note.", self.pprint(accusation))
                continue

            # Check that the accuser is not specifying an invalid ring.
            # No correct member should do this.
            if accusation.nr >= len(accused.note.mask):
                self.stats.accusationInvalid += 1
                accuser.accuseByzantine += 1
                accused.accusedByzantine += 1
                self.logger.warning("discard %s byzantine behavior. Not on a valid ring", self.pprint(accusation))
                continue

            # Check that the ring is enabled.
            # No correct member should violate this.
            if not accused.note.mask[accusation.nr]:
                self.stats.accusationInvalid += 1
                accuser.accuseByzantine += 1
                accused.accusedByzantine += 1
                self.logger.warning("discard %s byzantine behavior. Ring disabled by accused", self.pprint(accusation))
                continue

            # Make some shortcuts :-)
            rnr = accusation.nr
            ring = self.mRings[rnr]
            vas = accused.vAccusations
            va = vas.get(rnr, None)
            pas = accused.pAccusations
            pa = pas.get(rnr, None)

            # Always keep the closest accusation in pAccusations
            if not pa:
                # Peer has never been accused on this ring.
                assert va == None # No possible accusations => no valid accusations either
                accused.setAccusation(accusation)
                self._dirty = True
                accuser.stats.accusePossible += 1
                accused.stats.accusedPossible += 1

                self.logger.debug("add %s new", self.pprint(accusation))
                accused.allAccusations.insert(0, accusation)
                if len(accused.allAccusations) > HISTORYSIZE: accused.allAccusations.pop(-1)
            else:
                # Peer has been accused on this ring.
                if pa.accuser == accusation.accuser:
                    # We have this accusation
                    self.stats.accusationsRedundant += 1
                    self.logger.debug("discard %s dublicate", self.pprint(accusation))
                    continue

                ca = self.sn2peer[pa.accuser] #Current accuser
                if ring.isBetween(ca, accuser, accused):
                    # This accuser is closer on the ring than the previous accuser.
                    # And if the previous accusation was valid, so is this.
                    accuser.stats.accusePossible += 1
                    accused.stats.accusedPossible += 1

                    ca.stats.accuseReplaced += 1
                    accuser.stats.accuseCloser +=1                    

                    self.logger.warning("add %s replacing %s",
                                        self.pprint(accusation),
                                        self.pprint(pa))
                    accused.setAccusation(accusation)
                    self._dirty = True
                    # Keep this in our history
                    accused.allAccusations.insert(0, accusation)
                    if len(accused.allAccusations) > HISTORYSIZE: accused.allAccusations.pop(-1)
                else:
                    # We have a closer accusation than this, so toss it.
                    self.stats.accusationsRedundant += 1
                    self.logger.debug("discard %s have closer", self.pprint(accusation))

        if (not delayCheck) and (self._dirty): self.checkAccusations()


    def checkAccusations(self):
        
        if not self._dirty: return

        # Make a list of all peers that have accusations. Since we
        # might need to do multiple passes through all accused peers,
        # this will reduce the amount of work when only a few peers
        # are accused. We start out with no valid accusations and loop
        # through the list untill no more accusations can be made
        # valid. A copy of the previous valid accusations are keept to
        # track changes.
        hasAccus = []
        for peer in self.pRing:
            if peer.hasAccusations():
                hasAccus.append((peer, dict(peer.vAccusations)))
                peer.invalidateAllAccusations()

        nrrings = self.getNumberOfRings()
        changed = True
        
        while changed:
            changed = False
            for accused, oldVas in hasAccus:
                for x in range(nrrings):
                    va = accused.vAccusations.get(x, None)
                    oldVa = oldVas.get(x, None)
                    pa = accused.pAccusations.get(x, None)
                    
                    # No accusation on this ring.                    
                    if not pa:
                        assert not va and not oldVa
                        continue

                    # Any previous valid accusation should either be
                    # the same as pa, or None.
                    if oldVa:
                        assert oldVa == pa

                    # This accusation was set valid in a previous run.
                    if va: continue 

                    ring = self.mRings[x]                                        
                    accuser = self.sn2peer[pa.accuser]
                    isinstance(accuser, Member)
                    isinstance(accused, Member)
                    
                    # In my view, cm is the current valid monitor to
                    # the accused.
                    cm = ring.pred(accused)
                    isinstance(cm, Member)
                    while cm.isAccused():
                        if cm.serial == accused.serial: break
                        cm = ring.pred(cm)
                    
                    # The accusation is valid if the accuser is the
                    # predecessor of the accused, the accuser is the
                    # accused, or the accuser is closer on the ring
                    # than the current monitor (i.e. accuser can be
                    # accused or failed).
                    if (cm.id == accuser.id) or (cm.id == accused.id) or (ring.isBetween(cm, accuser, accused)):

                        if oldVa != accused.vAccusations.get(x, None):
                            pa.setTimestamp()
                            
                        accused.validateAccusation(x)
                        changed = True                        
                    else: 
                        pass


        # One extra pass of the peers is needed to set and remove
        # fail-timers and revive members.
        for peer, oldVas in hasAccus:
            isAccused = peer.isAccused()
            isFailed = peer in self.fRing
            if not isAccused:
                if isFailed:
                    assert not peer.fdTimer
                    self.logger.warning("%s invalidated accusations reviving", self.pprint(peer))
                    self.revive(peer)
                    self.group.notify("member.recover", peer, fireflies.EV_RECOVER_INVALIDATED)
                    continue
                else:
                    pass
                    #self.logger.warning("%s invalidated accusations", self.pprint(peer))
                # If a member is not accused, any fail-timer should be
                # removed.
                try:
                    self._stopRebuttalTimer(peer)
                except AttributeError:
                    pass
            else:
                if isFailed: continue
                if self.hasActiveTimer(peer): continue
                #peer.stats.accusedFirst += 1
                self.logger.warning("%s validated accusations first.", self.pprint(peer))
                self._startRebuttalTimer(peer) 
                #for l in self._listeners:
                #    l.handle_accused(peer)
                    #reactor.callLater(0, l.handle_accused, peer)

        self._dirty = False
        

    def addCerts(self, certs):
        if not type(certs) == type([]):
            certs = [certs, ]
        for c in certs:
            self.stats.certsTotal += 1
            
            if not self.group.isSignedByCA(c): 
                self.stats.certsInvalid += 1
                self.logger.warning("discard %s invalid CA signature.", self.pprint(c))
                continue

            member = self.sn2peer.get(c.serial, None)
            if member:
                member.stats.certsRedundant += 1
                #self.logger.debug("discard %s redundant", self.pprint(c))
                continue

            member = Member(c, self.group)
            assert not member in self.pRing
            self.sn2peer[member.id] = member
            self.cSet.append(c)

            # Add peer to all necessary rings.
            for ring in [self.mRings, self.fRing, self.pRing]:
                assert not member in ring
                ring.insert(member)
            self.group.notify("member.new", member)
            self.group.notify("certificate", c, True)
            self.logger.info("new %s s=%d t=%d", member, len(self.aRing), len(self.pRing))        

    def addNotes(self, notes, delayCheck=False):
        if not type(notes) == type([]):
            notes = [notes, ]            
            
        for note in notes:
            assert isinstance(note, Note)            
            self.stats.notesTotal +=1 
            
            if not note.serial in self.sn2peer:
                self.stats.notesInvalid += 1
                self.logger.warning("discard %s unknown peer", self.pprint(note))
                continue
            peer = self.sn2peer[note.serial]
            
            if not peer.cert.verify(note):
                self.stats.notesInvalid += 1
                self.logger.warning("discard %s invalid signature", self.pprint(note))
                continue
            if not isValidMask(note.mask, self.getByzantineToleranceNumber()): 
                self.logger.warning("discard %s invalid mask", self.pprint(note))
                continue
        
            if (not peer.note) or (note.epoch > peer.note.epoch):
                self.logger.debug("add %s updated (old=%s)", self.pprint( note), self.pprint(peer.note))

                self.group.notify("note", peer.note, False)
                peer.setNote(note)
                self.group.notify("note", note, True)
                peer.stats.noteUpdated += 1                
                for a in peer.vAccusations.values():
                    self.group.notify("accusation", a, False)
                peer.clearAccusations()
                if self.hasActiveTimer(peer):
                    self._stopRebuttalTimer(peer)
                
                self._dirty = True
                #note.setTimestamp()
                if peer in self.fRing:
                    self.logger.info("revive %s", self.pprint(note))
                    self.revive(peer)
                    self.group.notify("member.recover", peer, EV_RECOVER_REBUTTAL)
                else:
                    pass  
            else:
                self.stats.notesRedundant += 1
                
        if (not delayCheck) and self._dirty: self.checkAccusations()

    def pprint(self, data):
        if type(data) == Note:
            if data.serial in self.sn2peer:
                peer = self.sn2peer[data.serial]
                return "N:%s-%d" % (peer.cert.address, data.epoch)
            else:
                return  str(data)
            
        elif type(data) == Accusation:
            if data.accused in self.sn2peer:
                accused = self.sn2peer[data.accused].cert.address
            else: accused = "%x" % bytes_to_long(data.accused)
            if data.accuser in self.sn2peer:
                accuser = self.sn2peer[data.accuser].cert.address
            else: accuser = "%x" % bytes_to_long(data.accuser)

            return "A:%s-%d,%d,%s" % (accused,
                                      data.epoch,
                                      data.nr,
                                      accuser
                                      )
        else:
            return str(data)


