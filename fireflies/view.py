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
## $Id: view.py,v 1.3 2007/07/11 08:21:17 haavardj Exp $
##                
######################################################################


from Crypto.Hash import SHA
from Crypto.Util.number import bytes_to_long
from math import *
from twisted.internet import reactor
import fireflies.crypto
import logging
import random
import fireflies
import fireflies.stats
import fireflies.ring

from fireflies import Member, Note, Accusation
import fireflies.members
from fireflies.members import isValidMask

HISTORYSIZE = 100

EV_RECOVER_REBUTTAL = 1



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
        print "--------> startRebuttaltimer", member
        if member in self._timers.keys(): raise ValueError("Timer already started.")
        self._timers[member] = reactor.callLater(self.timeout, self._toRebuttalTimer, member)
        
    def _toRebuttalTimer(self, member):
        print "--------> toRebuttaltimers", member
        assert isinstance(member, fireflies.Member)
        self.logger.info("%s failed", member)
        assert member.isLive()
        assert member.isAccused()
        self._timers.pop(member)
        self._fail(member)
        
    def _stopRebuttalTimer(self, member):
        print "--------> stop", member
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

    def _new(self, member):
        """Transition member state from unknown to failed."""
        print "--------> new", member
        assert member not in self.fRing
        assert member not in self.pRing
        assert member not in self.aRing
        assert member.getSerial() not in self.sn2peer
        member.setFailed(True) # Members always joins in failed state.
        self.sn2peer[member.getSerial()] = member
        self.pRing.insert(member)
        self.fRing.insert(member)
        self.mRings.insert(member)

    def _recover(self, member):
        """Transition member state from failed to live."""
        print "--------> recover", member
        assert member in self.fRing
        assert member in self.pRing
        assert member not in self.aRing
        assert member.getSerial() in self.sn2peer
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
        
        print "--------> fail", member
        assert member not in self.fRing
        assert member in self.pRing
        assert member in self.aRing
        assert member.getSerial() in self.sn2peer
        assert member in self.mRings

        self.aRing.remove(member)
        self.fRing.insert(member)
        member.setFailed(True)

    def addCertificate(self, elm):
        """Adds cert to the view.
        
        Exceptions:
             -TypeError: elm is not a MemberCertificate object.
             -ValueError: The certificate already exists."""
        
        if not isinstance(elm, fireflies.crypto.MemberCertificate): raise TypeError, type(elm)
        self.stats.certsTotal += 1
            
        if not self.group.getGroupCertificate().verify(elm): 
            #self.stats.certsInvalid += 1
            #self.logger.warning("discard %s invalid CA signature.", c)
            raise ValueError("Certificate not correctly signed %s." % str(elm))
        try:
            m = self.group.getMemberBySerial(elm.serial)
        except KeyError:
            m = None
            
        if m:
            m.stats.certsRedundant += 1
            self.logger.debug("discard %s redundant", elm)
        else:                
            m = fireflies.members.Member(elm, self.group)
            m.group = self.group
            self._new(m)
            self.group.notify("data.certificate", elm, True)
            self.group.notify("member.crash", m, fireflies.EV_CRASH_NEW)
            #self.cSet.append(elm)
            self.logger.info("new %s", m)
        return m

    def addNote(self, note):
        """Add a note.
        
        Exceptions:
           - TypeError: note is not a Note object.
           - ByzantineError: Invalid mask. Note must have disabled exactly t rings."""
        
        if not isinstance(note, fireflies.members.Note): raise TypeError
        
        #self.stats.notesTotal +=1 
        if not note.serial in self.sn2peer:
            self.stats.notesInvalid += 1
            self.logger.warning("discard %s unknown peer", note)
            raise ValueError
        
        m = self.group.getMemberBySerial(note.serial)
    
        assert isinstance(m, fireflies.members.Member)
        if m.note: assert m.note.serial == note.serial
                
        if not m.getCertificate().verify(note):
            raise ValueError("Invalid Signature")
        
        if not isValidMask(note.mask, self.group.getByzantineToleranceLevel()): 
            #self.logger.warning("discard %s invalid mask", self.pprint(note))
            raise fireflies.members.ByzantineError("Invalid mask %s from %s" % (str(note.mask), note))
        
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
                            accuser = self.group.getMemberBySerial(qa.accuser)
                            accused = self.group.getMemberBySerial(qa.accused)
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
        """Adds accusations.

        Return a deferred that triggers when all callbacks have run.
        
        Exceptions:
            - TypeErrror: If accusation is not a Accusation object.

            - ValueError: If accuser or accused is not known. This would
            typical happen if certificates, notes, and accusations are not
            added in the correct order. These error could also indicate
            malicous behaviour.
            
            - ByzantineError: If accusation prepresents malicious behaviour.
            This happens if:
                 - the accusation is not correctly signed,
                 - the accused has disabled the ring, or
                 - the accused epoch is larger than in the current held note. """        
        
        if not isinstance(accusation, fireflies.members.Accusation): raise TypeError            
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
        assert isinstance(accused, fireflies.Member)            
        # Ditto for the accuser
        if not accuserID in self.sn2peer:
            #self.stats.accusationsInvalid += 1
            self.logger.warning("discard %s Unknown accuser", accusation)
            raise ValueError
        
        accuser = self.sn2peer[accuserID]
        assert isinstance(accuser, fireflies.members.Member)  
        
        if not accuser.getCertificate().verify(accusation):
            #    accuser.stats.accuseByzantine += 1
            #    accused.stats.accusedByzantine += 1
            #    self.stats.accusationsInvalid += 1
            self.logger.warning("discard %s Invalid signature", accusation)
            raise fireflies.members.ByzantineError("Invalid signature")
        
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
            currentAccuser = self.group.getMemberBySerial(currentAccusation.accuser)
            assert isinstance(currentAccusation, Accusation)
            assert isinstance(currentAccuser, fireflies.member.Member)
            
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





    #def addCerts(self, certs):
        #if not type(certs) == type([]):
            #certs = [certs, ]
        #for c in certs:
            #self.stats.certsTotal += 1
            
            #if not self.group.isSignedByCA(c): 
                #self.stats.certsInvalid += 1
                #self.logger.warning("discard %s invalid CA signature.", self.pprint(c))
                #continue

            #member = self.sn2peer.get(c.serial, None)
            #if member:
                #member.stats.certsRedundant += 1
                ##self.logger.debug("discard %s redundant", self.pprint(c))
                #continue

            #member = Member(c, self.group)
            #assert not member in self.pRing
            #self.sn2peer[member.id] = member
            #self.cSet.append(c)

            ## Add peer to all necessary rings.
            #for ring in [self.mRings, self.fRing, self.pRing]:
                #assert not member in ring
                #ring.insert(member)
            #self.group.notify("member.new", member)
            #self.group.notify("certificate", c, True)
            #self.logger.info("new %s s=%d t=%d", member, len(self.aRing), len(self.pRing))        

            
   ##def addNote(self, notes, delayCheck=False):
        #if not type(notes) == type([]):
            #notes = [notes, ]            
            
        #for note in notes:
            #assert isinstance(note, Note)            
            #self.stats.notesTotal +=1 
            
            #if not note.serial in self.sn2peer:
                #self.stats.notesInvalid += 1
                #self.logger.warning("discard %s unknown peer", self.pprint(note))
                #continue
            #peer = self.sn2peer[note.serial]
            
            #if not peer.cert.verify(note):
                #self.stats.notesInvalid += 1
                #self.logger.warning("discard %s invalid signature", self.pprint(note))
                #continue
            #if not isValidMask(note.mask, self.getByzantineToleranceNumber()): 
                #self.logger.warning("discard %s invalid mask", self.pprint(note))
                #continue
        
            #if (not peer.note) or (note.epoch > peer.note.epoch):
                #self.logger.debug("add %s updated (old=%s)", self.pprint( note), self.pprint(peer.note))

                #self.group.notify("note", peer.note, False)
                #peer.setNote(note)
                #self.group.notify("note", note, True)
                #peer.stats.noteUpdated += 1                
                #for a in peer.vAccusations.values():
                    #self.group.notify("accusation", a, False)
                #peer.clearAccusations()
                #if self.hasActiveTimer(peer):
                    #self._stopRebuttalTimer(peer)
                
                #self._dirty = True
                ##note.setTimestamp()
                #if peer in self.fRing:
                    #self.logger.info("revive %s", self.pprint(note))
                    #self.revive(peer)
                    #self.group.notify("member.recover", peer, EV_RECOVER_REBUTTAL)
                #else:
                    #pass  
            #else:
                #self.stats.notesRedundant += 1
                
        #if (not delayCheck) and self._dirty: self.checkAccusations()
        
                   
    #def addAccusations(self, accusations, delayCheck=False):
        #"""Add accusations to the view."""
        
        #if not type(accusations) == type([]):
            #accusations = [accusations, ]

        #for accusation in accusations:

            #assert isinstance(accusation, Accusation)            
            #self.stats.accusationsTotal += 1
            
            #accusedID = accusation.accused
            #accuserID = accusation.accuser

            ## Check that we know about accused. This should not really
            ## happen if we gossip notes before accusations and
            ## certificates before notes.
            #if not accusedID in self.sn2peer:
                #self.stats.accusationsInvalid += 1
                #self.logger.warning("discard %s Unknown accused", self.pprint(accusation))
                #continue
            #accused = self.sn2peer[accusedID]
            
            ## Ditto for the accuser
            #if not accuserID in self.sn2peer:
                #self.stats.accusationsInvalid += 1
                #self.logger.warning("discard %s Unknown accuser", self.pprint(accusation))
                #continue
            #accuser = self.sn2peer[accuserID]

            #if not accuser.cert.verify(accusation):
                #accuser.stats.accuseByzantine += 1
                #accused.stats.accusedByzantine += 1
                #self.stats.accusationsInvalid += 1
                #self.logger.warning("discard %s Invalid signature", self.pprint(accusation))
                #continue

            #if not accuser.note:
                #self.stats.accusationsInvalid += 1
                #self.logger.debug("discard %s invalid note", self.pprint(accusation))
                #continue
            
            ## Check that accusation is recent.
            #if not accused.note:
                #self.stats.accusationsInvalid += 1
                #self.logger.warning("discard %s byzantine behaviour", self.pprint(accusation))
                #continue
            
            #if accusation.epoch < accused.note.epoch:
                #self.stats.accusationsRedundant += 1
                #self.logger.warning("discard %s newer note", self.pprint(accusation))
                #continue

            #if accusation.epoch > accused.note.epoch:
                #self.stats.accusationsInvalid += 1
                #self.logger.warning("discard %s accusing newer note.", self.pprint(accusation))
                #continue

            ## Check that the accuser is not specifying an invalid ring.
            ## No correct member should do this.
            #if accusation.nr >= len(accused.note.mask):
                #self.stats.accusationInvalid += 1
                #accuser.accuseByzantine += 1
                #accused.accusedByzantine += 1
                #self.logger.warning("discard %s byzantine behavior. Not on a valid ring", self.pprint(accusation))
                #continue

            ## Check that the ring is enabled.
            ## No correct member should violate this.
            #if not accused.note.mask[accusation.nr]:
                #self.stats.accusationInvalid += 1
                #accuser.accuseByzantine += 1
                #accused.accusedByzantine += 1
                #self.logger.warning("discard %s byzantine behavior. Ring disabled by accused", self.pprint(accusation))
                #continue

            ## Make some shortcuts :-)
            #rnr = accusation.nr
            #ring = self.mRings[rnr]
            #vas = accused.vAccusations
            #va = vas.get(rnr, None)
            #pas = accused.pAccusations
            #pa = pas.get(rnr, None)

            ## Always keep the closest accusation in pAccusations
            #if not pa:
                ## Peer has never been accused on this ring.
                #assert va == None # No possible accusations => no valid accusations either
                #accused.setAccusation(accusation)
                #self._dirty = True
                #accuser.stats.accusePossible += 1
                #accused.stats.accusedPossible += 1

                #self.logger.debug("add %s new", self.pprint(accusation))
                #accused.allAccusations.insert(0, accusation)
                #if len(accused.allAccusations) > HISTORYSIZE: accused.allAccusations.pop(-1)
            #else:
                ## Peer has been accused on this ring.
                #if pa.accuser == accusation.accuser:
                    ## We have this accusation
                    #self.stats.accusationsRedundant += 1
                    #self.logger.debug("discard %s dublicate", self.pprint(accusation))
                    #continue

                #ca = self.sn2peer[pa.accuser] #Current accuser
                #if ring.isBetween(ca, accuser, accused):
                    ## This accuser is closer on the ring than the previous accuser.
                    ## And if the previous accusation was valid, so is this.
                    #accuser.stats.accusePossible += 1
                    #accused.stats.accusedPossible += 1

                    #ca.stats.accuseReplaced += 1
                    #accuser.stats.accuseCloser +=1                    

                    #self.logger.warning("add %s replacing %s",
                                        #self.pprint(accusation),
                                        #self.pprint(pa))
                    #accused.setAccusation(accusation)
                    #self._dirty = True
                    ## Keep this in our history
                    #accused.allAccusations.insert(0, accusation)
                    #if len(accused.allAccusations) > HISTORYSIZE: accused.allAccusations.pop(-1)
                #else:
                    ## We have a closer accusation than this, so toss it.
                    #self.stats.accusationsRedundant += 1
                    #self.logger.debug("discard %s have closer", self.pprint(accusation))

        #if (not delayCheck) and (self._dirty): self.checkAccusations()


    #def checkAccusations(self):
        
        #if not self._dirty: return

        ## Make a list of all peers that have accusations. Since we
        ## might need to do multiple passes through all accused peers,
        ## this will reduce the amount of work when only a few peers
        ## are accused. We start out with no valid accusations and loop
        ## through the list untill no more accusations can be made
        ## valid. A copy of the previous valid accusations are keept to
        ## track changes.
        #hasAccus = []
        #for peer in self.pRing:
            #if peer.hasAccusations():
                #hasAccus.append((peer, dict(peer.vAccusations)))
                #peer.invalidateAllAccusations()

        #nrrings = self.getNumberOfRings()
        #changed = True
        
        #while changed:
            #changed = False
            #for accused, oldVas in hasAccus:
                #for x in range(nrrings):
                    #va = accused.vAccusations.get(x, None)
                    #oldVa = oldVas.get(x, None)
                    #pa = accused.pAccusations.get(x, None)
                    
                    ## No accusation on this ring.                    
                    #if not pa:
                        #assert not va and not oldVa
                        #continue

                    ## Any previous valid accusation should either be
                    ## the same as pa, or None.
                    #if oldVa:
                        #assert oldVa == pa

                    ## This accusation was set valid in a previous run.
                    #if va: continue 

                    #ring = self.mRings[x]                                        
                    #accuser = self.sn2peer[pa.accuser]
                    #isinstance(accuser, Member)
                    #isinstance(accused, Member)
                    
                    ## In my view, cm is the current valid monitor to
                    ## the accused.
                    #cm = ring.pred(accused)
                    #isinstance(cm, Member)
                    #while cm.isAccused():
                        #if cm.serial == accused.serial: break
                        #cm = ring.pred(cm)
                    
                    ## The accusation is valid if the accuser is the
                    ## predecessor of the accused, the accuser is the
                    ## accused, or the accuser is closer on the ring
                    ## than the current monitor (i.e. accuser can be
                    ## accused or failed).
                    #if (cm.id == accuser.id) or (cm.id == accused.id) or (ring.isBetween(cm, accuser, accused)):

                        #if oldVa != accused.vAccusations.get(x, None):
                            #pa.setTimestamp()
                            
                        #accused.validateAccusation(x)
                        #changed = True                        
                    #else: 
                        #pass


        ## One extra pass of the peers is needed to set and remove
        ## fail-timers and revive members.
        #for peer, oldVas in hasAccus:
            #isAccused = peer.isAccused()
            #isFailed = peer in self.fRing
            #if not isAccused:
                #if isFailed:
                    #assert not peer.fdTimer
                    #self.logger.warning("%s invalidated accusations reviving", self.pprint(peer))
                    #self.revive(peer)
                    #self.group.notify("member.recover", peer, fireflies.EV_RECOVER_INVALIDATED)
                    #continue
                #else:
                    #pass
                    ##self.logger.warning("%s invalidated accusations", self.pprint(peer))
                ## If a member is not accused, any fail-timer should be
                ## removed.
                #try:
                    #self._stopRebuttalTimer(peer)
                #except AttributeError:
                    #pass
            #else:
                #if isFailed: continue
                #if self.hasActiveTimer(peer): continue
                ##peer.stats.accusedFirst += 1
                #self.logger.warning("%s validated accusations first.", self.pprint(peer))
                #self._startRebuttalTimer(peer) 
                ##for l in self._listeners:
                ##    l.handle_accused(peer)
                    ##reactor.callLater(0, l.handle_accused, peer)

        #self._dirty = False
        