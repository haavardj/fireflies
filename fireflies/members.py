# -*- coding: iso-8859-1 -*-
######################################################################
## Filename:      members.py
## Description:   Fireflies member structures.
## Author:        Håvard Dagenborg Johansen <haavardj@cs.uit.no>
## Modified at:   Thu Jan 19 20:03:32 2006
## Modified by:   Håvard Dagenborg Johansen <haavardj@cs.uit.no>
## Licence:       GPL (see the LICENSE file).
##  
##         Copyright© 2006, University of Tromsø (Norway)
##                
## $Id: members.py,v 1.1 2006/01/20 12:41:26 haavardj Exp $
##                
######################################################################



from Crypto.Hash import SHA
from Crypto.Util.number import long_to_bytes, bytes_to_long
from math import *
from twisted.internet import reactor
import bisect, fireflies, cert, logging, setrecon
import random
import fireflies.stats


HISTORYSIZE = 100
INITIAL_LRATE = 0.10

PARTITION_FACTOR = 3
RECON_EXTRA = 2

class Accusation(object, cert.TimestampMixin, cert.RSASignable):
    """A Fireflies accusation. Except for the signature, this class
    should be considered immutable."""

    def __init__(self, accused, ll, nr, accuser):
        self.accused = accused
        self.lifeline = ll
        self.nr = nr
        self.accuser = accuser 
        self.signature = 0

    def __getstate__(self):
        return {"accused": self.accused,
                "lifeline": self.lifeline,
                "nr": self.nr,
                "accuser": self.accuser,
                "signature": self.signature
                }

    def __setstate__(self, data):
        for k,v in data.items():
            setattr(self, k, v)
        
    def __cmp__(self, other):
        try: return cmp(self.shash(), other.shash())
        except AttributeError: return -1

    def __hash__(self):
        return hash(self.shash())

    def __repr__(self):        
            return "%s" % (self.uidstr())
        
    def uidstr(self):
        return "Accusation:%d,%d,%d-%d" % (bytes_to_long(self.accused), self.lifeline,
                                  self.nr, bytes_to_long(self.accuser))

        
def createInitialNote(serial, t, data=""):
    """Return a note with the specified serial, initial lifeline of 1,
    and a 2t+1 length mask with t disabled rings."""

    rings = 2*t + 1
    mask = [False] * t + ([True] * (rings - t))
    random.shuffle(mask)
    return Note(serial, 1, mask, data)

class Note(object, cert.TimestampMixin, cert.RSASignable):
    """A Fireflies note. Except for the signature, this class
    should be considered immutable.

    Important attributes are:
      - serial --- The member's serial number.
      - lifeline --- The lifeline/epoch of the note.
      - mask --- A list of True/False values. True means the corresponding
                 monitoring ring is enabled.
      - signature ---
      - data --- A string.
    """

    def __init__(self, serial, lifeline, mask, data=""):
        self.serial = serial
        self.lifeline = lifeline
        self.mask = mask
        self.signature = 0
        self.data = data        
        self.badness = 0

    def __repr__(self):        
        return "N:%x-%d" % (bytes_to_long(self.serial), self.lifeline)

    def __hash__(self):
        return hash(self.shash())

    def __getstate__(self):
        return {"serial": self.serial,
                "lifeline": self.lifeline,
                "mask": self.mask,
                "signature": self.signature,
                "badness": self.badness,
                "data": self.data
                }
    
    def __setstate__(self, data):
        for k,v in data.items():
            setattr(self, k, v)

    def __cmp__(self, other):
        try: return cmp(self.shash(), other.shash())
        except AttributeError: return -1

    def uidstr(self):
        return "Note:%d-%d-%s-%s" % (bytes_to_long(self.serial), self.lifeline,
                                     str(self.mask), str(self.data))


# hashCache is used to speed up simulations. This data structure
# contains the members ring hashes and is shared between all simulated
# members.
hashCache = {}


class Member(object):
    """A Fireflies member.

    The following attributes are of interest:

    note - the member's latest note.
    cert - the member's certificate. Does not change.
    id/serial - the serial number of the member's certificate.
    view - The view the member is in.
    """

    def __init__(self, mcert, view, note=None, initLRate=INITIAL_LRATE):

        if note:
            self.setNote(note)
        else:
            self.note = None
        self.cert = mcert
        self.mcert = mcert
        self.id = mcert.serial
        self.serial = self.mcert.serial
        self.view = view
        self.logger = logging.getLogger(mcert.address)

        self.view.cSet.append(self.cert)
        
        # Valid accusations. 
        self.vAccusations = {} 

        # Best accusation on each ring. Some might not be valid.
        self.pAccusations = {} 

        # At what time we received an accusation on each ring.
        self.hAccusations = {} 
        
        self._validAccusations = 0
        self._nrAccusations = 0
        self.nPing = 0
        
        # EXPECTEDLOSSRATE is the probability that one message gets
        # through. avgLoss is 1 + the expected value of the negative
        # binomial experiment with r = 1 and the probability, pSucc,
        # for a successful ping and pong exchange. Lossrate is
        # expected to be independent.
        pSucc = (1 - initLRate)**2 
        self.avgLoss = ((1-pSucc)/pSucc) + 1

        #self.lastPong = 0
        #self.firstAccused = 0
        #self._lastPinged = -1

        # Used by the web status displayer        
        self.allAccusations = []

        if not self.serial in hashCache:
            self._gIDCache = []
            self._mIDCache = []
            hashCache[self.serial] = (self._gIDCache, self._mIDCache)
            hashCache[self.serial]             
        else:
            self._gIDCache, self._mIDCache = hashCache[self.id]

        self.fdTimer = None

        self.stats = fireflies.stats.Stats()
        

    def getMask(self):
        """Returns a mask that is based on t, nr rings, accusation history, and the old mask."""

        t = self.view.getT()
        nrr = self.view.getNrMonitorRings()


        # We need to disable t rings. If the member has not been
        # accused on at least t rings, we pick disabled rings from the
        # old mask. If the note has not been set for this member, we
        # build a random mask.


        # p1 is a list of the ring numbers we are to disable. p1 is
        # sorted according to which rings are to be disabled first.         
        p1 = map(lambda x: (self.hAccusations[x], x), self.hAccusations.keys())
        p1.sort()
        p1.reverse()
        p1 = map(lambda x: x[1], p1)

        if self.note:
            p2 = list(self.note.mask)
        else:
            p2 = [False] * t + ([False] * (nrr - t))
            random.shuffle(p2)
            
        p2 = map(lambda x: (x, p2[x]), range(nrr))
        p2 = filter(lambda x: not (x[1] or  (x[0] in p1)), p2)
        p2 = map(lambda x: x[0], p2)
        random.shuffle(p2)
        p1.extend(p2)

        mask = [True] * nrr
        for x in p1:
            mask[x] = False
        return mask
            

    def isFailed(self):
        """Returns True if the member is failed."""
        
        return self in self.view.fRing

    def isAccused(self):
        """Return True if the member is accused."""

        return bool(self.vAccusations)

    def isAccusedOn(self, ring):
        """Returns True if the member is accused on ring."""

        return self.vAccusations.has_key(ring)


    def setNote(self, note):
        """Update the note of this member.

        Raises ValueError if: the note do not match the certificate,
        the note is older than the current note, or the note is not
        signed correctly by the member.
        """

        if self.serial != note.serial:
            raise ValueError("Note do not match certificate.")

        if not self.mcert.verify(note):
            raise ValueError("Note not signed correctly.")
        
        if self.note:
            if self.note.lifeline >= note.lifeline:
                raise ValueError("Lifeline must be larger.")

        self.view.nSet.append(note)
        if self.note:
            self.view.nSet.remove(self.note)
        self.note = note

    def setAccusation(self, accusation):
        """Keep the given accusation. This will invalidate and
        overwrite an existing accusation on the particular ring.""" 

        nr = accusation.nr
        assert accusation.lifeline == self.note.lifeline
        assert accusation.accused == self.serial
        assert self.note.mask[nr]

        oldA = self.pAccusations.get(nr, None)
        if oldA:
            self.view.aSet.remove(oldA)
        self.pAccusations[nr] = accusation
        self.view.aSet.append(accusation)
        
        try: del self.vAccusations[nr]
        except KeyError: pass

    def hasAccusations(self):
        """Returns True if there are one or more accusations on the
        member. This includes invalid accusations."""
        
        return bool(self.pAccusations)

    def hasAccusationOn(self, ring):
        """Returns True if there is is an accusations on the given
        ring. This includes invalid accusation."""
        
        return self.pAccusations.has_key(ring)

    def validateAccusation(self, nr):
        """Validate the accusation on ring 'nr'.

        Raises KeyError if there currently is no accusation on the ring."""
        
        if not self.pAccusations.has_key(nr): raise KeyError, "No accusation available on ring %d" % nr
        assert self.pAccusations[nr]
        self.vAccusations[nr] = self.pAccusations[nr]
        self.hAccusations[nr] = fireflies.time.time()
        
    def invalidateAccusation(self, nr):
        """Invalidate the accusation on ring 'nr'."""

        try:
            del self.vAccusations[nr]
        except KeyError:
            raise KeyError, "No vaid accusation on ring %d" % nr

    def invalidateAllAccusations(self):
        """Invalidates all accusations."""
        
        self.vAccusations = {}

    def clearAccusations(self):
        """Remove all accusations for made on this peer."""
        self.vAccusations = {}
        for a in self.pAccusations.values():
            self.view.aSet.remove(a)
        self.pAccusations = {}
        
    def gRingID(self, nr):
        """Return a members's identifier on gossip ring nr."""

        try:
            return self._gIDCache[nr]
        except IndexError:
            while len(self._gIDCache) <= nr:
                self._gIDCache.append(SHA.new("%s-g-%d" % (self.serial, len(self._gIDCache))).digest())
        return self._gIDCache[nr]

    def mRingID(self, nr):
        """Return a members's identifier on monitor ring nr."""
        try:
            return self._mIDCache[nr]
        except IndexError:
            while len(self._mIDCache) <= nr:
                self._mIDCache.append(SHA.new("%s-m-%d" % (self.serial, len(self._mIDCache))).digest())
        return self._mIDCache[nr]

    def __repr__(self):
        #return "%x" % bytes_to_long(self.serial)
        return  "P:%s,%d" % (self.cert.address, len(filter(None, self.vAccusations)))

    def __cmp__(self, other):
        try:
            return cmp(self.serial, other.serial)
        except AttributeError, why:
            return -1


class FFReconSet(setrecon.ReconSet):
    def elmToZZp(self, elm):
        return setrecon.to_ZZ_p(setrecon.to_ZZFromBytes(elm.shash()))


class View:
    """Membership view.

    The view is modified by adding certificates, notes, or
    accusations (see add* methods).

    The view is initialized with the CA certificate. 

    registerListener --- registers a callback object that will receive
    view events. Such object must implement the following methods:

       handle_leave(member): Member leaves or fails.
       handle_join(member):  Member joins.
       handle_rebuttal(member): A rebuttal is received from member.
       handle_accused(member): A member is accused. 
    
    """
    
    def __init__(self, cacert):
        """Create a new view with cacert as authority."""

        self.cSet = FFReconSet(PARTITION_FACTOR, RECON_EXTRA)
        self.nSet = FFReconSet(PARTITION_FACTOR, RECON_EXTRA)
        self.aSet = FFReconSet(PARTITION_FACTOR, RECON_EXTRA)

        self._listeners = []
        self.cacert = cacert
        self.sn2peer = {} # Maps serial nr's to peer objects.

        self.stats = fireflies.stats.Stats()
        
        self.aRing = SerialRing() # List of live members. Sorted by their serial number.
        self.pRing = SerialRing() # List of all members.
        self.fRing = SerialRing() # List of failed members. Sorted by their serial number.

        nrmr = cacert.config['T']*2 + 1
        nrgr = cacert.config['NUM_GOSSIPRINGS']
        self.mRings = []
        for x in range(nrmr):
            self.mRings.append(MonitorRing(x))
        self.gRings = []
        for x in range(nrgr):
            self.gRings.append(GossipRing(x))

        self.logger = logging.getLogger(cacert.name)
        self._dirty = False

    def getMember(self, serial):
        return self.sn2peer[serial]

    def getMembersByAddress(self, address):
        return filter(lambda x: x.cert.address == address, self.pRing)
        
    def rebuttalTime(self):
        return self.cacert.config['REBUTTAL_TIME']

    def getT(self):
        return self.cacert.config['TMIN']

    def getNrMonitorRings(self):
        return len(self.mRings)

    def clear(self):
        """Clear the membership."""

        # Remove circular dependency.
        for p in self.pRing:
            p.view = None
            
        self._listeners = []
        self.sn2peer = {} 
        self.aRing = SerialRing()
        self.pRing = SerialRing()
        self.fRing = SerialRing()

        self.cSet = FFReconSet()
        self.nSet = FFReconSet()
        self.aSet = FFReconSet()

        nrmr = cacert.config['T']*2+1
        nrgr = cacert.config['NUM_GOSSIPRINGS']
        self.mRings = []
        for x in range(nrmr):
            self.mRings.append(MonitorRing(x))
        self.gRings = []
        for x in range(nrgr):
            self.gRings.append(GossipRing(x))
                
    def registerListener(self, object):
        """Register an object that will receive membership events.

        Raises ValueError if object is already registered.
        """

        if object in self._listeners:
            raise ValueError("Dublicate object.")
        self._listeners.append(object)

    def unregisterListener(self, object):
        """Unregister object as a membership event listener.

        Raises ValueError if object is not registered previously.
        """
        
        self._listeners.remove(object)
        
    def fail(self, member):
        """Make a live member failed.

        Raises ValueError is member is not a live member in the view.
        """
        
        if member.view != self: raise ValueError("Peer not in view.")
        assert member in self.pRing
                
        self.aRing.remove(member)
        self.fRing.insert(member)
        
        try:
            if not (member.fdTimer.called):
                member.fdTimer.cancel()
        except AttributeError:
            pass
        member.fdTimer = None
        member.stats.failed += 1
        
        self.logger.info("failed %s s=%d t=%d", member, len(self.aRing), len(self.pRing))        

        for l in self._listeners:
            l.handle_leave(member)
            #reactor.callLater(0, l.handle_leave, member)

    def revive(self, member):
        """Make a failed member live.

        Raises ValueError if the member is not failed.
        """
        
        if member.view != self: raise ValueError("Member not in view.")
        assert member in self.pRing

        self.fRing.remove(member)
        self.aRing.insert(member)
        member.nPing = 0
        if member.isAccused():
            self.logger.warning("revived peer is accused. Setting timeout.")
            assert not member.fdTimer
            member.fdTimer = reactor.callLater(self.rebuttalTime(), self.fail, member)

        self.logger.info("joined %s s=%d t=%d", member, len(self.aRing), len(self.pRing))        
        member.stats.revived += 1
        for l in self._listeners:
            #reactor.callLater(0, l.handle_join, member)
            l.handle_join(member)
            
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
                self.logger.debug("discard %s byzantine behaviour", self.pprint(accusation))
                continue
            
            if accusation.lifeline < accused.note.lifeline:
                self.stats.accusationsRedundant += 1
                self.logger.debug("discard %s newer note", self.pprint(accusation))
                continue

            if accusation.lifeline > accused.note.lifeline:
                self.stats.accusationsInvalid += 1
                self.logger.debug("discard %s accusing newer note.", self.pprint(accusation))
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
                
                self.logger.warning("add %s New Possible", self.pprint(accusation))
                accused.allAccusations.insert(0, accusation)
                if len(accused.allAccusations) > HISTORYSIZE: accused.allAccusations.pop(-1)
            else:
                # Peer has been accused on this ring.
                if pa.accuser == accusation.accuser:
                    # We have this accusation
                    self.stats.accusationsRedundant += 1
                    self.logger.warning("discard %s dublicate", self.pprint(accusation))
                    continue

                ca = self.sn2peer[pa.accuser] #Current accuser
                if ring.between(ca, accuser, accused):
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
                    
                    self.logger.warning("discard %s have closer", self.pprint(accusation))

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

        nrrings = self.getNrMonitorRings()
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

                    # In my view, cm is the current valid monitor to
                    # the accused.
                    cm = ring.pred(accused)

                    # The accusation is valid if the accuser is the
                    # predecessor of the accused, the accuser is the
                    # accused, or the accuser is closer on the ring
                    # than the current monitor (i.e. accuser can be
                    # accused or failed).
                    if (cm.id == accuser.id) or (cm.id == accused.id) or (ring.between(cm, accuser, accused)):

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
                    self.logger.debug("revive %s accusations invalidated", self.pprint(peer))
                    self.revive(peer)
                    continue

                # If a member is not accused, any fail-timer should be
                # removed.
                try:
                    self.fdTimer.cancel()
                    peer.stats.accusedClear += 1
                except AttributeError:
                    pass
                self.fdTimer = None                
            else:
                if isFailed: continue
                if peer.fdTimer: continue
                peer.stats.accusedFirst += 1
                peer.fdTimer = reactor.callLater(self.cacert.config['REBUTTAL_TIME'], self.fail, peer)
                for l in self._listeners:
                    l.handle_accused(peer)
                    #reactor.callLater(0, l.handle_accused, peer)

        self._dirty = False
        
        
    def addCerts(self, certs):
        if not type(certs) == type([]):
            certs = [certs, ]
        for c in certs:
            self.stats.certsTotal += 1
            
            if not self.cacert.verify(c): 
                self.stats.certsInvalid += 1
                self.logger.warning("discard %s invalid CA signature.", self.pprint(c))
                continue

            member = self.sn2peer.get(c.serial, None)
            if member:
                member.stats.certsRedundant += 1
                #self.logger.debug("discard %s redundant", self.pprint(c))
                continue

            
            member = Member(c, self)
            assert not member in self.pRing
            self.sn2peer[member.id] = member

            # Add peer to all necessary rings.
            for ring in self.mRings + self.gRings + [self.fRing, self.pRing]:
                assert not member in ring
                ring.insert(member)
            #self.fRing.insert(member)
            #self.pRing.insert(member)
            c.setTimestamp()
            self.logger.info("new %s s=%d t=%d", member, len(self.aRing), len(self.pRing))        
                   
    def addNotes(self, notes, delayCheck=False):
        if not type(notes) == type([]):
            notes = [notes, ]
            
        for note in notes:
            assert note
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
        
            if (not peer.note) or (note.lifeline > peer.note.lifeline):
                self.logger.debug("add %s updated (old=%s)", self.pprint( note), self.pprint(peer.note))

                peer.setNote(note)
                peer.stats.noteUpdated += 1                
                peer.clearAccusations()
                try:
                    peer.fdTimer.cancel()    
                except AttributeError:
                    pass
                peer.fdTimer = None
                
                self._dirty = True
                note.setTimestamp()
                if peer in self.fRing:
                    self.logger.info("revive %s", self.pprint(note))
                    self.revive(peer)
                else:
                    pass                
                for l in self._listeners:
                    l.handle_rebuttal(peer)
                    #reactor.callLater(0, l.handle_rebuttal, peer)
            else:
                self.stats.notesRedundant += 1
                
        if (not delayCheck) and self._dirty: self.checkAccusations()

    def pprint(self, data):
        if type(data) == Note:
            if data.serial in self.sn2peer:
                peer = self.sn2peer[data.serial]
                return "N:%s-%d" % (peer.cert.address, data.lifeline)
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
                                      data.lifeline,
                                      data.nr,
                                      accuser
                                      )
        else:
            return str(data)



def __ringIterator(ring, start=0):
    for x in range(len(ring)):
        yield ring[x]
        

def __ringTraverse(ring, idx):
    l = len(ring)
    idx = (start + 1) % l
    while 1:
        yield ring[idx]
        idx = (idx + 1) % l
        if idx == start: break
    

class Ring(object):    
    """A ring is a finite field of items. A ring is similar to Python
    list but items are kept sorted according to their sort
    key. Inserting two items with the same key will raise a ValueError
    exception.
    
    This implementation uses the return value of the items hash
    function as the sort keys. To use a different sort key,
    re-implement the _sortKey method in a subclass. Keys can be any
    object that implements a __hash__ and __cmp__ method, and is
    unique to each object.    
    """

    def __init__(self):
        self.__keylist = []
        self.__key2itm = {}

    def _sortKey(self, item):
        """Returns the key used for sorting items. 
        
        This implementation uses the item's hash function return value
        as a key. Reimplement this method in a subclass to use other
        sort keys."""
        return hash(item)

    def __iterate__(self):
        """Iterate the ring starting at the lowest number.
        
        The ring should not be modified during iteration."""
        return __ringIterator(self, 0)

    def traverse(self, item):
        """Iterates the ring starting at item's successor."""
        idx = self.__keylist.index(self._sortKey(item))        
        return __ringIterator(self, idx)

    def __len__(self):
        return len(self.__keylist)
        
    def __getitem__(self, idx):
        key = self.__keylist[idx]
        return self.__key2itm[key]
        
    def __contains__(self, item):
        key = self._sortKey(item)
        return key in self.__key2itm

    def index(self, item):
        """Return the item's index in the ring. Raises ValueError if
        the item is not in the ring."""

        key = self._sortKey(item)
        try:
            return self.__keylist.index(key)
        except ValueError:
            raise ValueError, "Item %s not in ring" % str(item)
        
    def insert(self, item):
        """Insert item into the ring. Raises ValueError if the item is
        already in the ring. Return index where item was inserted."""

        key = self._sortKey(item)
        if key in self.__key2itm:
            raise ValueError, "Item %s already in list" % (str(item))        
        idx = bisect.bisect_right(self.__keylist, key)
        self.__keylist.insert(idx, key)
        self.__key2itm[key] = item
        return idx

    def remove(self, item):
        """Remove item from the ring. Raises ValueError if the item is
        not in the ring."""
        
        try:
            del self[self.index(item)]
        except ValueError:
            raise ValueError, "Item %s not in ring" % str(item)
        
    def __delitem__(self, idx):
        key = self.__keylist[idx]
        del self.__keylist[idx]
        del self.__key2itm[key]
    
    def sort(self):
        """Does nothing. Ring is sorted on insert."""        
        pass

    def between(self, lp, bp, hp):
        """Returns True if bp lies between lp and hp on the ring.

        Please note the following:

          - Nothing lies between an item and itself. That is, if
          lp == hp this method returns False.

          - An item is always between itself and any other item. That
          is, if lp == bp, or hp == bp but hp != lp, this method
          returns True.

          - Raises a ValueError if lp, bp, or hp is not in the ring.          
        """
        
        li = self.index(lp)
        bi = self.index(bp)
        hi = self.index(hp)
        if hi > li:
            if bi <= li or bi >= hi: return False
            else: return True
        elif hi < li:
            if bi > li or bi < hi: return True
            else: return False
        else:
            return False

    def succ(self, item):
        """Returns the the successor of item. Raises ValueError if
        item is not in the ring. If the ring contains only item, item
        will be returned.
        """
        
        key = self._sortKey(item)
        idx = self.__keylist.index(key)
        idx = (idx + 1) % len(self.__keylist)
        key = self.__keylist[idx]
        return self.__key2itm[key]
    
    def pred(self, item):
        """Returns the predecessor if item. Raises ValueError if item
        is not in the ring. If the ring contains only item, item will be returned.
        """
        
        key = self._sortKey(item)
        idx = self.__keylist.index(key)
        idx = (idx - 1) % len(self.__keylist)
        key = self.__keylist[idx]
        return self.__key2itm[key]

        
class SerialRing(Ring):
    """A ring of Peer object. The ring is sorted according to the peer
    id attribute."""

    def _sortKey(self, item):
        return item.id

        
class MonitorRing(Ring):
    """A Fireflies monitor ring. The item's mRingID function is used
    for generating sort keys. This class also needs to be instantiated
    with the number of the monitor ring.
    """
    
    def __init__(self, nr):
        """nr - The monitor-ring number."""
        self.nr = nr
        super(MonitorRing, self).__init__()
        
    def _sortKey(self, peer):
        return peer.mRingID(self.nr)


class GossipRing(Ring):
    """A Fireflies gossip ring. The item's gRingID function is used
    for generating sort keys. This class also needs to be instantiated
    with the number of the gossip ring.
    """
    
    def __init__(self, nr):
        """nr - The monitor-ring number."""
        self.nr = nr
        super(GossipRing, self).__init__()
    def _sortKey(self, peer):
        return peer.gRingID(self.nr)
