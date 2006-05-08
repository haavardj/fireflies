# -*- coding: iso-8859-1 -*-
######################################################################
## Filename:      members.py
## Description:   Fireflies member structures.
## Author:        Håvard Dagenborg Johansen <haavardj@cs.uit.no>
## Modified at:   Tue Jan 24 10:39:41 2006
## Modified by:   Håvard Dagenborg Johansen <haavardj@cs.uit.no>
## Licence:       GPL (see the LICENSE file).
##  
##         Copyright© 2006, University of Tromsø (Norway)
##                
## $Id: members.py,v 1.5 2006/05/08 09:47:55 haavardj Exp $
##                
######################################################################



from Crypto.Hash import SHA
from Crypto.Util.number import long_to_bytes, bytes_to_long
from math import *
from twisted.internet import reactor
import bisect, fireflies, logging, setrecon
import random
import fireflies.stats
import fireflies.crypto
from fireflies.ring import Ring

from fireflies.interfaces import IMember
from zope.interface import implements

HISTORYSIZE = 100
INITIAL_LRATE = 0.10


class FirefliesError(Exception):
    """A generic fireflies exception."""

class ByzantineError(FirefliesError):
    """Raised when byzantine behaviour is detected.
   
    offender  --- the id of the offender.
    """
    
    def __init__(self, serial=None):
        self.offender = serial
    
def isValidMask(mask, t):
    """Returns True if mask is valid given a Byzantine tolerance factor t."""
    if len(filter(lambda x: x == True, mask)) != t + 1: return False 
    if len(filter(lambda x: x == False, mask)) != t: return False 
    return True 

def getMask(member, t):
    #"""Returns a mask that is based on t, nr rings, accusation history, and the old mask."""
    
    #t = self.__view.getT()
    #nrr = 2*t + 1
    
    # We need to disable t rings. If the member has not been
    # accused on at least t rings, we pick disabled rings from the
    # old mask. If the note has not been set for this member, we
    # build a random mask.
    
    # p1 is a list of the ring numbers we are to disable. p1 is
    # sorted according to which rings are to be disabled first.         
    
    if not isinstance(member, Member): raise ValueError
    
    p1 = map(lambda x: (member.__hAccusations[x], x), member.__hAccusations.keys())
    p1.sort()
    p1.reverse()
    p1 = map(lambda x: x[1], p1)

    if member._note and isValidMask(member._note.mask, t):
        p2 = list(member._note.mask)
    else:
        p2 = ([False] * t) + ([True] * (t+ 1))
        random.shuffle(p2)
            
    for n, v in enumerate(p2):
        if v == True: continue
        if len(p1) >= t: break
        if n not in p1: p1.append(n)
        
    if not len(p1) >= t:
        raise RuntimeError("Mask computation error.")

    p1 = p1[0:t]
        
    mask = [True] * (2*t + 1)
    for n in p1:
        mask[n] = False
        
    assert isValidMask(mask, t)
    return mask            


class Accusation(object, fireflies.crypto.RSASignable):
    """A Fireflies accusation. Except for the signature, this class
    should be considered immutable."""

    def __init__(self, accused, epoch, nr, accuser):
        self.accused = accused
        self.epoch = epoch
        self.nr = nr
        self.accuser = accuser 
        self.signature = 0

    def __getstate__(self):
        return {"accused": self.accused,
                "epoch": self.epoch,
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
        return "Accusation:%d,%d,%d-%d" % (bytes_to_long(self.accused), self.epoch,
                                  self.nr, bytes_to_long(self.accuser))

        
def createInitialNote(serial, t):
    """Return a note with the specified serial, initial epoch of 1,
    and a 2t+1 length mask with t disabled rings."""

    rings = 2*t + 1
    mask = [False] * t + ([True] * (rings - t))
    random.shuffle(mask)
    return Note(serial, 1, mask)


class Note(object, fireflies.crypto.RSASignable):
    """A Fireflies note. Except for the signature, this class
    should be considered immutable.

    Important attributes are:
      - serial --- The member's serial number.
      - epoch --- The epoch/epoch of the note.
      - mask --- A list of True/False values. True means the corresponding
                 monitoring ring is enabled.
      - signature ---
      - data --- A string.
    """

    def __init__(self, serial, epoch, mask):        
        self.serial = serial
        self.epoch = epoch
        self.mask = mask
        self.signature = 0
        self.badness = 0

    def __repr__(self):        
        return "N:%x-%d" % (bytes_to_long(self.serial), self.epoch)

    def __hash__(self):
        return hash(self.shash())

    def __getstate__(self):
        return {"serial": self.serial,
                "epoch": self.epoch,
                "mask": self.mask,
                "signature": self.signature,
                "badness": self.badness
                }
    
    def __setstate__(self, data):
        for k,v in data.items():
            setattr(self, k, v)

    def __cmp__(self, other):
        try: return cmp(self.shash(), other.shash())
        except AttributeError: return -1

    def uidstr(self):
        return "Note:%d-%d-%s" % (bytes_to_long(self.serial), self.epoch,
                                  str(self.mask))
    
    


class Member(object):
    """A Fireflies member."""
    
    implements(IMember)

    def __init__(self, cert, note = None, initLRate=INITIAL_LRATE):

        assert isinstance(cert, fireflies.crypto.MemberCertificate)
        #assert isinstance(view, View)
        if note: assert isinstance(note, Note)
        
        self._cert = cert
        self._note = None 
                
        if note:
            assert isinstance(self._note, Note)       
            self._note = note
            
            #self.logger = logging.getLogger(mcert.address)
        
        # Valid accusations. 
        self.__vAccusations = {} 

        # Best accusation on each ring. Some might not be valid.
        #self.__pAccusations = {} 

        # At what time we received an accusation on each ring.
        self.__hAccusations = {} 
        
        #self.__validAccusations = 0
        #self.__nrAccusations = 0
        
        self.__failed = True
        
        #self.nPing = 0
        
        # EXPECTEDLOSSRATE is the probability that one message gets
        # through. avgLoss is 1 + the expected value of the negative
        # binomial experiment with r = 1 and the probability, pSucc,
        # for a successful ping and pong exchange. Lossrate is
        # expected to be independent.
        #pSucc = (1 - initLRate)**2 
        #self.avgLoss = ((1-pSucc)/pSucc) + 1


        # Used by the web status displayer        
        #self.allAccusations = []

        #if not self.serial in hashCache:
        #    self._gIDCache = []
        #    self._mIDCache = []
        #    hashCache[self.serial] = (self._gIDCache, self._mIDCache)
        #    hashCache[self.serial]             
        #else:
        #   self._gIDCache, self._mIDCache = hashCache[self.id]
        #
        # self.fdTimer = None
        # self.stats = fireflies.stats.Stats()

    def _setFailed(self, failed):
        """Set the failed status of the member."""
        
        # A member should never be set live when there's been no note.
        if not failed: assert self._note
        self.__failed = failed

    #
    # IMember interface
    #
    def getAddress(self):
        """Return member's Internet address (ip:port tuple)."""
        return self._cert.address

    def getNote(self):
        return self._note

    def getCertificate(self):
        """Return member's fireflies.crypto.MemberCertificate object."""
        return self._cert
    
    def getSerial(self):
        """Return serial number / member id."""
        return self._cert.serial
        
    def isFailed(self):
        """Return True if the member is failed."""
        
        # A member without a note is failed.
        if not self._note: return True
        return self.__failed

    def isAccused(self):
        """Return True if the member is accused."""
        
        # Catches the instance when a member has no accusation and no note.
        if self.__failed: return False
        return bool(self.__vAccusations)

    #
    # Other funcs
    # 
    def isRingEnabled(self, ringNr):
        """Return True if member has enabled ringNr."""
        
        if not self._note: return False
        return self._note.mask[ringNr]

    def isAccusedOn(self, ring):
        """Returns True if the member is accused on ring."""
        return self.__vAccusations.has_key(ring)


    #def setNote(self, note):
        #"""Update the note of this member.

        #Raises ValueError if: the note do not match the certificate,
        #the note is older than the current note, or the note is not
        #signed correctly by the member.
        #"""
        #assert  isinstance(note, Note)
        
        #if self.serial != note.serial:
            #raise ValueError("Note do not match certificate.")

        #if not self.mcert.verify(note):
            #raise ValueError("Note not signed correctly.")
        
        #if self._note:
            #if self._note.epoch >= note.epoch:
                #raise ValueError("Lifeline must be larger.")

        #self.view.nSet.append(note)
        #if self._note:
            #self.view.nSet.remove(self._note)
        #self._note = note
        

    #def setAccusation(self, accusation):
        #"""Keep the given accusation. This will invalidate and
        #overwrite an existing accusation on the particular ring.""" 

        #nr = accusation.nr
        #assert accusation.epoch == self._note.epoch
        #assert accusation.accused == self.serial
        #assert self._note.mask[nr]

        #oldA = self.__pAccusations.get(nr, None)
        #if oldA:
            #self.view.aSet.remove(oldA)
        #self.__pAccusations[nr] = accusation
        ##self.__view.aSet.append(accusation)
        
        #try: del self.vAccusations[nr]
        #except KeyError: pass

    def getAccusation(self, ringNr):
        return self.__vAccusations[ringNr]

    def getAccusations(self):
        return self.__vAccusations.values()
    
    def _setAccusation(self, elm):
        if not isinstance(elm, Accusation): raise TypeError
        self.__vAccusations[elm.nr] = elm

    def _delAccusation(self, ring):
        self.__vAccusations.pop(ring)

    def hasAccusations(self):
        """Returns True if there are one or more accusations on the
        member. This includes invalid accusations."""
        
        return bool(self.__pAccusations)

    def hasAccusationOn(self, ring):
        """Returns True if there is is an accusations on the given
        ring. This includes invalid accusation."""
        
        return self.__vAccusations.has_key(ring)

    #def validateAccusation(self, nr):
        #"""Validate the accusation on ring 'nr'.

        #Raises KeyError if there currently is no accusation on the ring."""
        
        #if not self.__pAccusations.has_key(nr): raise KeyError, "No accusation available on ring %d" % nr
        #assert self.__pAccusations[nr]
        #self.__vAccusations[nr] = self.__pAccusations[nr]
        #self.__hAccusations[nr] = fireflies.time.time()
        
    #def invalidateAccusation(self, nr):
        #"""Invalidate the accusation on ring 'nr'."""
        #try:
            #del self.__vAccusations[nr]
        #except KeyError:
            #raise KeyError, "No vaid accusation on ring %d" % nr

    #def invalidateAllAccusations(self):
        #"""Invalidates all accusations."""
        #self.__vAccusations = {}

    def _clearAccusations(self):
        """Remove all accusations."""
        self.__vAccusations = {}
        #self.__pAccusations = {}

    def __repr__(self):
        #return "%x" % bytes_to_long(self.serial)
        return  "P:%s,%d" % (self._cert.address, len(filter(None, self.__vAccusations)))

    def __cmp__(self, other):
        try:
            return cmp(self._note.serial, other._note.serial)
        except AttributeError, why:
            return -1



__mRingIDCache = {}
def _mRingID(member, ringNr):
    """Return a members's identifier on gossip ring nr."""
    
    if False: isinstance(member, Member)    
    try:
        return __mRingIDCache[member.getSerial()][ringNr]
    except KeyError:
        memberId = member.getSerial()
        ids = __mRingIDCache.get(memberId, {})
        idOnRing = SHA.new("%s-gossip-%d" % (memberId, ringNr)).digest()
        ids[ringNr] = idOnRing
        __mRingIDCache[memberId] = ids
        return idOnRing
        
class MonitorRing(Ring):
    """A Fireflies monitor ring."""
    
    def __init__(self, nr):
        """nr - The monitor-ring number."""
        self.nr = nr
        super(MonitorRing, self).__init__()
        
    def _sortKey(self, member):
        return _mRingID(member, self.nr)

class SerialRing(Ring):
    """A ring of Peer object. The ring is sorted according to the peer
    id attribute."""

    def _sortKey(self, item):
        return item.getSerial()


    

class MemberRings:
    """This class implements the membership rules. The rings are modified by
    adding accusations, notes, and certificates. The rings has no consept of
    failed/vs live members, only accused/not accused."""
    
    def __init__(self, t):

        self.__t = t
        self.__nrRings = 2*t + 1
        self.__listeners = []
        self.__sn2peer = {} # Maps serial nr's to IMember objects.
        #self.__pRing = SerialRing() # List of all members.
        self.stats = fireflies.stats.Stats()
        
        #self.aRing = SerialRing() # List of live members. Sorted by their serial number.
        #self.fRing = SerialRing() # List of failed members. Sorted by their serial number.
        #nrmr = cacert.config['T']*2 + 1
        #nrgr = cacert.config['NUM_GOSSIPRINGS']
        #self.cSet = FFReconSet(PARTITION_FACTOR, RECON_EXTRA)
        #self.nSet = FFReconSet(PARTITION_FACTOR, RECON_EXTRA)
        #self.aSet = FFReconSet(PARTITION_FACTOR, RECON_EXTRA)        
        
        self.__mRings = []
        for x in range(self.__nrRings):
            self.__mRings.append(MonitorRing(x))

        #self.logger = logging.getLogger(cacert.name)

    def getMemberBySerial(self, serial):
        """Return the IMember object of the member identified by serial.
        
        Raises KeyError if serial is unknown."""
        return self.__sn2peer[serial]

    def succ(self, itm, func=lambda x: True):
        """Return for each ring the first successor of itm for which func evaluates to true."""
        return map(lambda x: x.succ(itm, func), self.__mRings)

    def pred(self, itm, func=lambda x: True):        
        """Return for each ring the first predecessor of itm for which func evaluates to true."""
        return map(lambda x: x.pred(itm, func), self.__mRings)

    def getRing(self, nr):
        return self.__mRings[nr]
    
    def getT(self):
        """Return the set Byzantine tolerance factor t."""
        return self.__t
    
    def getNrRings(self):
        """Return the number of rings (2t+1)."""
        return self.__nrRings
    
    def getNrMembers(self):
        return len(self.__mRings[0])
                
                
    def addAccusation(self, accusation):
        """Adds accusations.

        Return True if accusation was valid and accapted, othervise False.
        
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
                 - the accused epoch is larger than in the current held note.

        Events:
            - cb_add_accucation
            - cb_del_accusation"""
        
        if not isinstance(accusation, Accusation): raise TypeError            
        self.stats.accusationsTotal += 1
        
        accusedID = accusation.accused
        accuserID = accusation.accuser

        # Check that we know about accused. This should not really
        # happen if we gossip notes before accusations and
        # certificates before notes.
        if not accusedID in self.__sn2peer:
            self.stats.accusationsInvalid += 1
            self.logger.warning("discard %s Unknown accused", self.pprint(accusation))
            raise ValueError

        accused = self.__sn2peer[accusedID]
        assert isinstance(accused, Member)            
        # Ditto for the accuser
        if not accuserID in self.__sn2peer:
            self.stats.accusationsInvalid += 1
            self.logger.warning("discard %s Unknown accuser", self.pprint(accusation))
            raise ValueError
            
        accuser = self.__sn2peer[accuserID]
        assert isinstance(accuser, Member)  
        
        #if not accuser.cert.verify(accusation):
        #    accuser.stats.accuseByzantine += 1
        #    accused.stats.accusedByzantine += 1
        #    self.stats.accusationsInvalid += 1
        #    self.logger.warning("discard %s Invalid signature", self.pprint(accusation))
        #    continue
        
        if not accuser._note:
            self.stats.accusationsInvalid += 1
            self.logger.debug("discard %s invalid note", self.pprint(accusation))
            raise ValueError
            
        # Check that accusation is recent.
        if not accused._note:
            self.stats.accusationsInvalid += 1
            self.logger.warning("discard %s byzantine behaviour", self.pprint(accusation))
            raise ValueError
            
        if accusation.epoch < accused._note.epoch:
            self.stats.accusationsRedundant += 1
            self.logger.warning("discard %s newer note", self.pprint(accusation))
            return False

        if accusation.epoch > accused._note.epoch:
            self.stats.accusationsInvalid += 1
            self.logger.warning("discard %s accusing newer note.", self.pprint(accusation))
            raise False

        # Check that the accuser is not specifying an invalid ring.
        # No correct member should do this.
        if accusation.nr >= self.getNrRings():
            self.stats.accusationInvalid += 1
            accuser.accuseByzantine += 1
            accused.accusedByzantine += 1
            self.logger.warning("discard %s byzantine behavior. Not on a valid ring", self.pprint(accusation))
            raise ByzantineError(accuserID)

        # Check that the ring is enabled.
        # No correct member should violate this.
        if not accused._note.mask[accusation.nr]:
            self.stats.accusationInvalid += 1
            accuser.accuseByzantine += 1
            accused.accusedByzantine += 1
            self.logger.warning("discard %s byzantine behavior. Ring disabled by accused", self.pprint(accusation))
            raise ByzantineError(accuserID)

        # Make some shortcuts :-)
        #rnr = accusation.nr
        ring = self.__mRings[accusation.nr]
        isinstance(ring, MonitorRing)

        # If member currently is accused on ring, keep the new one only if it
        # is from a closer predecessor.
        if accused.hasAccusationOn(ring.nr):
            assert accused.isAccused()
            currentAccusation = accused.getAccusation(ring.nr)
            currentAccuser = self.getMemberBySerial(currentAccusation.accuser)
            assert isinstance(currentAccusation, Accusation)
            assert isinstance(currentAccuser, Member)
            
            if ring.isBetween(currentAccuser, accuser, accused):
                accused._setAccusation(accusation)
                self.__trigger_add_accusation(accusation)
                self.__trigger_del_accusation(currentAccusation)
                return True
            
        elif accuser == ring.pred(accused, func=lambda x: (not x.isAccused()) or (x == accuser)):
            # Valid accusation
            accused._setAccusation(accusation)
            self.__trigger_add_accusation(accusation)
            return True
            
        return False
        
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
            #if ring.between(ca, accuser, accused):
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

    #if (not delayCheck) and (self._dirty): self.__checkAccusations()


    #def __checkAccusations(self):
        
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

        #nrrings = self.getNrMonitorRings()
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
                    #if (cm.id == accuser.id) or (cm.id == accused.id) or (ring.between(cm, accuser, accused)):

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
                    #continue
                #else:
                    #pass
                    ##self.logger.warning("%s invalidated accusations", self.pprint(peer))
                ## If a member is not accused, any fail-timer should be
                ## removed.
                #try:
                    #self.fdTimer.cancel()
                    #peer.stats.accusedClear += 1
                #except AttributeError:
                    #pass
                #peer.fdTimer = None                
            #else:
                #if isFailed: continue
                #if peer.fdTimer: continue
                #peer.stats.accusedFirst += 1
                #self.logger.warning("%s validated accusations first.", self.pprint(peer))
                #peer.fdTimer = reactor.callLater(self.cacert.config['REBUTTAL_TIME'], self.fail, peer)
                #for l in self._listeners:
                    #l.handle_accused(peer)
                    ##reactor.callLater(0, l.handle_accused, peer)

        #self._dirty = False
        
        
    def addCert(self, elm):
        """Adds cert to the view.
        
        Return IMember object of the new member.
        
        Exceptions:
             -TypeError: elm is not a MemberCertificate object.
             -ValueError: The certificate already exists.

        Events:
            - cb_add_certificate"""
        
        if not isinstance(elm, fireflies.crypto.MemberCertificate): raise TypeError
        self.stats.certsTotal += 1
            
        # MOVEME
        #if not self.cacert.verify(c): 
        #    self.stats.certsInvalid += 1
        #    self.logger.warning("discard %s invalid CA signature.", self.pprint(c))
        #    continue
        
        m = self.__sn2peer.get(elm.serial, None)
        if m:
            m.stats.certsRedundant += 1
            #self.logger.debug("discard %s redundant", self.pprint(c))
            raise ValueError
        
        
        m = Member(elm)
        self.__sn2peer[m.getSerial()] = m
        
        # Add peer to all necessary rings.
        for ring in self.__mRings:
            assert not m in ring
            ring.insert(m)

        self.__trigger_add_certificate(elm)
        #self.logger.info("new %s s=%d t=%d", member, len(self.aRing), len(self.pRing))
        #self._dirty = True        
        return m
    
    def __contains__(self, serial):
        """Return True if the rings contains a member with serial."""
        return serial in self.__sn2peer
        
    def addNote(self, note):
        """Adds a note.
        
        Return True if the note was successfully added. Otherwise False.

        Exceptions:
           - TypeError: note is not a Note object.
           - ByzantineError: Invalid mask. Note must have disabled exactly t rings.
   
        Events:
           - cb_add_note
           - cb_del_note
           - cb_del_accusations"""
        
        if not isinstance(note, Note):
            raise TypeError
        
        self.stats.notesTotal +=1 
            
        #if not note.serial in self.sn2peer:
        #    self.stats.notesInvalid += 1
        #    self.logger.warning("discard %s unknown peer", self.pprint(note))
        #    continue
        
        m = self.__sn2peer[note.serial]
    
        assert isinstance(m, Member)
        assert (not m._note) or (m._note.serial == note.serial)
        
        #if not peer.cert.verify(note):
        #    self.stats.notesInvalid += 1
        #    self.logger.warning("discard %s invalid signature", self.pprint(note))
        #    continue
        
        if not isValidMask(note.mask, self.getT()): 
            #self.logger.warning("discard %s invalid mask", self.pprint(note))
            raise ByzantineError
        
        if m._note and m._note.epoch > note.epoch:
            return False
        
        if m._note and m._note.epoch == note.epoch:
            # We have the note. Return silently.
            return False
        
        self.logger.debug("add %s updated (old=%s)", self.pprint(note), self.pprint(m._note))
        
        if m._note: self.__trigger_del_note(m._note)
        m._note = note
        self.__trigger_add_note(note)
        
        #m.stats.noteUpdated += 1
        
        if m.isAccused():
            for a in m.vAccusations.values():
                self.__trigger_del_accusation(a)
            m.clearAccusations()

            # The member goes from an accused to not accused state. As such,
            # it may invalidate other accusations. 
            # Let m_j be m's first live successor on ring r.
            # All accusations for members between m and m_j
            #   If m between accuser and accuse: invalidate accusation.  
            #   If accused now is cleared, rerun for this member.
            
            check = [m,]
            while check:
                m = check.pop()      
                for ring in self.__mRings:
                    isinstance(ring, MonitorRing)                    
                    for q in ring.collectSucc(m, lambda x: not x.isAccused()):
                        isinstance(q, Member)
                        if not q.isAccusedOn(ring.nr): continue                        
                        qa = q.getAccusation(ring.nr)
                        assert isinstance(qa, Accusation)
                        accuser = self.getMemberBySerial(qa.accuser)
                        accused = self.getMemberBySerial(qa.accused)
                        if ring.isBetween(accuser, q, accused):
                            q.delAccusation(ring.nr)
                            self.__trigger_del_accusation(qa)
                            if not q.isAccused(): check.append(q)
                        
        return True

    def subscribe(self, object):
        """Register an object that will receive membership events.

        Raises ValueError if object is already registered."""

        if object in self.__listeners:
            raise ValueError("Dublicate object.")
        self.__listeners.append(object)

    def unsubscribe(self, object):
        """Unregister object as a membership event listener.
        
        Raises ValueError if object is not registered previously."""
        
        self.__listeners.remove(object)    
    
    def pprint(self, data):
        if type(data) == Note:
            if data.serial in self.__sn2peer:
                peer = self.__sn2peer[data.serial]
                return "N:%s-%d" % (peer.getAddress(), data.epoch)
            else:
                return  str(data)
            
        elif type(data) == Accusation:
            if data.accused in self.__sn2peer:
                accused = self.__sn2peer[data.accused].cert.address
            else: accused = "%x" % bytes_to_long(data.accused)
            if data.accuser in self.__sn2peer:
                accuser = self.__sn2peer[data.accuser].cert.address
            else: accuser = "%x" % bytes_to_long(data.accuser)

            return "A:%s-%d,%d,%s" % (accused,
                                      data.epoch,
                                      data.nr,
                                      accuser
                                      )
        else:
            return str(data)


    # Event triggers.
    def __trigger_add_note(self, elm):
        for l in self.__listeners:
            reactor.callLater(0, l._cb_add_note, elm)
        
    def __trigger_add_accusation(self, elm):
        for l in self.__listeners:
            reactor.callLater(0, l._cb_add_accusation, elm)

    def __trigger_add_certificate(self, elm):
        for l in self.__listeners:
            reactor.callLater(0, l._cb_add_certificate, elm)

    def __trigger_del_note(self, elm):
        for l in self.__listeners:
            reactor.callLater(0, l._cb_del_note, elm)
        
    def __trigger_del_accusation(self, elm):
        for l in self.__listeners:
            reactor.callLater(0, l._cb_del_accusation, elm)

    def __trigger_del_certificate(self, elm):
        for l in self.__listeners:
            reactor.callLater(0, l._cb_del_certificate, elm)
    
    def __trigger_valid_accusation(self, elm):
        for l in self.__listeners:
            reactor.callLater(0, l._cb_vaild_accusation, elm)
    
    def __trigger_invalid_accusation(self, elm):
        for l in self.__listeners:
            reactor.callLater(0, l._cb_invaild_accusation, elm)
    
