# -*- coding: iso-8859-1 -*-
######################################################################
## Filename:      members.py
## Description:   Fireflies member structures.
## Author:        Håvard Dagenborg Johansen <haavardj@cs.uit.no>
## Modified at:   Tue Jan 24 10:39:41 2006
## Modified by:   Håvard Dagenborg Johansen <haavardj@cs.uit.no>
## Licence:       GPL (see the LICENSE file).
##  
##         Copyright© 2007, Håvard D Johansen (Norway)
##                
## $Id: members.py,v 1.12 2007/07/09 08:59:59 haavardj Exp $
##                
######################################################################



from Crypto.Hash import SHA
from Crypto.Util.number import long_to_bytes, bytes_to_long
from math import *
from twisted.internet import reactor
import bisect, fireflies, cert, logging, setrecon
import random


INITIAL_LRATE = 0.10

def isValidMask(mask, t):
    """Returns True if mask is valid given a Byzantine tolerance factor t."""

    if len(filter(lambda x: x == True, mask)) != t + 1: return False 
    if len(filter(lambda x: x == False, mask)) != t: return False 
    return True 

def createInitialMask(t):
    """Return a mask of lenght 2t+1 with t randomly disabled rings."""

    rings = 2*t + 1
    mask = [False] * t + ([True] * (rings - t))
    random.shuffle(mask)
    return mask


def createRebuttal(member, group, priv):
    T = group.T
    if member.getEpoch() == 0:
        mask = createInitialMask(T)
    else:
        mask = getMask(member, T)
    n = Note(member.getSerial(), member.getEpoch()+1, mask)
    priv.sign(n)
    return n



class Accusation(object, cert.TimestampMixin, cert.RSASignable):
    """A Fireflies accusation. Except for the signature, this class
    should be considered immutable."""

    def __init__(self, accused, ll, nr, accuser):
        self.accused = accused
        self.epoch = ll
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


class Note(object, cert.TimestampMixin, cert.RSASignable):
    """A Fireflies note. Except for the signature, this class
    should be considered immutable.

    Important attributes are:
      - serial --- The member's serial number.
      - epoch --- The epoch/epoch of the note.
      - mask --- A list of True/False values. True means the corresponding
                 monitoring ring is enabled.
      - signature ---
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
                "badness": self.badness,
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
    """A Fireflies member.

    The following attributes are of interest:

    note - the member's latest note. Update only with setNote.
    cert - the member's certificate. Does not change.
    id/serial - the serial number of the member's certificate.
    """

    note = None

    def __init__(self, mcert, group, initLRate=INITIAL_LRATE):

        #assert isinstance(mcert, cert.MemberCertificate), type(mcert)
        #assert isinstance(view, fireflies.view.View)

        if not isinstance(group, fireflies.group.BaseGroup): raise ValueError
        
        self.cert = self.mcert = self._cert = mcert
        self.id = mcert.serial
        self.serial = self.mcert.serial
        self.group = group
        self.view = group.view       
            
        self.logger = logging.getLogger(mcert.address)
        
        # Valid accusations. 
        self.vAccusations = {} 

        # Best accusation on each ring. Some might not be valid.
        #self.pAccusations = {} 

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

        self.stats = fireflies.stats.Stats()
        self.__failed = True


    def setFailed(self, failed):
        """Set the failed status of the member."""
        
        # A member should never be set live when there's been no note.
        if not failed: assert self.note
        self.__failed = failed


    def getAddress(self):
        return self.mcert.address

    def getEpoch(self):
        if not self.note: return 0
        else: return self.note.epoch
    
    def getNote(self):
        return self.note
    
    def nextNote(self):
        """Return a note for this member based on previous notes.
        The returned note must be signed by this members private key before it is considered valid."""
        
        return Note(self.getSerial(), self.getEpoch() + 1, self.nextMask())       
    
    def nextMask(self): 
        """Compute the next mask for this member."""
    
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
        t = self.group.getByzantineToleranceLevel()
        if not self.note: return createInitialMask(t)
        assert isValidMask(self.note.mask, t)

        p2 = list(self.note.mask)
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
        
    
    def getCertificate(self):
        """Return member's fireflies.crypto.MemberCertificate object."""
        return self._cert
    
    def getAccusations(self):
        return self.vAccusations.values()
    
    def getAccusation(self, rnr):
        return self.vAccusations[rnr]
    
    def getSerial(self):
        """Return serial number / member id."""
        return self._cert.serial

          

    def isFailed(self):
        """Returns True if the member is failed."""
        
        # A member without a note is failed.
        
        if not self.note or self.note.epoch == 0: assert self.__failed
        return self.__failed
 
    def isLive(self):
        """Return true if member is concidered live."""
        return not self.isFailed()


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
        assert  isinstance(note, Note)
        
        if self.serial != note.serial:
            raise ValueError("Note do not match certificate.")

        if not self.mcert.verify(note):
            raise ValueError("Note not signed correctly.")
        
        if self.note:
            if self.note.epoch >= note.epoch:
                raise ValueError("Epoch must be larger.")

        if self.note:
            #self.view.nSet.remove(self.note)
            self.group.notify("data.note", self.note, False)
            
 
        self.note = note
        #self.view.nSet.append(note)
        self.group.notify("data.note", note, True)

        
    def setAccusation(self, accusation):
        """Keep the given accusation. This will invalidate and
        overwrite an existing accusation on the particular ring.""" 

        if not isinstance(accusation, Accusation): raise ValueError, accusation
        nr = accusation.nr
        assert accusation.epoch == self.note.epoch
        assert accusation.accused == self.serial
        assert self.note.mask[nr]

        if self.vAccusations.has_key(nr):
            a = self.vAccusations.pop(nr)
            self.group.notify("data.accusation", a, False)
            #self.view.aSet.remove(a)

        self.hAccusations[nr] = fireflies.time.time()
        self.vAccusations[nr] = accusation
        #self.view.aSet.append(accusation)
        self.group.notify("data.accusation", accusation, True)

    def invalidateAccusation(self, accusation):
        if not isinstance(accusation, Accusation): raise ValueError
        rnr = accusation.nr
        if not self.vAccusations[rnr] == accusation:
            raise ValueError, "Given accusation not valid."
        self.vAccusations.pop(rnr)
        self.group.notify("data.accusation", accusation, False)

    def invalidateAccusationOnRing(self, rnr):
        self.invalidateAccusation(self.vAccusations[rnr])
        
        
    def hasAccusations(self):
        """Returns True if there are one or more accusations on the
        member. This includes invalid accusations."""
        
        return bool(self.vAccusations)

    def hasAccusationOn(self, ring):
        """Returns True if there is is an accusations on the given
        ring. This includes invalid accusation."""
        
        return self.vAccusations.has_key(ring)
        
    def clearAccusations(self):
        """Remove all accusations for made on this peer."""
        for rnr, a in self.vAccusations.items():
            self.group.notify("data.accusation", a, False)
        self.vAccusations = {}

    def __repr__(self):
        #return "%x" % bytes_to_long(self.serial)
        return  "P:%s,%d" % (self.cert.address, len(filter(None, self.vAccusations)))

    def __cmp__(self, other):
        try:
            return cmp(self.serial, other.serial)
        except AttributeError, why:
            return -1
