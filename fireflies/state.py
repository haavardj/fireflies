######################################################################
## Filename:      state.py
## Description:   Fireflies member state classes.
## Author:        Haavard Dagenborg Johansen <haavardj@cs.uit.no>
## Modified at:   Tue Jan 24 10:39:41 2006
## Modified by:   Haavard Dagenborg Johansen <haavardj@cs.uit.no>
## Licence:       GPL (see the LICENSE file).
##  
##         Copyright 2007, Haavard D Johansen (Norway)
##                
## $Id: state.py,v 1.20 2011/12/12 12:20:28 haavardj Exp $
##                
######################################################################

"""This module provides classes that are used to represent the state of members in a group."""

from twisted.internet import reactor
import fireflies
from fireflies.stats import Stats
from fireflies import crypto
import bisect, setrecon, random, stats
import M2Crypto
import twisted


def isValidMask(mask, t):
    """
    Check the validity of a mask. A mask is valid if the following
    conditions are satisfied: - Its is of length 2t+1 - It has exactly
    t + 1 enabled elements.
    
    @param mask: The mask that is to be checked.
    @type mask: List of bools.
    @param t: Byzantine tolerance factor.
    @type t: int
    @return: True if mask is valid, otherwise False.
    @rtype: bool    
    """
    
    if len(mask) != 2* t + 1: return False
    if len(filter(lambda x: x == True, mask)) != t + 1: return False 
    return True 

def createInitialMask(t):
    """
    Create a mask of length 2t+1 with t randomly disabled rings.
    
    @param t: Byzantine tolerance factor.
    @type t: int
    @return: The created mask.
    @rtype: list of bools
    """

    rings = 2*t + 1
    mask = [False] * t + ([True] * (rings - t))
    random.shuffle(mask)
    return mask

def createInitialNote(member):
    """Create a note with the specified identity, initial epoch of 1,
    and a 2t+1 length mask with t disabled rings.
    
    @param member: Member object
    @return: A new note
    @rtype: L{Note}
    """

    isinstance(member, Member)
    t = member.group.view.toleranceLevel
    rings = 2*t + 1
    mask = [False] * t + ([True] * (rings - t))
    random.shuffle(mask)
    return Note(member.getIdentity(), 1, mask)

    

class Accusation(object, crypto.Signable):
    """
    Members issue Accusations to signal to other members failure suspicion. 
    Whenever a member suspects that one of its monitored members has failed, 
    it will issue an accusation for that member. 
    This accusation it then distributed to all other members and, if not rebutted, 
    will cause the accused member to be considered failed. 
    
    @ivar accused: The identity of the accused member.
    @type accused: str
    @ivar accuser: The identity of the member who issued the accusation.
    @type accuser: str
    @ivar nr: The ring number on which the accusation is made.
    @type nr: int
    @ivar epoch: The epoch of the accused note.
    @type epoch: int
    @ivar signature: Signature of the accuser.
    @type signature: str
    """

    def __init__(self, accused, ll, nr, accuser):
        self.accused = accused
        self.epoch = ll
        self.nr = nr
        self.accuser = accuser 

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
        try: return cmp(self.get_fingerprint(), other.get_fingerprint())
        except AttributeError: return -1

    def __hash__(self):
        return hash(self.get_fingerprint())

    def __repr__(self):        
            return "%s" % (self.uidstr())
        
    def uidstr(self):
        return "Accusation:%s,%d,%d-%s" % (self.accused, self.epoch,
                                  self.nr, self.accuser)

        

class Note(object, crypto.Signable):
    """Members issue notes to signal to other members that they are alive. In
    particular, a member will issue a new note as a rebuttal to a false
    accusation. Notes should be considered immutable after they are signed.

    @ivar identity: The member's identity.
    @type identity: str
    @ivar epoch: A monotonically increasing number.  
    @type epoch: int
    @ivar mask: A list of enabled/disabled monitoring rings. A True means enabled.
    @type mask: list of bools
    @ivar signature: Signed with the member's private key.
    @type signature: str
    """

    def __init__(self, identity, epoch, mask):        
        self.identity = identity
        self.epoch = epoch
        self.mask = mask
        self.badness = 0

    def __repr__(self):        
        return "N:%s-%d" % (self.identity, self.epoch)

    def __hash__(self):
        return hash(self.get_fingerprint())

    def __getstate__(self):
        return {"identity": self.identity,
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
        return "Note:%s-%d-%s" % (self.identity, self.epoch,
                               str(self.mask))

        
def shortIdentity(member):
    return member.getIdentity()[-4:]

import fireflies
class Member(object):
    """Encapsulates known state of a group member.

    @ivar group: The group in which this member is a member of.
    @type group: L{fireflies.group.Group}
    """
    
    initialLossRate = 0.001 

    def __init__(self, cert, group):

        isinstance(group, fireflies.group.Group)
        isinstance(cert, M2Crypto.X509.X509)
    
        self._cert = cert
        self._note = None
        self._group = group
        
        self.view = group.view       
  
        # Valid accusations. 
        self.vAccusations = {} 

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
        pSucc = (1 - self.initialLossRate)**2 
        self.avgLoss = ((1-pSucc)/pSucc) + 1

        # Used by the web status displayer        
        self.allAccusations = []

        self.stats = fireflies.stats.Stats()
        self._failed = True

    @property
    def logger(self):
        return self._group.logger

#    def verify(self, obj):
#        """Verify that obj is correctly signed by this member."""
#        return self._cert.verify(obj)


    def setFailed(self, status):
        """
        Update the failed/liveness status of the member.
        
        @param status: The new status of the member.
        @type status: bool
        """
        
        # A member should never be set live when there's been no note.
        status = bool(status)
        if not self._failed: assert self._note
        self._failed = status

    def getAddress(self):
        """
        @return: The member's network address and port number. 
        @rtype: IP:port string
        """
        return self._cert.get_subject().L
    
    @property
    def group(self):
        return self._group
    
    @property
    def address(self):
        host, port = self._cert.get_subject().L.split(":")
        port = int(port) 
        return twisted.internet.address.IPv4Address("TCP", host, port) 
    
    def getCommonName(self):
        return self._cert.get_subject().CN
    
    def getPublicKey(self):
        return self._cert.get_pubkey()
        
    def getEpoch(self):
        """
        @return: The member's current epoch number.
        @rtype: int
        """
        if not self._note: return 0
        else: return self._note.epoch
    
    def getNote(self):
        """
        @return: The member's most current note or None if no note is set.
        @rtype: L{Note}
        """
        return self._note
    
    def isEnabledOnRing(self, ring):
        return bool(self._note.mask[ring.name])
    
    def nextNote(self):
        """Compute a new note for the member based on any previous note and previous accusations. 
        The new note has a larger epoch number the the current note.
           
        @note: The returned note is not signed.
        @return: A new note object.
        @rtype: L{Note}
        """
        
        return Note(self.getIdentity(), self.getEpoch() + 1, self.nextMask())       
    
    def nextMask(self): 
        """
        Compute a new mask based on the previous mask and previous accusations.
        
        @return: A new mask.
        @rtype: list of booleans.
        """
    
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
        if not self.getNote(): return createInitialMask(t)
        assert isValidMask(self.getNote().mask, t)

        p2 = list(self.getNote().mask)
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
        """
        @return: The member's latest member certificate.
        @rtype: L{M2Crypto.X509.X509}
        """

        return self._cert
    
    def getAccusations(self):
        """
        
        @return: All current valid accusations.        
        @rtype: List of L{Accusation}
        """
        
        return self.vAccusations.values()
    
    def getAccusation(self, nr):
        """
        Get accusation for a specific ring.
        
        @param nr: Ring number
        @type nr: int
        @raises e: L{KeyError} if there are no accusations on ring nr.
        @return: The requested accusation, if any.
        @rtype: L{Accusation}
        """
        return self.vAccusations[nr]
    
    def getIdentity(self):
        """
        @return: The member's identity.
        @rtype: string
        """

        return crypto.identityFromCertificate(self._cert)

    identity = getIdentity
    
    def getPublicKey(self):
        return self._cert.get_pubkey()

    def isFailed(self):
        """
        @return: True if member is considered failed, otherwise False.
        @rtype: bool
        """
        
        # A member without a note is failed.        
        if not self.getNote() or self.getNote().epoch == 0: assert self._failed
        return self._failed
 
    def isLive(self):
        """
        @return: True if the member is considered live, otherwise False.
        @rtype: bool
        """
        return not self.isFailed()


    def isAccused(self):
        """
        @return: True if the member is accused of having failed, otherwise False.
        @rtype: bool
        """

        return bool(self.vAccusations)

    def isAccusedOn(self, nr):
        """
        Checks if member is accused on a particular ring.
        
        @return: True if the member is accused on the given ring, otherwise False.
        @rtype: bool
        @param nr: Ring number
        @type nr: int
        """

        return self.vAccusations.has_key(nr)

    def setNote(self, note):
        """
        Update the note of this member.

        @param note: The new note.
        @type note: L{Note}        
        @raise L{ByzantineError}: If the given note 
          - does not belong to this member, 
          - is is older than the current one, or
          - is not correctly signed.
        """
        assert  isinstance(note, Note)
        
        if self.getIdentity() != note.identity:
            raise ByzantineError("Note do not match certificate.")

        if not note.verify(self.getCertificate().get_pubkey()):
            raise ByzantineError("Note not signed correctly.")
        
        if self._note:
            if self.getEpoch() >= note.epoch:
                raise ByzantineError("Epoch must be larger.")

        if self._note:
            self.group.notify("data.note", self._note, False)
            
        self._note = note
        self.group.notify("data.note", note, True)

        
    def setAccusation(self, accusation):
        """
        Add an accusation for this member.
        Any existing accusation with the same ring number will be invalidated and removed.
        
        @param accusation: The accusation to add.
        @type accusation: L{Accusation}
        
        @raise e: L{ByzantineError} in the following situations:
          - the accused note does not match this members current note, 
          - the accused member is not this member,
          - the accusation is made on a ring that this member has disabled.
        """ 

        if not isinstance(accusation, Accusation): raise ValueError
        nr = accusation.nr
        
        if accusation.epoch != self.getEpoch(): raise ByzantineError, "Note in accusation does not match current note."
        if accusation.accused != self.getIdentity(): raise ByzantineError, "Accusation is not for this member."
        if not self._note.mask[nr]: raise ByzantineError, "Ring not enabled in mask."
        
        if self.vAccusations.has_key(nr):
            a = self.vAccusations.pop(nr)
            self.group.notify("data.accusation", a, False)

        self.hAccusations[nr] = fireflies.time.time()
        self.vAccusations[nr] = accusation
        self.group.notify("data.accusation", accusation, True)

    def invalidateAccusation(self, accusation):
        """Invalidate an accusation.
        
        @param accusation: The accusation to make invalid.
        @type accusation: L{fireflies.state.Accusation}
        @raises e: L{ValueError} if accusation was not valid. 
        """
        
        if not isinstance(accusation, Accusation): raise ValueError
        rnr = accusation.nr
        if not self.vAccusations[rnr] == accusation:
            raise ValueError, "Given accusation not valid."
        self.vAccusations.pop(rnr)
        self.group.notify("data.accusation", accusation, False)

    def invalidateAccusationOnRing(self, rnr):
        """Invalidate accusation on an given ring.
        
        @param rnr: Ring number
        @type rnr: int
        @raises e: L{KeyError} is there is no accusation on rnr.
        """
        self.invalidateAccusation(self.vAccusations[rnr])
        
    def hasAccusations(self):
        """
        Check for valid accusations.
        
        @return: True if the member has one or more accusations.
        @rtype: bool
        """
    
        return bool(self.vAccusations)


        
    def clearAccusations(self):
        """
        Remove all accusations for this member.
        """
        
        for rnr, a in self.vAccusations.items():
            self.group.notify("data.accusation", a, False)
        self.vAccusations = {}

    def __repr__(self):
        #return "%x" % bytes_to_long(self.identity)
        return  "P:%s:%d:%s" % (shortIdentity(self), self.getEpoch(), self.getCommonName())

    def __cmp__(self, other):
        try:
            return cmp(self.getIdentity(), other.getIdentity())
        except AttributeError:
            return False
#  LocalWords:  param
