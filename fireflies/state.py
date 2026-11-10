######################################################################
## Filename:      state.py
## Description:   Fireflies member state classes.
## Author:        Håvard Dagenborg <havard.dagenborg@outlook.com>
## Modified at:   Tue Jan 24 10:39:41 2006
## Modified by:   Håvard Dagenborg <havard.dagenborg@outlook.com>
## Licence:       MIT (see the LICENCE file).
##  
##         Copyright© 2007, Håvard Dagenborg
##                
## $Id: state.py,v 1.26 2014/06/16 07:49:47 haavardj Exp $
##                
######################################################################

"""This module provides classes that are used to represent the state of members in a group."""

import functools
import random

import twisted.internet.address

import fireflies
import fireflies.util
from fireflies import crypto
from fireflies.crypto import shortIdentity


def isValidMask(mask, nrMonitoringRings):
    """
    Check the validity of a mask. A mask is valid if it is of lenght t.
    
    @param mask: The mask that is to be checked.
    @type mask: List of bools.
    @param t: Byzantine tolerance factor.
    @type t: int
    @return: True if mask is valid, otherwise False.
    @rtype: bool    
    """
    t = fireflies.util.minmajority(nrMonitoringRings)
    if len(mask) != 2* t + 1: return False
    if len([x for x in mask if x == True]) != t + 1: return False 
    return True
    

def createInitialNote(member):
    """Create a note with the specified identity, initial epoch of 1,
    and an empty mask.
    
    @param member: Member object
    @return: A new note
    @rtype: L{Note}
    """

    isinstance(member, Member)
    t = fireflies.util.minmajority(member.group.nrMonitoringRings())
    mask = [False] * t + [True] * (t+1)
    random.shuffle(mask)
    return Note(member.identity, 1, mask)	


class TimeStampMixin:
    
    timestamp = 0 
    
    def touch(self):
        self.timestamp = fireflies.time.time()
             

@functools.total_ordering
class Accusation(crypto.Signable, TimeStampMixin):
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

    printShortIDs = True

    def __init__(self, accused, ll, accuser):
        self.accused = accused
        self.epoch = ll
        self.accuser = accuser 
        
        self.touch()

    def __getstate__(self):
        return {"accused": self.accused,
                "epoch": self.epoch,
                "accuser": self.accuser,
                "signature": self.signature
                }

    def __setstate__(self, data):
        for k,v in list(data.items()):
            setattr(self, k, v)
            
        self.touch()
        
    # Accusations compare by fingerprint. Comparing with anything else
    # gives "less than", as __cmp__ returning -1 did in Python 2.
    def __eq__(self, other):
        try: return self.get_fingerprint() == other.get_fingerprint()
        except AttributeError: return False

    def __lt__(self, other):
        try: return self.get_fingerprint() < other.get_fingerprint()
        except AttributeError: return True

    def __hash__(self):
        return hash(self.get_fingerprint())

    def __str__(self):        
        if self.printShortIDs:
            return "A:%s-%d,%s" % (self.accused[-4:-1], self.epoch, self.accuser[-4:-1])
        else:
            return "%s" % (self.uidstr())
        
    def uidstr(self):
        return "A:%s-%d,%s" % (self.accused, self.epoch, self.accuser)

        

class Note(crypto.Signable, TimeStampMixin):
    """Members issue notes to signal to other members that they are alive. In
    particular, a member will issue a new note as a rebuttal to a false
    accusation. Notes should be considered immutable after they are signed.

    @ivar identity: The member's identity.
    @type identity: str
    @ivar epoch: A monotonically increasing number.  
    @type epoch: int
    @ivar mask: Bitmap of enabled rings. 
    @type mask: bitmap
    @ivar signature: Signed with the member's private key.
    @type signature: str
    """

    def __init__(self, identity, epoch, mask):        
        self.identity = identity
        self.epoch = epoch
        self.mask = mask
        self.badness = 0
        
        self.touch()

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
        for k,v in list(data.items()):
            setattr(self, k, v)

        self.touch()
        
    # Python 2's __cmp__ here called a non-existent shash() method and
    # always returned -1, so notes were only equal to themselves. The
    # default identity-based __eq__ keeps that behaviour.

    def uidstr(self):
        return "N:%s-%d-%s" % (self.identity, self.epoch, str(self.mask))

    

@functools.total_ordering
class Member(object):
    """Encapsulates known state of a group member.

    @ivar group: The group in which this member is a member of.
    @type group: L{fireflies.group.Group}
    """
    
    maxAccusationHistory = 100

    group = None

    def __init__(self, cert, group):

        if not isinstance(cert, crypto.Certificate): raise TypeError(cert)

        self._cert = cert
        self._note = None
        self.group = group
        self.identity = crypto.identityFromCertificate(self._cert)
                
        self.view = group.view       
  
        # Valid accusations. 
        self.vAccusations = set()

        # History of accusations
        self.hAccusations = []

        # Ping counts and loss estimates live in the failure detector
        # (fd.ExpSmoothedTimeoutPolicy).

        self._failed = True

    @property
    def logger(self):
        return self.group.logger
    
    @property
    def stats(self):
        return self.group.stats

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
        
        if not self._note: return False
        return bool(self._note.mask[ring.name])
        
    def nextNote(self):
        """Compute a new note for the member based on any previous note and previous accusations. 
        The new note has a larger epoch number the the current note.
           
        @note: The returned note is not signed.
        @return: A new note object.
        @rtype: L{Note}
        """
        
        n = Note(self.identity, self.getEpoch() + 1, self.nextMask())
        n.badness = self.group.badness
        self.group.stats.notesCreated += 1
        return n
    
    def nextMask(self):
        """
        Compute a new mask based on the accusatio history of this node.
         
        @return: A new mask.
        @rtype: list of booleans.
        """
     
        # We need to disable t rings. If the member has not been
        # accused on at least t rings, we pick disabled rings from the
        # old mask. If the note has not been set for this member, we
        # build a random mask.
        
        # p1 is a list of the ring numbers we are to disable. p1 is
        # sorted according to which rings are to be disabled first.
        
        p1 = [(x.timestamp, x) for x in self.hAccusations]
        p1.sort()
        p1.reverse()
        p1 = [x[1] for x in p1]
        t = (self.group.nrMonitoringRings() -1) // 2
        assert self.getNote()
        assert isValidMask(self.getNote().mask, self.group.nrMonitoringRings())
             
        mask = [True] * (2*t + 1)
        disabledRings = 0
        
        # Pick rings to disable from accusation history.
        while p1:            
            if disabledRings >= t: break
            
            accuser = self.group.getMemberByIdentity(p1.pop(0).accuser)
            
            for ring in self.group.view.mRings:
                if fireflies.view.validPredecessor(accuser, self, ring) and mask[ring.name]:                    
                    mask[ring.name] = False
                    disabledRings += 1
                    if disabledRings >= t: break
                    
        
        # Pick remaining rings from old mask.
        for rnr, enabled in enumerate(self._note.mask):
            if disabledRings >= t: break
            if enabled: continue
            if mask[rnr]:
                mask[rnr] = False
                disabledRings += 1
               
        assert isValidMask(mask, self.group.nrMonitoringRings()), "t=%d disabledRings=%d %d" %(t, disabledRings, len([x for x in mask if x==False]))
        return mask            
    
    def accusers(self):
        return [self.group.getMemberByIdentity(x) for x in self.getAccusations()]

    def getCertificate(self):
        """
        @return: The member's latest member certificate.
        @rtype: L{fireflies.crypto.Certificate}
        """

        return self._cert
    
    def getAccusations(self):
        """
        
        @return: All current valid accusations.        
        @rtype: List of L{Accusation}
        """
        
        return self.vAccusations
    
    def getAccusationBy(self, member):
        """
        Get accusation for a specific member.
        
        @param member: member identity to get accusations for
        @type member: L{Member} or member identity string 
        @return: Accusation
        @rtype: L{Accusation}
        @raises e: KeyError if member has not made any accusations.
        """

        if isinstance(member, Member):
            identity = member.identity
        else:
            identity = member

        for a in self.vAccusations:
            assert isinstance(a, Accusation)
            assert a.accused == self.identity
            if a.accuser == identity:                
                return a
        raise KeyError("No such accuser %s" % member)
        
    def getPublicKey(self):
        return self._cert.get_pubkey()

    def isFailed(self):
        """
        @return: True if member is considered failed, otherwise False.
        @rtype: bool
        """
        
        # A member without a note is failed.        
        return self._failed
 
    def isLive(self):
        """
        @return: True if the member is considered live, otherwise False.
        @rtype: bool
        """
        return not self._failed


    def isAccused(self):
        """
        @return: True if the member is accused of having failed, otherwise False.
        @rtype: bool
        """

        return bool(self.vAccusations)

    def isAccusedBy(self, member):
        """Returns true if member is accused by member.
        
        @param member: member identity to get accusations for
        @type member: L{Member} or member identity string         
        
        @return: True if the member is accused on the given ring, otherwise False.
        @rtype: bool
        """
        if isinstance(member, Member):
            identity = member.identity
        else:
            identity = member

        for a in self.vAccusations:
            assert isinstance(a, Accusation)
            assert a.accused == self.identity, "%s - %s" %(a.accused, self.identity)
            if a.accuser == identity: return True
        return False


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
        
        if self.identity != note.identity:
            raise fireflies.ByzantineError("Note do not match certificate.")

        if not note.verify(self.getCertificate().get_pubkey()):
            raise fireflies.ByzantineError("Note not signed correctly.")
        
        if self._note:
            if self.getEpoch() >= note.epoch:
                raise fireflies.ByzantineError("Epoch must be larger.")

        if self._note:
            self.group.notify("data.note", self._note, False)
            
        self._note = note
        self.group.notify("data.note", note, True)
        
    def setAccusation(self, accusation):
        """
        Add an accusation for this member.
        
        @param accusation: The accusation to add.
        @type accusation: L{Accusation}
        
        @raise e: L{ByzantineError} in the following situations:
          - the accused note does not match this members current note, 
          - the accused member is not this member,
          - the accusation is made on a ring that this member has disabled.
        """ 

        if not isinstance(accusation, Accusation): raise TypeError("Parameter %s not an accusation." % accusation)
        
        if accusation.epoch != self.getEpoch(): raise fireflies.ByzantineError("Note in accusation does not match current note.")
        if accusation.accused != self.identity: raise fireflies.ByzantineError("Accusation is not for this member.")
        
        if self.isAccusedBy(accusation.accuser):
            assert accusation in self.vAccusations
            raise KeyError("Duplicate accusation %s")
        
        assert accusation not in self.vAccusations
        
        self.vAccusations.add(accusation)
        self.hAccusations.append(accusation)
        if len(self.hAccusations) > self.maxAccusationHistory:
            self.hAccusations.pop(0)
        
        self.group.notify("data.accusation", accusation, True)
    
    def invalidateAccusation(self, accusation):
        """Invalidate an accusation.
        
        @param accusation: The accusation to make invalid.
        @type accusation: L{fireflies.state.Accusation}
        @raises e: L{ValueError} if accusation was not valid. 
        """
        
        if not isinstance(accusation, Accusation): raise TypeError("Parameter %s not an accusation." % accusation)

        self.vAccusations.remove(accusation)
        self.group.notify("data.accusation", accusation, False)

    def invalidateAccusationBy(self, member):
        """Invalidate accusation on an given ring.
        
        @param rnr: Ring number
        @type rnr: int
        @raises e: L{ValueError} is there is accusations by member.
        """
                
        a = self.getAccusationBy(member)
        if a == None:
            raise ValueError("No accusations for %s by %s" % (self, member))
        
        self.invalidateAccusation(a)
        
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
        vAccusations = self.vAccusations
        self.vAccusations = set()
        
        for a in vAccusations:
            self.group.notify("data.accusation", a, False)

    def __repr__(self):
        return  "P:%s:%s-%d" % (shortIdentity(self.identity), self.getCommonName(), self.getEpoch())

    # Members compare and hash by identity. View.sn2peer holds one Member
    # object per identity, so this matches the id()-based hash Python 2 used.
    def __eq__(self, other):
        if not isinstance(other, Member): return NotImplemented
        return self.identity == other.identity

    def __lt__(self, other):
        if not isinstance(other, Member): return NotImplemented
        return self.identity < other.identity

    def __hash__(self):
        return hash(self.identity)
#  LocalWords:  param
