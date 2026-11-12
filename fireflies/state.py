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

import logging
from typing import TYPE_CHECKING, Any, Sequence

import twisted.internet.address

import fireflies
import fireflies.util
from fireflies import crypto
from fireflies.crypto import shortIdentity

if TYPE_CHECKING:
    from fireflies.group import Group
    from fireflies.ring import NamedRing
    from fireflies.stats import Stats


def isValidMask(mask: Sequence[bool], nrMonitoringRings: int) -> bool:
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
    

def createInitialNote(member: "Member") -> "Note":
    """Create a note with the specified identity, initial epoch of 1,
    and an empty mask.
    
    @param member: Member object
    @return: A new note
    @rtype: L{Note}
    """

    t = fireflies.util.minmajority(member.group.nrMonitoringRings())
    mask = [False] * t + [True] * (t+1)
    random.shuffle(mask)
    return Note(member.identity, 1, mask)	


class TimeStampMixin:
    
    timestamp: float = 0

    def touch(self) -> None:
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

    def __init__(self, accused: str, ll: int, accuser: str) -> None:
        self.accused = accused
        self.epoch = ll
        self.accuser = accuser 
        
        self.touch()

    def __getstate__(self) -> dict[str, Any]:
        return {"accused": self.accused,
                "epoch": self.epoch,
                "accuser": self.accuser,
                "signature": self.signature
                }

    def __setstate__(self, data: dict[str, Any]) -> None:
        for k,v in list(data.items()):
            setattr(self, k, v)
            
        self.touch()
        
    # Accusations compare by fingerprint. Comparing with anything else
    # gives "less than", as __cmp__ returning -1 did in Python 2.
    def __eq__(self, other: object) -> bool:
        if not isinstance(other, crypto.Signable): return False
        return self.get_fingerprint() == other.get_fingerprint()

    def __lt__(self, other: object) -> bool:
        if not isinstance(other, crypto.Signable): return True
        return self.get_fingerprint() < other.get_fingerprint()

    def __hash__(self) -> int:
        return hash(self.get_fingerprint())

    def __str__(self) -> str:
        if self.printShortIDs:
            return "A:%s-%d,%s" % (self.accused[-4:-1], self.epoch, self.accuser[-4:-1])
        else:
            return "%s" % (self.uidstr())
        
    def uidstr(self) -> str:
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

    def __init__(self, identity: str, epoch: int, mask: list[bool]) -> None:
        self.identity = identity
        self.epoch = epoch
        self.mask = mask
        self.badness: int = 0
        
        self.touch()

    def __repr__(self) -> str:
        return "N:%s-%d" % (self.identity, self.epoch)

    def __hash__(self) -> int:
        return hash(self.get_fingerprint())

    def __getstate__(self) -> dict[str, Any]:
        return {"identity": self.identity,
                "epoch": self.epoch,
                "mask": self.mask,
                "signature": self.signature,
                "badness": self.badness,
                }
    
    def __setstate__(self, data: dict[str, Any]) -> None:
        for k,v in list(data.items()):
            setattr(self, k, v)

        self.touch()
        
    # Python 2's __cmp__ here called a non-existent shash() method and
    # always returned -1, so notes were only equal to themselves. The
    # default identity-based __eq__ keeps that behaviour.

    def uidstr(self) -> str:
        return "N:%s-%d-%s" % (self.identity, self.epoch, str(self.mask))

    

@functools.total_ordering
class Member(object):
    """Encapsulates known state of a group member.

    @ivar group: The group in which this member is a member of.
    @type group: L{fireflies.group.Group}
    """
    
    maxAccusationHistory = 100

    group: "Group"

    def __init__(self, cert: crypto.Certificate, group: "Group") -> None:

        self._cert = cert
        self._note: "Note | None" = None
        self.group = group
        self.identity = crypto.identityFromCertificate(self._cert)
                
        self.view = group.view       
  
        # Valid accusations.
        self.vAccusations: set[Accusation] = set()

        # History of accusations
        self.hAccusations: list[Accusation] = []

        # Ping counts and loss estimates live in the failure detector
        # (fd.ExpSmoothedTimeoutPolicy).

        self._failed = True

    @property
    def logger(self) -> logging.Logger:
        return self.group.logger
    
    @property
    def stats(self) -> "Stats":
        return self.group.stats

#    def verify(self, obj):
#        """Verify that obj is correctly signed by this member."""
#        return self._cert.verify(obj)


    def setFailed(self, status: bool) -> None:
        """
        Update the failed/liveness status of the member.
        
        @param status: The new status of the member.
        @type status: bool
        """
        
        # A member should never be set live when there's been no note.
        status = bool(status)
        if not self._failed: assert self._note
        self._failed = status

    def getAddress(self) -> str:
        """
        @return: The member's network address and port number. 
        @rtype: IP:port string
        """
        return self._cert.address()
    
    @property
    def address(self) -> twisted.internet.address.IPv4Address:
        host, port = self._cert.address().split(":")
        return twisted.internet.address.IPv4Address("TCP", host, int(port))
    
    def getCommonName(self) -> "str | None":
        return self._cert.get_subject().CN
    
    def getPublicKey(self) -> crypto.PublicKey:
        return self._cert.get_pubkey()
        
    def getEpoch(self) -> int:
        """
        @return: The member's current epoch number.
        @rtype: int
        """
        if not self._note: return 0
        else: return self._note.epoch
    
    def getNote(self) -> "Note | None":
        """
        @return: The member's most current note or None if no note is set.
        @rtype: L{Note}
        """
        return self._note

    def isEnabledOnRing(self, ring: "NamedRing[Member]") -> bool:
        
        if not self._note: return False
        return bool(self._note.mask[ring.name])
        
    def nextNote(self) -> Note:
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
    
    def nextMask(self) -> list[bool]:
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
        
        history = sorted(((x.timestamp, x) for x in self.hAccusations), reverse=True)
        p1 = [x[1] for x in history]
        t = (self.group.nrMonitoringRings() -1) // 2
        note = self.getNote()
        assert note is not None
        assert isValidMask(note.mask, self.group.nrMonitoringRings())
             
        mask = [True] * (2*t + 1)
        disabledRings = 0
        
        # Pick rings to disable from accusation history.
        while p1:            
            if disabledRings >= t: break
            
            accuser = self.group.getMemberByIdentity(p1.pop(0).accuser)
            
            # Imported here: fireflies.view imports this module.
            from fireflies.view import validPredecessor
            for ring in self.group.view.mRings:
                if validPredecessor(accuser, self, ring) and mask[ring.name]:                    
                    mask[ring.name] = False
                    disabledRings += 1
                    if disabledRings >= t: break
                    
        
        # Pick remaining rings from old mask.
        for rnr, enabled in enumerate(note.mask):
            if disabledRings >= t: break
            if enabled: continue
            if mask[rnr]:
                mask[rnr] = False
                disabledRings += 1
               
        assert isValidMask(mask, self.group.nrMonitoringRings()), "t=%d disabledRings=%d %d" %(t, disabledRings, len([x for x in mask if x==False]))
        return mask            
    
    def accusers(self) -> "list[Member]":
        return [self.group.getMemberByIdentity(x.accuser) for x in self.getAccusations()]

    def getCertificate(self) -> crypto.Certificate:
        """
        @return: The member's latest member certificate.
        @rtype: L{fireflies.crypto.Certificate}
        """

        return self._cert
    
    def getAccusations(self) -> set[Accusation]:
        """
        
        @return: All current valid accusations.        
        @rtype: List of L{Accusation}
        """
        
        return self.vAccusations
    
    def getAccusationBy(self, member: "Member | str") -> Accusation:
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
            assert a.accused == self.identity
            if a.accuser == identity:                
                return a
        raise KeyError("No such accuser %s" % member)
        

    def isFailed(self) -> bool:
        """
        @return: True if member is considered failed, otherwise False.
        @rtype: bool
        """
        
        # A member without a note is failed.        
        return self._failed
 
    def isLive(self) -> bool:
        """
        @return: True if the member is considered live, otherwise False.
        @rtype: bool
        """
        return not self._failed


    def isAccused(self) -> bool:
        """
        @return: True if the member is accused of having failed, otherwise False.
        @rtype: bool
        """

        return bool(self.vAccusations)

    def isAccusedBy(self, member: "Member | str") -> bool:
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
            assert a.accused == self.identity, "%s - %s" %(a.accused, self.identity)
            if a.accuser == identity: return True
        return False


    def setNote(self, note: Note) -> None:
        """
        Update the note of this member.

        @param note: The new note.
        @type note: L{Note}        
        @raise L{ByzantineError}: If the given note 
          - does not belong to this member, 
          - is is older than the current one, or
          - is not correctly signed.
        """
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
        
    def setAccusation(self, accusation: Accusation) -> None:
        """
        Add an accusation for this member.
        
        @param accusation: The accusation to add.
        @type accusation: L{Accusation}
        
        @raise e: L{ByzantineError} in the following situations:
          - the accused note does not match this members current note, 
          - the accused member is not this member,
          - the accusation is made on a ring that this member has disabled.
        """ 

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
    
    def invalidateAccusation(self, accusation: Accusation) -> None:
        """Invalidate an accusation.
        
        @param accusation: The accusation to make invalid.
        @type accusation: L{fireflies.state.Accusation}
        @raises e: L{ValueError} if accusation was not valid. 
        """
        
        self.vAccusations.remove(accusation)
        self.group.notify("data.accusation", accusation, False)

    def invalidateAccusationBy(self, member: "Member | str") -> None:
        """Invalidate accusation on an given ring.
        
        @param rnr: Ring number
        @type rnr: int
        @raises e: L{KeyError} if there is no accusation by member.
        """

        a = self.getAccusationBy(member)
        self.invalidateAccusation(a)
        
    def hasAccusations(self) -> bool:
        """
        Check for valid accusations.
        
        @return: True if the member has one or more accusations.
        @rtype: bool
        """
    
        return bool(self.vAccusations)

    def clearAccusations(self) -> None:
        """
        Remove all accusations for this member.
        """
        vAccusations = self.vAccusations
        self.vAccusations = set()
        
        for a in vAccusations:
            self.group.notify("data.accusation", a, False)

    def __repr__(self) -> str:
        return  "P:%s:%s-%d" % (shortIdentity(self.identity), self.getCommonName(), self.getEpoch())

    # Members compare and hash by identity. View.sn2peer holds one Member
    # object per identity, so this matches the id()-based hash Python 2 used.
    def __eq__(self, other: object) -> bool:
        if not isinstance(other, Member): return NotImplemented
        return self.identity == other.identity

    def __lt__(self, other: object) -> bool:
        if not isinstance(other, Member): return NotImplemented
        return self.identity < other.identity

    def __hash__(self) -> int:
        return hash(self.identity)
#  LocalWords:  param
