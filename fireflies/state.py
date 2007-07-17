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
## $Id: state.py,v 1.1 2007/07/17 13:42:52 haavardj Exp $
##                
######################################################################

"""This module provides classes that captures the state of a group."""


from Crypto.Util.number import long_to_bytes, bytes_to_long
from twisted.internet import reactor
from fireflies.stats import Stats
from fireflies import crypto
import bisect, logging, setrecon, random, stats



INITIAL_LRATE = 0.10

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

def createInitialNote(identity, t):
    """
    Create a note with the specified identity, initial epoch of 1,
    and a 2t+1 length mask with t disabled rings.
    
    @param identity: Member's identity
    @type identity: str
    @param t: Byzantine tolerance factor.
    @type t: int
    @return: A new note
    @rtype: L{Note}
    """

    rings = 2*t + 1
    mask = [False] * t + ([True] * (rings - t))
    random.shuffle(mask)
    return Note(identity, 1, mask)



class Accusation(object, crypto.RSASignable):
    """
    Accusations are used by Fireflies to signal failure suspicions. 
    Whenever a member suspects that one of its monitored members has failed, 
    it will issue an accusation for that member. 
    This accusation it then distributed to all other members and, if not rebutted, 
    will cause the accused member to be considered failed. 
    
    @ivar accused: The identity of the accused member.
    @type accused: str
    @ivar accuser: The identity of the member who issued the accusation.
    @type accused: str
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

        

class Note(object, crypto.RSASignable):
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
        self.signature = 0
        self.badness = 0

    def __repr__(self):        
        return "N:%x-%d" % (bytes_to_long(self.identity), self.epoch)

    def __hash__(self):
        return hash(self.shash())

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
        return "Note:%d-%d-%s" % (bytes_to_long(self.identity), self.epoch,
                                     str(self.mask))


class MemberCertificate(object, crypto.RSASignable, crypto.RSAVerifyingKey):
    """Each member is represented in a group by a MemberCertificate.
    A MemberCertificate binds a member's public key to a Internet
    network address. To be valid, a MemberCertificate must be signed
    with the group CA's private key.
    
    @ivar key: The member's public RSA key.
    @ivar address: Network address (IP:port)
    @type address: string
    @ivar identity: A member's identity is the secure hash of its public key.
    @type identity: string
    @ivar signature: Signed by the corresponding private key.
    @type signature: string
    """
    
    def __init__(self, key, address, signature=0):
        """
        @param key: The member's public key.
        @param address: The member's network address (IP:port)
        @type address: string
        @param signature: Group CA's signature.
        @type signature: string
        """
        self.key = key
        self.address = address
        self.signature = signature
        self.identity = crypto.keyToIdentity(self.key)

    def __str__(self):
        return "MemberCertificate:%s" % (self.address)
        
    def __cmp__(self, other):
        try:
            return cmp(self.shash(), other.shash())
        except AttributeError:
            return -1

    def uidstr(self):
        return "MemberCertificate:%s-%s" % (self.address,
                                            self.identity)
    
    def __getstate__(self):
        return {"key": self.key,
                "address": self.address,
                "signature": self.signature
                }
    
    def __setstate__(self, data):
        for k,v in data.items():
            setattr(self, k, v)
        self.identity = crypto.keyToIdentity(self.key)

class GroupCertificate(object, crypto.RSASignable, crypto.RSAVerifyingKey):
    """A Fireflies group certificate.  The group certificate can be
    used to verify received MemberCertificate objects.  It also holds
    the textual group name and certain configuration options that
    members should abide to.

    @ivar name: The group's textual name.
    @type name: string
    @ivar key: The group's public key.
    @ivar config: Default configuration options set by the group's CA.
    @type config: dict    
    """
    
    def __init__(self, key, name, config, signature=0):        
        self.name, self.key, self.config, self.signature = name, key, config, signature
        self.identity = crypto.keyToIdentity(self.key)

    def uidstr(self):        
        return "GroupCertificate-%s-%s%s" %(str(self.identity),
                                         str(self.name),
                                         str(crypto.sHashDict(self.config)))
                                         
    def __cmp__(self, other):
        try:
            return cmp(self.identity, other.identity)
        except AttributeError:
            return -1

    def __str__(self):
        return "GroupCertificate:%s" % (self.name)


class MemberKey(object, crypto.RSASigningKey, crypto.RSAVerifyingKey):
    """The private key of a Fireflies members."""

    def __init__(self, address, size=1024):
        self.size = size
        self.address = address
        self.key = crypto.generateKey(size)
        self.identity = crypto.keyToIdentity(self.key)

    def __str__(self):
        return "MemberKey:%s@%s" % (self.address, self.identity)
        
    def __cmp__(self, other):
        try:
            return cmp(self.identity, other.identity)
        except AttributeError:
            return -1

    def getCertificate(self):
        c = MemberCertificate(self.key.publickey(), self.address)
        return c


class CAKey(object, crypto.RSASigningKey, crypto.RSAVerifyingKey):
    """Private key of a certificate authority (CA)."""
    
    def __init__(self, name, config, size=1024):
        self.name, self.config = name, config
        self.key = crypto.generateKey(size)
        self.identity = crypto.keyToIdentity(self.key)

    def __str__(self):
        return "CAKey:%s@%s" % (self.name, self.identity)
        
    def __cmp__(self, other):
        try:
            return cmp(self.identity, other.identity)
        except AttributeError:
            return -1

    def getCertificate(self):
        """
        @return: A group certificate that embeds the corresponding public key.
        @rtype: GroupCertificate
        """
        c = GroupCertificate(self.key.publickey(), self.name, self.config)
        self.sign(c)
        return c




class Member(object):
    """Encapsulates known state of a group member.

    @ivar group: The group in which this member is a member of.
    @type group: L{fireflies.group.BaseGroup}
    """

    def __init__(self, cert, group, initLRate=INITIAL_LRATE):

        if 0: isinstance(group, fireflies.group.Group)
        if 0: isinstance(cert, fireflies.crypto.MemberCertificate)
        
        self._cert = cert
        self._note = None
        
        self.group = group
        self.view = group.view       
        self.logger = logging.getLogger(cert.address)
        
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
        pSucc = (1 - initLRate)**2 
        self.avgLoss = ((1-pSucc)/pSucc) + 1

        #self.lastPong = 0
        #self.firstAccused = 0
        #self._lastPinged = -1

        # Used by the web status displayer        
        self.allAccusations = []

        self.stats = Stats()
        self._failed = True


    def setFailed(self, status):
        """
        Update the failed/liveness status of the member.
        
        @param failed: The new status of the member.
        @type failed: bool
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
        return self._cert.address
        
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
    
    def nextNote(self):
        """Compute a new note for the member based on any previous note and previous accusations. 
        The new note has a larger epoch number the the current note.
           
        @note: The returned note is not signed.
        @return: A new note object.
        @rtype: L{Note}
        """
        
        return Note(self.getSerial(), self.getEpoch() + 1, self.nextMask())       
    
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
        @rtype: L{fireflies.crypto.MemberCertificate}
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
        self.vAccusations[rnr]
    
    def getIdentity(self):
        """
        @return: The member's identity.
        @rtype: string
        """
        return self._cert.identity

    def getSerial(self):
        """@deprecated: Use getIdentity instead."""
        
        self.logger.warning("DEPRECATED: getSerial")
        return self.getIdentity()

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

        if not self._cert.verify(note):
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

        if not isinstance(accusation, Accusation): raise ValueError, accusation
        nr = accusation.nr
        
        if accusation.epoch != self.getEpoch(): raise ByzantineError, "Note in accusation does not match current note."
        if accusation.accused != self.getIdentity(): raise ByzantineError, "Accusation is not for this member."
        if not self._note.mask[nr]: raise ByzantineError, "Ring not enabled in mask."
        
        if self.vAccusations.has_key(nr):
            a = self.vAccusations.pop(nr)
            self.group.notify("data.accusation", a, False)
            #self.view.aSet.remove(a)

        self.hAccusations[nr] = fireflies.time.time()
        self.vAccusations[nr] = accusation
        #self.view.aSet.append(accusation)
        self.group.notify("data.accusation", accusation, True)

    def invalidateAccusation(self, accusation):
        """Invalidate an accusation.
        
        @param accusation: The accusation to make invalid.
        @type accusation: L{fireflies.members.Accusation}
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

    def hasAccusationOn(self, rnr):
        """
        Check for valid accusations on a given ring.
        
        @param rnr: Ring number
        @type rnr: int
        @return:True if there is is an accusations on the given ring. """
        
        return self.vAccusations.has_key(rnr)
        
    def clearAccusations(self):
        """
        Remove all accusations for this member.
        """
        
        for rnr, a in self.vAccusations.items():
            self.group.notify("data.accusation", a, False)
        self.vAccusations = {}

    def __repr__(self):
        #return "%x" % bytes_to_long(self.identity)
        return  "P:%s,%d" % (self.getAddress(), len(filter(None, self.vAccusations)))

    def __cmp__(self, other):
        try:
            return cmp(self.identity, other.identity)
        except AttributeError, why:
            return -1

#  LocalWords:  param
