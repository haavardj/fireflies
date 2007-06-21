# -*- coding: iso-8859-1 -*-
######################################################################
## Filename:      group.py
## Description:   Fireflies group abstraction. 
## Author:        Håvard Dagenborg Johansen <haavardj@cs.uit.no>
## Modified at:   Tue Jan 24 13:51:45 2006
## Modified by:   Håvard Dagenborg Johansen <haavardj@cs.uit.no>
## Licence:       GPL (see the LICENSE file).
##  
##         Copyright© 2006, University of Tromsø (Norway)
##                
######################################################################


import fireflies,  fireflies.members, fireflies.crypto, fireflies.stats
import logging
from twisted.internet import reactor, defer
from zope.interface import Interface, implements


def _filterDupMonitors(l):
    """Return a list monitores of the same length as l but any duplicate and
    disabled monitores set to None."""
    r = []
    for x, n in enumerate(l):
        if (not n) or (n in r) or (n._note.mask[x] == False): r.append(None)
        else: r.append(n)
    return r

EV_RECOVER_NEW = 0
EV_RECOVER_REBUTTAL = 1
EV_RECOVER_INVALIDATED = 2
EV_CRASH_REVOKED = 0
EV_CRASH_ACCUSED = 1
EV_CRASH_NEW = 2

class IMembershipEvent(Interface):   
    def evRecover(self, member, reason):
        """member has recovered from a crash.
        
        Reason:  0 first time a member is considered live
                 1 recovered by rebuttal
                 2 recovered by invalidation of accustations through structural changes
        """
        
    def evCrash(self, member, reason):
        """member has crashed or left the group. 
        
        Reason:  0 revoked certificate
                 1 not revoked an accusation (aka crash)
                 2 new member (have member certificate but no a note)
        """

EV_DATA_VALID = True
EV_DATA_INVALID = False
class IDataEvent(Interface):
    def evAccusation(self, itm, valid): pass
    def evNote(self, itm, valid): pass
    def evCertificate(self, itm, valid): pass

EV_NEIGHBOUR_INBOUND = 1**2
EV_NEIGHBOUR_OUTBOUND = 2**2
class INeighborEvent(Interface):
    def evConnect(self, member, role): pass
    def evDisconnect(self, member, role): pass

def createGroup(name, config=fireflies.defaultConfig):
    caPrivate = fireflies.crypto.CAKey(name, config, config["RSA_SIZE"])
    caPublic = caPrivate.getCertificate()
    
class Group:
    """A Fireflies group."""
    badness = 0
    timeout = 10.0
    
    logger = logging.getLogger()
    _membersClass = fireflies.members.Member
                
    def __init__(self, groupCertificate, credentials): 
        """Create a group from a CACertificate."""
        
        if not isinstance(groupCertificate, fireflies.crypto.CACertificate): raise ValueError
        if not isinstance(credentials, fireflies.crypto.MemberKey): raise ValueError
   
        self._neighborsEvL = []
        self._membershipEVL = [] 
        self._dataEVL = []
        
        self._timers = {}
        self._groupCA = groupCertificate
        self.sn2member = {} # serial to member mapping.

        # Rings
        self.aRing = fireflies.members.SerialRing() # Live members
        self.fRing = fireflies.members.SerialRing() # Failed members
        self.T = t = max(2* groupCertificate.config['T'] + 1, groupCertificate.config['k'])
        self.rings = fireflies.members.MemberRings(t)
        
        self.stats = fireflies.stats.Stats()     
        self.credentials = credentials

    def ensureNumRings(self, num):
        if self.getNumRings() < num:
            self.setNumRings(num)

    def setNumRings(self, num):
        self.rings.setLength(num)        
        
    def getNumRings(self):
        return len(self.rings)
        
    def _makeLive(self, m):
        isinstance(m, fireflies.members.Member)
        self.fRing.remove(m)
        self.aRing.insert(m)
        m._setFailed(False)
        
     
    def __len__(self):
        """Size of the membership (both failed and live members).""" 
        
        return len(self.sn2member)
    
    def register(self, service, neighborEv=0,  membershipEv=False, dataEv=False):
        if dataEv: 
            self._dataEVL.append(service)
        if membershipEv: 
            self._membershipEVL.append(service)            
        if neighborEv > 0: 
            self._neighborsEvL.append( (neighborEv, service) )

    def _createMemberInstance(self, mCert):
        return self._membersClass(mCert)
                
    def liveMembers(self):
        """Return a Ring object containing all live members."""
        return self.aRing

    def failedMembers(self):
        """Return a Ring object containing all failed members."""       
        return self.fRing

    def __contains__(self, serial):     
        return serial in self.sn2member

    def getMemberByAddress(self, address):
        raise NotImplementedError
    
    def getMemberBySerial(self, serial):
        """Return IMember object.
        Raises KeyError if group has no member with the provided serial."""
        return self.sn2member[serial]
    
    def getMemberByCertificate(self, memberCertificate):
        return self.getMemberBySerial(memberCertificate.serial)

    def getGroupID(self):
        """Returns the unique identifier of the group."""        
        return self._groupCA.serial
    
    def getGroupCertificate(self):
        """Return the group's certificate."""
        return self._groupCA
    
    def getCredentials(self):
        """Return credentials to this group."""
        return self.credentials
    
    def getGroupName(self):
        """Returns the group name."""
        return self._groupCA.name
                
    def _failback(self, reason):
        self.logger.exception(reason)

    def _startRebuttalTimer(self, member):
        if member in self._timers: raise ValueError("Timer already started.")
        self._timers[member] = reactor.callLater(self.timeout, self._toRebuttalTimer, member)
        
    def _toRebuttalTimer(self, member):
        assert isinstance(member, fireflies.members.Member)
        self.logger.info("%s failed", member)
        member.setFailed(True)
        self._timers.pop(member)
        self.aRing.remove(members)
        self.fRing.insert(member)
        
    def _stopRebuttalTimer(self, member):
        t = self._timers.pop(member)
        t.cancel()


    #
    # Methods to change the membership.
    #
    def suspect(self, member): pass    
    
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
        
        d = defer.succeed()
        d.pause()
        reactor.callLater(0, d.unpause)

        # Check that we know about accused. This should not really
        # happen if we gossip notes before accusations and
        # certificates before notes.
        if not accusedID in self.sn2member:
            self.stats.accusationsInvalid += 1
            self.logger.warning("discard %s Unknown accused", accusation)
            raise ValueError

        accused = self.sn2member[accusedID]
        assert isinstance(accused, fireflies.member.Member)            
        # Ditto for the accuser
        if not accuserID in self.sn2member:
            #self.stats.accusationsInvalid += 1
            self.logger.warning("discard %s Unknown accuser", accusation)
            raise ValueError
        
        accuser = self.sn2member[accuserID]
        assert isinstance(accuser, fireflies.members.Member)  
        
        if not self.getGroupCertificate().verify(accusation):
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
            return defer.succeed()
        
        if accusation.epoch > accused.getNote().epoch:
            #self.stats.accusationsInvalid += 1
            self.logger.warning("discard %s accusing newer note.", saccusation)
            raise defer.succeed()

        # Check that the accuser is not specifying an invalid ring.
        # No correct member should do this.
        if accusation.nr >= self.T:
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
        ring = self.rings[rnr]
        isinstance(ring, fireflies.members.MonitoringRings)

        # If member currently is accused on ring, keep the new one only if it
        # is from a closer predecessor.
        if accused.hasAccusationOn(rnr):
            assert accused.isAccused()
            currentAccusation = accused.getAccusation(rnr)
            currentAccuser = self.getMemberBySerial(currentAccusation.accuser)
            assert isinstance(currentAccusation, Accusation)
            assert isinstance(currentAccuser, fireflies.member.Member)
            
            if ring.isBetween(currentAccuser, accuser, accused):
                accused._setAccusation(accusation)
                self.logger.info("%s accused by %s on ring %d (replacing %s)", accused, accuser, accusation.nr, currentAccuser)
                d.addCallback(lambda x: self._trigger_accusation(accusation, True))
                d.addCallback(lambda x: self._trigger_accusation(currentAccusation, False))
            
        elif accuser == ring.pred(accused, func=lambda x: (not x.isAccused()) or (x == accuser)):
            accused._setAccusation(accusation)
            if not accused.isFailed():
                self.logger.info("%s accused by %s on ring %d (timer started)", accused, accuser, accusation.nr)
                self._startRebuttalTimer(accused)
            d.addCallback(lambda x: self._trigger_accusation(accusation, True))
        return d
        
    def addCertificate(self, elm):
        """Adds cert to the view.
        
        Return a deferred that triggers when all callbacks have run. The callback will contain the added member object.
        
        Exceptions:
             -TypeError: elm is not a MemberCertificate object.
             -ValueError: The certificate already exists.

        Events:
            - cb_add_certificate"""
        
        if not isinstance(elm, fireflies.crypto.MemberCertificate): raise TypeError
        self.stats.certsTotal += 1
            
        # MOVEME
        if not self.getGroupCertificate().verify(elm): 
            #self.stats.certsInvalid += 1
            #self.logger.warning("discard %s invalid CA signature.", c)
            raise ValueError("Certificate not correctly signed %s." % str(elm))
        try:
            m = self.getMemberBySerial(elm.serial)
        except KeyError:
            m = None
            
        if m:
            m.stats.certsRedundant += 1
            self.logger.debug("discard %s redundant", c)
            return defer.succeed(m)
            #raise NotImplementedError
                
        m = self._createMemberInstance(elm)
        m.group = self
        self.sn2member[m.getSerial()] = m

        # Add peer to all necessary rings.
        self.rings.insert(m)
        self.fRing.insert(m)
        d = defer.succeed(None)
        d.pause()
        reactor.callLater(0, d.unpause)
        d.addCallback(lambda x: self._trigger_certificate(elm, True))
        d.addCallback(lambda x: m)
        self.logger.info("new %s", m)
        return d

    def addNote(self, note):
        """Add a note.
        
        Return a deferred that triggers when all callbacks have completed.

        Exceptions:
           - TypeError: note is not a Note object.
           - ByzantineError: Invalid mask. Note must have disabled exactly t rings."""
        
        if not isinstance(note, fireflies.members.Note):
            raise TypeError
        
        #self.stats.notesTotal +=1 
        if not note.serial in self.sn2member:
            self.stats.notesInvalid += 1
            self.logger.warning("discard %s unknown peer", note)
            raise ValueError
        
        m = self.getMemberBySerial(note.serial)
    
        assert isinstance(m, fireflies.members.Member)
        assert m._note.serial == note.serial
        
        d = defer.succeed(None)
        d.pause()        
        reactor.callLater(0, d.unpause)
        
        if not m.getCertificate().verify(note):
            raise ValueError("Invalid Signature")
        
        if not fireflies.members.isValidMask(note.mask, self.T): 
            #self.logger.warning("discard %s invalid mask", self.pprint(note))
            raise fireflies.members.ByzantineError("Invalid mask %s from %s" % (str(note.mask), note))
        
        if m.getEpoch() > note.epoch:
            # Old note
            return d
        if m.getEpoch() == note.epoch:
            # We have the note. Return silently.
            return d
        
        d.addCallback(lambda x: self._trigger_note(note, True))
        d.addCallback(lambda x: self._trigger_note(m.getNote(), False))        

        if m.isFailed():
            if m.getEpoch() == 0: 
                assert not m.isAccused()
                m._note = note
                self._makeLive(m)
                d.addCallback(lambda x: self._trigger_evRecover(m, EV_RECOVER_NEW))
                self.logger.info("rebuttal %s first note", m)

            else:
                assert m.isAccused()
                for a in m.vAccusations.values():
                    d.addCallback(lambda x: self._trigger_accusation(a, False))
                m._note = note
                m.clearAccusations()

                self._makeLive(m)
                d.addCallback(lambda x: self._trigger_evRecover(m, EV_RECOVER_REBUTTAL))
                
                # The member goes from an accused to not accused state. As such,
                # it may invalidate other accusations. 
                # Let m_j be m's first live successor on ring r.
                # All accusations for members between m and m_j
                #   If m between accuser and accuse: invalidate accusation.  
                #   If accused now is cleared, rerun for this member.            
                check = [m,]
                while check:
                    m = check.pop()      
                    for ring in self.rings:
                        isinstance(ring, fireflies.members.MonitorRing)                    
                        for q in ring.collectSucc(m, lambda x: not x.isAccused()):
                            isinstance(q, fireflies.member.Member)
                            if not q.isAccusedOn(ring.nr): continue                        
                            qa = q.getAccusation(ring.nr)
                            assert isinstance(qa, Accusation)
                            accuser = self.getMemberBySerial(qa.accuser)
                            accused = self.getMemberBySerial(qa.accused)
                            if ring.isBetween(accuser, q, accused):
                                assert q.isAccused()
                                assert q.isAccusedOn(ring.nr)
                                q.delAccusation(ring.nr)
                                d.addCallback(lambda x: self._trigger_accusation(qa, False))
                                self.logger.debug("%s accusation invalidated", m)
                                if not q.isAccused():                                 
                                    if q.isFailed():
                                        self._makeLive(q)
                                        self.logger.info("%s live (accusations invalidated)", q)
                                        d.addCallback(lambda x: self._trigger_evRecover(q, EV_RECOVER_INVALIDATED))
                                    else:
                                        self._stopRebuttalTimer(q)
                                        self.logger.debug("%s rebuts (accusation invalidated)", m)
                                    check.append(q)
                            
        return d

    #
    # IGroupEvents
    #    
    
    def _trigger_evRecover(self, member, reason):
        l = map(lambda x: defer.maybeDeferred(x.evRecover, member, reason), self._membershipEVL)
        return defer.DeferredList(l, 0, 1, 0)

    def _trigger_evCrash(self, member, reason):
        l = map(lambda x: defer.maybeDeferred(x.evCrash, member, reason), self._membershipEVL)
        return defer.DeferredList(l, 0, 1, 0)
    
    #def _trigger_member_joined(self, member):
        #l = map(lambda x: defer.maybeDeferred(x._evJoin, member, ), self._membershipEVL)
        #return defer.DeferredList(l, 0, 1, 0)

    #def _trigger_member_lives(self, member):
        #l = map(lambda x: defer.maybeDeferred(x._cb_member_lives, member), self._membershipEVL)
        #return defer.DeferredList(l, 0, 1, 0)

    #def _trigger_member_rebuts(self, member):
        #l = map(lambda x: defer.maybeDeferred(x._cb_member_rebuts, member), self._membershipEVL)
        #return defer.DeferredList(l, 0, 1, 0)    
    
    #def _trigger_member_leaves(self, member):
        #l = map(lambda x: defer.maybeDeferred(x._cb_member_leaves, member), self._membershipEVL)
        #return defer.DeferredList(l, 0, 1, 0)

    #def _trigger_member_accused(self, member):
        #l = map(lambda x: defer.maybeDeferred(x._cb_member_accused, member), self._membershipEVL)
        #return defer.DeferredList(l, 0, 1, 0)

    #def _trigger_member_failes(self, member):
        #l = map(lambda x: defer.maybeDeferred(x._cb_member_failes, member), self._membershipEVL)
        #return defer.DeferredList(l, 0, 1, 0)
    

    #
    # IDataEvents
    #     
    def _trigger_accusation(self, elm, valid):
        l = map(lambda x: defer.maybeDeferred(x.evAccusation, elm, valid), self._dataEVL)
        return defer.DeferredList(l, 0, 1, 0)

    def _trigger_note(self, elm, valid):
        l = map(lambda x: defer.maybeDeferred(x.evNote, elm, valid), self._dataEVL)
        return defer.DeferredList(l, 0, 1, 0)
    
    def _trigger_certificate(self, elm, valid):
        l = map(lambda x: defer.maybeDeferred(x.evCertificate, elm, valid), self._dataEVL)
        return defer.DeferredList(l, 0, 1, 0)
    
    #def _trigger_add_accusation(self, elm):
        #l = map(lambda x: defer.maybeDeferred(x.evAccusation, elm, True), self._dataEVL)
        #return defer.DeferredList(l, 0, 1, 0)

    #def _trigger_del_accusation(self, elm):
        #l = map(lambda x: defer.maybeDeferred(x.evAccusation, elm, False), self._dataEVL)
        #return defer.DeferredList(l, 0, 1, 0)
    
    #def _trigger_add_note(self, elm):
        #l = map(lambda x: defer.maybeDeferred(x.evNote, elm, True), self._dataEVL)
        #return defer.DeferredList(l, 0, 1, 0)

    #def _trigger_del_note(self, elm):
        #l = map(lambda x: defer.maybeDeferred(x.evNote, elm, False), self._dataEVL)
        #return defer.DeferredList(l, 0, 1, 0)

    #def _trigger_add_certificate(self, elm):
        #l = map(lambda x: defer.maybeDeferred(x.evCertificate, elm, True), self._dataEVL)
        #return defer.DeferredList(l, 0, 1, 0)

    #def _trigger_del_certificate(self, elm):
        #l = map(lambda x: defer.maybeDeferred(x.evCertificate, elm, False), self._dataEVL)
        #return defer.DeferredList(l, 0, 1, 0)  