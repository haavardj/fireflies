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
## $Id: group.py,v 1.5 2006/05/08 09:47:55 haavardj Exp $
##                
######################################################################

import fireflies
import logging
from twisted.application.service import Service, MultiService
from twisted.internet import reactor
from zope.interface import Interface, implements


class GroupPolicy:
    """Implements a failure policy on the given IGroup object in responce to
    IDataEvents callbacks."""
    
    implements(fireflies.interfaces.IDataEvents)
    
    def __init__(self, group, timeout=400):
       if 0: isinstance(group, fireflies.group.Group)
       if 0: isinstance(rings, IDataEvents)
       self.group = group
       self.__timers = {}
       self.timeout = timeout
       self.group.mRings.subscribe(self)
    
   
    #
    # IDataEvents Interface
    #    
    def _cb_add_accusation(self, elm):
        assert isinstance(elm, fireflies.members.Accusation)        
        m = self.group.getMemberBySerial(elm.accused)
        assert isinstance(m, fireflies.members.Member)
        
        if m.isFailed():
            return
        
        # Member is not failed. Start timer.
        if not m.getSerial() in self.__timers:
            
            self.__timers[elm.accused] = reactor.callLater(self.timeout,
                                                           self.__memberTimeout,
                                                           m)
            self.group.logger.info("%s accused", m)
            self.group._trigger_member_accused(m)
                                                            
    def _cb_del_accusation(self, elm):
        assert isinstance(elm, fireflies.members.Accusation)
        m = self.group.getMemberBySerial(elm.accused)
        assert isinstance(m, fireflies.members.Member)

        if m.isAccused():
            # Do nothing as the member is still accused.
            return
        
        if m.isFailed():
            m._setFailed(False)
            self.group.fRing.remove(m)
            self.group.aRing.insert(m)
            self.group.logger.info("%s revived", m)
            self.group._trigger_member_lives(m)
        try:
            to = self.__timers.pop(m.getSerial())
            to.cancel()
        except KeyError:
            pass
        
        
    def _cb_add_note(self, elm):
        assert isinstance(elm, fireflies.members.Note)
        m = self.group.getMemberBySerial(elm.serial)
        assert isinstance(m, fireflies.members.Member)
        assert not m.isAccused()        
        m._setFailed(False)
        
        if m in self.group.fRing:
            assert not m in self.group.nRing
            assert not m in self.group.aRing
            self.group.fRing.remove(m)
            self.group.aRing.insert(m)        
            self.group.logger.info("%s live", m)
            assert m.getSerial() not in self.__timers
            self.group._trigger_member_lives(m)
        elif m in self.group.aRing:
            assert not m in self.group.fRing
            assert not m in self.group.nRing
            to = self.__timers.pop(m.getSerial())
            to.cancel()
            self.group._trigger_member_rebuts(m)
            self.group.logger.info("%s rebuts", m)
        elif m in self.group.nRing:
            assert not m in self.group.fRing
            assert not m in self.group.aRing
            self.group.nRing.remove(m)
            self.group.aRing.insert(m)        
            self.group._trigger_member_joined(m)
            self.group.logger.info("%s joined", m)
                            
    def _cb_del_note(self, elm): pass

    def _cb_add_certificate(self, elm):
        assert isinstance(elm, fireflies.crypto.MemberCertificate)        
        m = self.group.mRings.getMemberBySerial(elm.serial)
        if m in self.group.fRing or m in self.group.aRing:
            raise NotImplementedError
        else:
            self.group.logger.info("%s new", m)
            self.group.nRing.insert(m)

    def _cb_del_certificate(self, elm):
        raise NotImplementedError

    def __memberTimeout(self, m):
        assert isinstance(m, fireflies.members.Member)
        self.group.logger.info("%s failed", m)
        m._setFailed(True)
        self.__timers.pop(m.getSerial())
        self.group.aRing.remove(m)
        self.group.fRing.insert(m)

            

class Group(Service):
    """A Fireflies group."""
    
    implements(fireflies.interfaces.IGroup)
    
    def __init__(self, ca, key, cert, mnote=None):
        
        #Service.__init__(self)
        
        if not isinstance(ca, fireflies.crypto.CACertificate): raise ValueError
        if not isinstance(key, fireflies.crypto.MemberKey): raise ValueError
        if not isinstance(cert, fireflies.crypto.MemberCertificate): raise ValueError
        
        self.__listeners = []
        self.logger = logging.getLogger(cert.address)

        self.ca = cert
        self.key = key
        
        self.nRing = fireflies.members.SerialRing()
        self.aRing = fireflies.members.SerialRing()
        self.fRing = fireflies.members.SerialRing()
        self.mRings = fireflies.members.MemberRings(ca.config['T'])      
        self.mRings.logger = self.logger
        
        self.peer = self.mRings.addCert(cert)
        
        if not mnote:
            mnote = members.createInitialNote(cert.serial,							  
                                              ca.config["T"])
            key.sign(mnote)
            
        #self.view.stats.notesCreated += 1            
        
        if not isinstance(mnote, fireflies.members.Note): raise ValueError
        self.mRings.addNote(mnote)
        self.aRing.insert(self.peer)        
        self.__policy = GroupPolicy(self)        
 
        self.badness = 0
        self.running = 0
        #self.stats = fireflies.stats.Stats()
             

    def __len__(self):
        """Return the number of live members."""    
        return len(self.aRing)
    
    def members(self):
        """Return a Ring object containing all live members."""
        return self.aRing

    def failed(self):
        """Return a Ring object containing all failed members."""       
        return self.fRing

    def accused(self):
        raise NotImplementedError

    def __contains__(self, serial):     
        return serial in self.aRing

    def getMemberByAddress(self, address):
        raise NotImplementedError
    
    def getMemberBySerial(self, serial):
        """Return IMember object.
        Raises KeyError if group has no member with the provided serial."""
        return self.mRings.getMemberBySerial(serial)        

    def getGroupID(self):
        """Returns the unique identifier if the group."""        
        return self.ca.serial

    def getGroupName(self):
        """Returns the group name."""
        return self.ca.name
                
    def _failback(self, reason):
        self.logger.exception(reason)


    #
    # IService interface
    #
    def privilegedStartService(self):
        pass

    def startService(self):
        self.running = 1		
        Service.startService(self)

    def join(self): self.startService()

    def stopService(self):
        self.running = 0
        Service.stopService(self)
        self.logger.warning("leave %s", self.ca.name)
        assert self.joined
        self.stats.leave += 1
        #self.joined = False


    def leave(self): self.stopService()
    

    #
    # IGroupEvents
    #    
    def subscribe(self, listener):
        if not fireflies.interfaces.IGroupEvents.providedBy(listener): raise TypeError
        if listener in self.__listeners: raise ValueError
        self.__listeners.append(listener)
        
    def unsubscribe(self, listener):
        if listener not in self.__listeners: raise ValueError
        self.__listeners.remove(listener)
        
    def _trigger_member_joined(self, member):
        for l in self.__listeners:
            reactor.callLater(0, l._cb_member_joined, member)
            
    def _trigger_member_leaves(self, member):
        for l in self.__listeners:
            reactor.callLater(0, l._cb_member_leaves, member)

    def _trigger_member_accused(self, member):
        for l in self.__listeners:
            reactor.callLater(0, l._cb_member_accused, member)

    def _trigger_member_rebuts(self, member):
        for l in self.__listeners:
            reactor.callLater(0, l._cb_member_rebuts, member)

    def _trigger_member_failes(self, member):
        for l in self.__listeners:
            reactor.callLater(0, l._cb_member_failes, member)
    
    def _trigger_member_lives(self, member):
        for l in self.__listeners:
            reactor.callLater(0, l._cb_member_lives, member)

    

    #def fail(self, member):
    #"""Make a live member failed.
    #
    #    Raises ValueError is member is not a live member in the view.
    #    """
    #    
    #    if member.view != self: raise ValueError("Peer not in view.")
    #    assert member in self.pRing
    #            
    #    self.aRing.remove(member)
    #    self.fRing.insert(member)
    #    
    #    try:
    #        if not (member.fdTimer.called):
    #            member.fdTimer.cancel()
    #    except AttributeError:
    #        pass
    #    member.fdTimer = None
    #    member.stats.failed += 1
    #    
    #    self.logger.info("failed %s s=%d t=%d", member, len(self.aRing), len(self.pRing))        
    #
    #    for l in self._listeners:
    #        l.handle_leave(member)
    #        #reactor.callLater(0, l.handle_leave, member)

    #def revive(self, member):
    #    """Make a failed member live.
    #
    #    Raises ValueError if the member is not failed.
    #    """
    #    
        #if member.view != self: raise ValueError("Member not in view.")
        #assert member in self.pRing

        #self.fRing.remove(member)
        #self.aRing.insert(member)
        #member.nPing = 0
        #if member.isAccused():
            #self.logger.warning("revived peer is accused. Setting timeout.")
            #assert not member.fdTimer
            #member.fdTimer = reactor.callLater(self.rebuttalTime(), self.fail, member)

        #self.logger.info("joined %s s=%d t=%d", member, len(self.aRing), len(self.pRing))        
        #member.stats.revived += 1
        #for l in self._listeners:
            #reactor.callLater(0, l.handle_join, member)
            #l.handle_join(member)



    #def handle_accused(self, member):
        #"""Upcall when a member gets accused.

        #The default implementation rebuts accusation for itself."""

        ## Rebut accusation for this member.
        #isinstance(member, members.Member)
        
        #if member.serial == self.peer.serial:
            #mask = self.peer.getMask()
            #newNote = members.Note(self.cert.serial,
                                    #self.peer.note.lifeline + 1,
                                    #self.peer.getMask(),
                                    #self.peer.note.data)
            #newNote.badness = self.badness
            #self.key.sign(newNote)
            #reactor.callLater(0, self.view.addNotes, newNote)
            #self.view.stats.notesCreated += 1



#
# Stuff below does not work.
#

#class FlyCast(BaseGroup):
    #"""Intrusion tolerant multicast group."""

    #def __init__(self, ca, priv, pub, note=None):
        #super(FlyCast, self).__init__(ca, priv, pub, note)
        #self._myViewOfOther = {}  # The last message nr I've seen from all known peers.
        #self._othersViewOfMe = {} # Dict of nr of the last of my message seen by all known peers.
        #self._msgWindow = []  # My message window. 
        #self._msgWindowBase = 0 # The first message in _msgWindow has this 

    #def handle_join(self, peer):
        #pass

    #def handle_leave(self, peer):
        #del self._myViewOfOther[peer.id]
        #del self._othersViewOfMe[peer.id]

    #def handle_rebuttal(self, member):
        #note = member.note
        #if not note.data: return
        #if note.serial == self.peer.id: return # Ignore messages from ourselves.

        #print "Received", note, note.data
        #print "myViewOfOther", self._myViewOfOther
        #print "oterhsViewOfMe", self._othersViewOfMe
        #print "mymsgs", self._msgWindow
        #print "base", self._msgWindowBase
        
        ## Todo: Check data format
        #hisVersions, hisWindowBase, hisMsgWindow = note.data
        #hisId = note.serial

        ##
        ## Shrink msg window
        ##
        
        ## Record what msg nr he has seen. If we are not in his dict,
        ## he has not seen any messages.        
        #if self.peer.id in hisVersions:
            #hisVersionOfMe = hisVersions[self.peer.id]
        #else:
            #hisVersionOfMe = self._msgWindowBase - 1
        #self._othersViewOfMe[hisId] = hisVersionOfMe
        
        ## Check that he is in range
        #assert hisVersionOfMe >= self._msgWindowBase - 1
        #assert hisVersionOfMe <= self._msgWindowBase + len(self._msgWindow)

        ## Move window past the last acked message.
        #rear = self._rearOfWindow()
        #print rear, self._msgWindowBase
        #while rear >= self._msgWindowBase:
            #self._msgWindowBase += 1
            #self._msgWindow.pop(0)

        ##
        ## Deliver any new messages
        ##        
        #myVersionOfHim = self._myViewOfOther.get(hisId, hisWindowBase-1)
        #sendAck = False
        #for nr in range(len(hisMsgWindow)):
            #msg = hisMsgWindow[nr]
            #msgnr = hisWindowBase + nr
            #if myVersionOfHim >= msgnr: continue
            #reactor.callLater(0, self.handle_mcast, msg, hisId, msgnr)
            #sendAck = True
            #myVersionOfHim = msgnr
        #self._myViewOfOther[hisId] = myVersionOfHim
        
        #if sendAck:
            #self.mcast()

                
    #def mcast(self, msg=None):
        #"""Multicast msg."""
        
        #print "Sending: ", msg

        #if msg:
            #self._msgWindow.append(msg)
            
        #n = copy(self.peer.note)
        #n.data = (self._myViewOfOther, self._msgWindowBase, self._msgWindow)
        #n.lifeline += 1
        #n.sign(self.peer.priv)
        
        #reactor.callLater(0, self.view.addNotes, n)

    #def _rearOfWindow(self):
        #v = self._othersViewOfMe.values()
        #if v == []:
            #return self._msgWindowBase + len(self._msgWindow)
        #else:
            #return min(self._othersViewOfMe.values())
        
    #def handle_mcast(self, msg, sender, version):
        #print "MCAST:", msg, sender, version
        #pass


#class FlyDict(FlyCast):

    #def __init__(self, ca, priv, pub, note=None):
        #super(FlyDict, self).__init__(ca, priv, pub, note)
        #self._flydict = {}

    #def handle_mcast(self, data, sender, version):
        #self._flydict[sender] = data
        #self.handle_update(sender)

    #def handle_update(self, key):
        #pass
        
    #def handle_leave(self, peer):
        #super(FlyDict, self).handle_leave(peer)
        #if peer.id in self._flydict:
            #del self._flydict[peer.id]
        
    #def __setitem__(self, key, value):        
        #if not self.isWritable[key]:
            #raise IndexError, "Read only"
        #peer = self.sn2peer[key]
        #sn = peer.id
        #n = copy(peer.note)
        #n.data = (self_versions[key]+1, data)
        #n.lifeline += 1
        #n.sign(peer.priv)
        #self.view.addNotes(n)
        
    #def __getitem__(self, key):
        #return self._flydict[key]

    #def isWritable(self, key):
        #return self.view.sn2peer[key].priv != None

    #def __iterate__(self):
        #return self._flydict.__iterate__()
