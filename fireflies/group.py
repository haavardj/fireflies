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
## $Id: group.py,v 1.6 2006/06/06 20:45:28 haavardj Exp $
##                
######################################################################



import logging
import gossip4, fd, members
import fireflies.stats
from twisted.internet import reactor    

# To speed up the simulator, copying is done here.
from copy import copy

class BaseGroup(object):
    """A basic Fireflies group object.

    cacert --- The certificate of the groups' CA.
    
    mkey   --- The member's private key. 
    
    mcert  --- The member's certificate, signed by the CA.
    
    mnote --- The member's note. If the member is re-joning the group,
    its latest note can be supplied here. This argument is never
    necessary but speeds up the joining process. If not specified a
    new note will be created. Any previous notes that the member
    issued will be learned from the group.        
    """
    
    def __init__(self, cacert, mkey, mcert, mnote=None):
        
        self.logger = logging.getLogger(mcert.address)
        self.cacert, self.mkey, self.mcert = cacert, mkey, mcert

        self.view = members.View(self.cacert)
    
        if not mnote:
            self.mnote = members.createInitialNote(mcert.serial,
                                                   cacert.config["T"])
            self.view.stats.notesCreated += 1
        else: self.mnote = mnote

        self.joined = False        
        self.badness = 0
        self.view.logger = self.logger

        self.stats = fireflies.stats.Stats()

        #self.__setattr__ = self.__setattr_im__
    
    def __setattr_im__(self, k, v):
        raise RuntimeError("immutable error")
                
    def leave(self):
        """Leave the group."""
        self.logger.warning("leave %s", self.cacert.name)
        assert self.joined
        self.stats.leave += 1
        self.pinger.stop()
        self.gossiper.stop()
        self.view.unregisterListener(self)
        self.joined = False

    def __len__(self):
        return len(self.view.aRing)

    def __contains__(self, serial):
        return serial in self.view.aRing
    
    def size(self):
        """Return the number of live members."""
        return len(self)

    def getMembers(self):
        """Returns a list of members serials and addresses."""
        return map(lambda: (x.serial, x.cert.address), self.view.aRing)

    def getGroupID(self):
        """Returns the unique identifier if the group."""        
        return self.cacert.serial

    def getGroupName(self):
        """Returns the group name."""
        return self.cacert.name
        
    def join(self, bootnodes=[]):
        """Join the group.

        bootnodes --- list of (certificate, note) tuples. To be
        successfully integrated into an existing group, at least t
        other members must be specified."""
        
        assert not self.joined
        self.logger.warning("join %s", self.cacert.name)
        self.stats.join += 1
        cacert, mkey, mcert, mnote = self.cacert, self.mkey, self.mcert, self.mnote

        self.mnote.badness = self.badness

        self.view.registerListener(self)
        self.view.addCerts(mcert)
        peer = self.view.sn2peer[mcert.serial]
        self.view.addNotes(self.mnote)
        self.peer = peer
        isinstance(self.peer, members.Member)
        
        for c, n in bootnodes:
            self.view.addCerts(c)
            self.view.addNotes(n)
                    
        def failback(failure):
            self.logger.critical("%s failure", str(failure))
            return failure

        self.pinger = fd.FailureDetector(peer, self.mkey)
        self.gossiper = gossip4.Gossip(peer)
        self.gossiper.start()
        self.pinger.start()
        self.joined = True
        
    def handle_join(self, member):
        """Upcall when a member joins."""

        self.logger.info("join %s total=%d known=%d", self.view.pprint(member),
                         len(self.view.aRing),
                         len(self.view.pRing))

    def handle_leave(self, member):
        """Upcall when a member leaves."""
        pass

    def handle_rebuttal(self, member):
        """Upcall when receiving a new rebutal (note) from a member."""
        pass

    def handle_accused(self, member):
        """Upcall when a member gets accused.

        The default implementation rebuts accusation for itself."""

        # Rebut accusation for this member.
        isinstance(member, members.Member)
        
        if member.serial == self.peer.serial:
            mask = self.peer.getMask()
            newNote = members.Note(self.mcert.serial,
                                   self.peer.note.lifeline + 1,
                                   self.peer.getMask(),
                                   self.peer.note.data)
            newNote.badness = self.badness
            self.mkey.sign(newNote)
            reactor.callLater(0, self.view.addNotes, newNote)
            self.view.stats.notesCreated += 1


    def _failback(self, reason):
        self.logger.exception(reason)


class FlyCast(BaseGroup):
    """Intrusion tolerant multicast group."""

    def __init__(self, ca, priv, pub, note=None):
        super(FlyCast, self).__init__(ca, priv, pub, note)
        self._myViewOfOther = {}  # The last message nr I've seen from all known peers.
        self._othersViewOfMe = {} # Dict of nr of the last of my message seen by all known peers.
        self._msgWindow = []  # My message window. 
        self._msgWindowBase = 0 # The first message in _msgWindow has this 

    def handle_join(self, peer):
        pass

    def handle_leave(self, peer):
        del self._myViewOfOther[peer.id]
        del self._othersViewOfMe[peer.id]

    def handle_rebuttal(self, member):
        note = member.note
        if not note.data: return
        if note.serial == self.peer.id: return # Ignore messages from ourselves.

        print "Received", note, note.data
        print "myViewOfOther", self._myViewOfOther
        print "oterhsViewOfMe", self._othersViewOfMe
        print "mymsgs", self._msgWindow
        print "base", self._msgWindowBase
        
        # Todo: Check data format
        hisVersions, hisWindowBase, hisMsgWindow = note.data
        hisId = note.serial

        #
        # Shrink msg window
        #
        
        # Record what msg nr he has seen. If we are not in his dict,
        # he has not seen any messages.        
        if self.peer.id in hisVersions:
            hisVersionOfMe = hisVersions[self.peer.id]
        else:
            hisVersionOfMe = self._msgWindowBase - 1
        self._othersViewOfMe[hisId] = hisVersionOfMe
        
        # Check that he is in range
        assert hisVersionOfMe >= self._msgWindowBase - 1
        assert hisVersionOfMe <= self._msgWindowBase + len(self._msgWindow)

        # Move window past the last acked message.
        rear = self._rearOfWindow()
        print rear, self._msgWindowBase
        while rear >= self._msgWindowBase:
            self._msgWindowBase += 1
            self._msgWindow.pop(0)

        #
        # Deliver any new messages
        #        
        myVersionOfHim = self._myViewOfOther.get(hisId, hisWindowBase-1)
        sendAck = False
        for nr in range(len(hisMsgWindow)):
            msg = hisMsgWindow[nr]
            msgnr = hisWindowBase + nr
            if myVersionOfHim >= msgnr: continue
            reactor.callLater(0, self.handle_mcast, msg, hisId, msgnr)
            sendAck = True
            myVersionOfHim = msgnr
        self._myViewOfOther[hisId] = myVersionOfHim
        
        if sendAck:
            self.mcast()

                
    def mcast(self, msg=None):
        """Multicast msg."""
        
        print "Sending: ", msg

        if msg:
            self._msgWindow.append(msg)
            
        n = copy(self.peer.note)
        n.data = (self._myViewOfOther, self._msgWindowBase, self._msgWindow)
        n.lifeline += 1
        n.sign(self.peer.priv)
        
        reactor.callLater(0, self.view.addNotes, n)

    def _rearOfWindow(self):
        v = self._othersViewOfMe.values()
        if v == []:
            return self._msgWindowBase + len(self._msgWindow)
        else:
            return min(self._othersViewOfMe.values())
        
    def handle_mcast(self, msg, sender, version):
        print "MCAST:", msg, sender, version
        pass


class FlyDict(FlyCast):

    def __init__(self, ca, priv, pub, note=None):
        super(FlyDict, self).__init__(ca, priv, pub, note)
        self._flydict = {}

    def handle_mcast(self, data, sender, version):
        self._flydict[sender] = data
        self.handle_update(sender)

    def handle_update(self, key):
        pass
        
    def handle_leave(self, peer):
        super(FlyDict, self).handle_leave(peer)
        if peer.id in self._flydict:
            del self._flydict[peer.id]
        
    def __setitem__(self, key, value):        
        if not self.isWritable[key]:
            raise IndexError, "Read only"
        peer = self.sn2peer[key]
        sn = peer.id
        n = copy(peer.note)
        n.data = (self_versions[key]+1, data)
        n.lifeline += 1
        n.sign(peer.priv)
        self.view.addNotes(n)
        
    def __getitem__(self, key):
        return self._flydict[key]

    def isWritable(self, key):
        return self.view.sn2peer[key].priv != None

    def __iterate__(self):
        return self._flydict.__iterate__()
