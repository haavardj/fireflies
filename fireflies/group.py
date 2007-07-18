######################################################################
## Filename:      group.py
## Description:   Fireflies group.
## Author:        Haavard Dagenborg Johansen <haavardj@cs.uit.no>
## Modified at:   Tue Jan 24 13:51:45 2006
## Modified by:   Haavard Dagenborg Johansen <haavardj@cs.uit.no>
## Licence:       GPL (see the LICENSE file).
##  
##         Copyright 2006, Haavard D Johansen (Norway)
##                
## $Id: group.py,v 1.14 2007/07/18 12:44:40 haavardj Exp $
##                
######################################################################

import logging
from twisted.internet import reactor
from fireflies.state import Accusation, Note, Member, GroupCertificate, MemberCertificate, MemberKey
from fireflies.state import createInitialNote
from fireflies.view import View
from fireflies.fd import FailureDetector
from fireflies.gossip import Gossip

import fireflies.stats


class Group(object):
    """A Fireflies group.

    mnote --- The member's note.     
    """
    peer = None
    
    def __init__(self, groupCertificate, myKey, myCertificate, myNote=None):
        """
        A group must be initialized with a group certificate and your member certificate and 
        private key.
        
        @param groupCertificate: The public certificate of the group CA.
        @type groupCertificate: L{fireflies.state.GroupCertificate}
        @param myKey: Your private key. 
        @type myKey: L{fireflies.state.MemberKey}
        @param myCertificate: Your member certificate, signed by the CA's private key,
        @type myCertificate: L{fireflies.state.MemberCertificate}
        @param myNote: Your most up-to-date note. When re-joning a group
        a note can be supplied here. This argument is never
        necessary but speeds up the joining process. If not specified a
        new note will be created with epoch 1. Any previously issued notes with higher epochs 
        will be learned from the group.    
        @type myNote: L{fireflies.state.Note}
        """
        
        if not isinstance(groupCertificate,  GroupCertificate): raise ValueError, groupCertificate
        self._groupCertificate = groupCertificate
        
        if not isinstance(myKey, MemberKey): raise ValueError, myKey
        self._myKey = myKey
        
        if not isinstance(myCertificate, MemberCertificate): raise ValueError, myCertificate
        self.logger = logging.getLogger(myCertificate.address)
        
        if not myNote: myNote = createInitialNote(myCertificate.identity, groupCertificate.config["T"])
        if not isinstance(myNote, Note): raise ValueError, myNote 
        
        self.view = View(self, byzantineToleranceNumber=groupCertificate.config["T"])
        self.view.logger = self.logger

        self._eventSinkRegistry = {}
        self.registerEventHandler("data.accusation", self.evSelfRebuttal)        
        
        self.view.addCertificate(myCertificate)
        self.view.addNote(myNote)
        
        self._me = self.view.getMemberByIdentity(myCertificate.identity)
        assert isinstance(self._me, Member)

        self.joined = False        
        self.badness = 0

        self.stats = fireflies.stats.Stats()
        
    
    def registerEventHandler(self, name, func, *args, **kwargs):
        """Register a function to receive events (callbacks). Events have
        names. Names are usually strings, but can be any object. A callback
        function is registered to receive events with a spesific name. The
        callback will receive the arguments given by the event publisher. In
        addition, it will receive any arguments spesified when registering the
        callback. The semantics for the arguments in the callback is the
        following:
        
          name, publisher's arguments + provided arguments, publishers kwargs + provided kwargs
        
        For instance, consider the function f regisered to receive events in
        the following manner:

          registerEventHandler("foo", f, "bar1", "bar2")
        
        Later, a "foo" event is published in the following manner:

          notify("foo", "bar3")

        then, f will be called with the following:
        
          foo("foo", "bar3", "bar1", "bar2")
          
        Keyword arguments list will be merged together. 
          
        @param name: The event name/type that is to be received.
        @param func: The function that is to be called.
        @param args: Argumens that is to be passed back to the function.
        @param kwargs: Keyword arguments that is to be passed back to the function.
        """
        t = self._eventSinkRegistry.get(name, [])
        t.append((func, args, kwargs))
        self._eventSinkRegistry[name] = t
        
    def getEventNames(self):
        """
        @return: List of all event names.
        """
        return self._eventSinkRegistry.keys()

    def notify(self, name, *args, **kwargs):
        """Publish an event.
        
        @param name: Event name/type.
        @param args: Arguments.
        @param kwargs: keyword arguments.
        """
        try:
            for f, a, k in self._eventSinkRegistry[name]:
                nk = {}
                nk.update(k)
                nk.update(kwargs)
                na = args + a
                reactor.callLater(0, f, name, *na, **nk)
        except KeyError:
            pass
            #self.logger.debug("notify %s but no subscribers", name)
                        
    def leave(self):
        """Leave the group."""
        self.logger.warning("leave %s", self._groupCertificate.name)
        assert self.joined
        self.stats.leave += 1
        self.pinger.stop()
        self.gossiper.stop()
        self.view.unregisterListener(self)
        self.joined = False

    def evSelfRebuttal(self, name, elm, status):
        assert name == "data.accusation"
        if elm.accused == self.me.getSerial() and status == True:
            self.logger.info("rebutting false accusation %s", elm)
            n = self.me.nextNote()
            self._myKey.sign(n)
            reactor.callLater(0, self.view.addNote, n)

            
    def __len__(self):
        """@return: Return the number of all members."""
        return len(self.view.aRing)

    def __contains__(self, identity):
        """@return: true if the group has a member with the given identity."""
        return identity in self.view.aRing
    
    def size(self):
        """@return: Return the number of all members."""
        return len(self)

    def isSignedByCA(self, itm):
        """Check if an object is correctly signed by the group CA.
        @param itm: Object that is to be checked.
        @type itm: Subclass of L{fireflies.crypto.RSASignable}
        @return: Return true if itm is signed by the group CA.
        """
        return self._groupCertificate.verify(itm)
        
    def getGroupCertificate(self):
        """
        @return: Get group certificate.
        @rtype: L{fireflies.state.GroupCertificate}
        """
        return self._groupCertificate

    def getView(self):
        """
        @return: Return the group's view object.
        @rtype: L{fireflies.view.View}"""
        return self.view

    def getMe(self):
        """
        @return: Return your member object.
        @rtype: L{fireflies.state.Member}
        """
        return self._me
    
    def getMyKey(self):
        """
        @return: Return your private key.
        @rtype: L{fireflies.state.MemberKey}
        """
        return self._myKey

    def getGroupID(self):
        """@return: Return the unique group identity."""        
        return self._groupCertificate.identity

    def getGroupName(self):
        """@return: Return the unique group name."""        
        return self._groupCertificate.name
    
    def getByzantineToleranceLevel(self):
        """@return: Return the Byzantine tolerance level set by the group's CA."""        
        return self._groupCertificate.config['T']
        
    def join(self, bootnodes=[]):
        """Join the group."""
        
        assert not self.joined
        self.logger.warning("join %s", self.getGroupName())
        self.stats.join += 1
        
    
        self.pinger = FailureDetector(self.getMe(), self.getMyKey())
        self.gossiper = Gossip(self)
        
        for c, n in bootnodes:
            self.view.addCertificate(c)
            self.view.addNote(n)
                    
        def failback(failure):
            self.logger.critical("%s failure", str(failure))
            return failure

        self.gossiper.start()
        self.pinger.start()
        self.joined = True

    def _failback(self, reason):
        self.logger.exception(reason)
