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
## $Id: group.py,v 1.32 2014/06/16 07:49:47 haavardj Exp $
##                
######################################################################

"""Fireflies group interface."""

import logging
import twisted.internet
from twisted.application.service import MultiService
from fireflies.state import Accusation, Note, Member, createInitialNote
from fireflies.view import View
from fireflies.crypto import identityFromCertificate
import fireflies.stats
import fireflies.protocols
from fireflies import crypto



class Group(MultiService):
    """A Fireflies group. This class is the main interface to the Firelifes runtime. 
    """

    #maxGroupSize = 1000 
    #pByz = 0.20    
    tRebuttal = 60 #5 #2 * (2.5* 60)
    badness = 0
    name = "group"
    wasStarted = False
    
    def __init__(self, groupCertificate, myKey, myCertificate, myNote=None, logger=logging.getLogger()):
        """
        A group must be initialized with a group certificate and your member certificate and 
        private key.
        
        @param groupCertificate: The public certificate of the group CA.
        @type groupCertificate: L{fireflies.crypto.Certificate}
        @param myKey: Your private key. 
        @type myKey: L{fireflies.crypto.PrivateKey}
        @param myCertificate: Your member certificate, signed by the CA's private key,
        @type myCertificate: L{fireflies.crypto.Certificate}
        @param myNote: Your most up-to-date note. When re-joning a group
        a note can be supplied here. This argument is never
        necessary but speeds up the joining process. If not specified a
        new note will be created with epoch 1. Any previously issued notes with higher epochs 
        will be learned from the group.    
        @type myNote: L{fireflies.state.Note}
        """

        MultiService.__init__(self)
        self.stats = fireflies.stats.Stats()
        self.logger = logger
        
        
        if not isinstance(groupCertificate, crypto.Certificate): raise ValueError(groupCertificate)
        self._groupCertificate = groupCertificate
        
    
        self.name = groupCertificate.get_subject().commonName

        if not isinstance(myKey, crypto.PrivateKey): raise ValueError(myKey)
        self._myKey = myKey
        
        if not isinstance(myCertificate, crypto.Certificate): raise ValueError(myCertificate)

        self.view = View(self)

        self._eventSinkRegistry = {
            "member.crash": [],
            "member.recover": [],
            "data.note":[],
            "data.accusation":[],
            "data.certificate":[]} 

        self.registerEventHandler("data.accusation", self.evSelfRebuttal)        
        
        self.view.addCertificate(myCertificate)
        self._me = self.view.getMemberByCertificate(myCertificate)
        
        assert isinstance(self._me, Member)
        if myNote: 
            self.view.addNote(myNote)
        else:
            myNote = createInitialNote(self._me)
            myNote.sign(self.getMyKey())
            self.view.addNote(myNote)
                            
        self._sslCtx = fireflies.protocols.makeSSLCtx(
            self._me.getCertificate(), 
            self._myKey,
            self._groupCertificate)
        
    def getMemberByIdentity(self, fid):
        return self.view.getMemberByIdentity()
    
    def getLiveMembers(self):
        """@return: Return an iterable object of all currently live members."""
        return self.view.aRing

    def getFailedMembers(self):
        """@return: Return an iterable object of all currently failed members."""
        return self.view.fRing

    def getAllMembers(self):
        """@return: Return an iterable object of of all (live + failed) members."""
        return self.view.pRing

    def getMemberByCertificate(self, cert):
        return self.view.getMemberByIdentity(identityFromCertificate(cert))

    def getMemberByIdentity(self, id):
        return self.view.sn2peer[id]

    def getMembersByAddress(self, address):
        return [x for x in self.view.pRing if x.cert.address == address]        

    def createEventChannel(self, name):
        if name in self._eventSinkRegistry:
            raise KeyError("Name %s exist as eventhandler" %name)
        self._eventSinkRegistry[name] = []
    
    def registerEventHandler(self, name, func, *args, **kwargs):
        """Register a function to receive events (callbacks). Events have
        names. Names are usually strings, but can be any object. A callback
        function is registered to receive events with a spesific name. The
        callback will receive the arguments given by the event publisher. In
        addition, it will receive any arguments spesified when registering the
        callback. The semantics for the arguments in the callback is the
        following::
        
          name, publisher's arguments + provided arguments, publishers kwargs + provided kwargs
        
        For instance, consider the function f regisered to receive events in
        the following manner::

          registerEventHandler("foo", f, "bar1", "bar2")
        
        Later, a "foo" event is published in the following manner::

          notify("foo", "bar3")

        then, f will be called with the following::
        
          foo("foo", "bar3", "bar1", "bar2")
          
        Keyword arguments list will be merged together. 
          
        @param name: The event name/type that is to be received.
        @param func: The function that is to be called.
        @param args: Argumens that is to be passed back to the function.
        @param kwargs: Keyword arguments that is to be passed back to the function.
        """
        upcall = (func, args, kwargs)
        self._eventSinkRegistry[name].append(upcall)        
        return (name, upcall)
        
    def removeEventHandler(self, hdlr):
        name, upcall = hdlr
        self._eventSinkRegistry[name].remove(upcall)
        
    def getPublicKey(self):
        return self.getGroupCertificate().get_pubkey()
        
    def getEventNames(self):
        """
        @return: List of all event names.
        """
        return list(self._eventSinkRegistry.keys())

    def notify(self, name, *args, **kwargs):
        """Publish an event.
        
        @param name: Event name/type.
        @param args: Arguments.
        @param kwargs: keyword arguments.
        """
        try:
            #self.logger.debug("notify %s %s %s", name, args, kwargs)
            for f, a, k in self._eventSinkRegistry[name]:
                nk = {}
                nk.update(k)
                nk.update(kwargs)
                na = args + a
                twisted.internet.reactor.callLater(0, f, name, *na, **nk)
        except KeyError:
            self.logger.error("error: notify %s but no subscribers", name)
            raise

    def evSelfRebuttal(self, name, elm, status):
        """@todo: Check that the accusation is still valid when receiving this event."""
        assert name == "data.accusation"
        assert isinstance(elm, Accusation)
                   
        if status == True and elm.accused == self.getMe().identity:
            currentEpoch = self.getMe().getNote().epoch
            if elm.epoch < currentEpoch:
                self.logger.warning("accusation %s old. Current epoch=%d.", self.view.pprint(elm),self.getMe().getNote().epoch)
            elif elm.epoch == currentEpoch:        
                self.logger.warning("rebutting false accusation %s", self.view.pprint(elm))
                self.nextEpoch()            
                assert elm.epoch < self.getMe().getNote().epoch
            else:
                self.logger.warning("accusation %s old. Current epoch=%d.", self.view.pprint(elm), currentEpoch)
                
                        
    def nextEpoch(self):
        n = self.getMe().nextNote()
        assert isinstance(n, Note)
        n.sign(self.getMyKey())
        self.view.addNote(n)        
            
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
        """
        Check if an object is correctly signed by the group CA.
        @param itm: Object that is to be checked.
        @type itm: Subclass of L{fireflies.crypto.Signable}
        @return: Return true if itm is signed by the group CA.
        """
        return self._groupCertificate.verify(itm)
        
    def getGroupCertificate(self):
        """
        @return: Get group certificate.
        @rtype: L{fireflies.crypto.Certificate}
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
        @rtype: L{fireflies.crypto.PrivateKey}
        """
        return self._myKey

    def getGroupID(self):
        """@return: Return the unique group identity."""        
        return self._groupCertificate.identity

    def getGroupName(self):
        """@return: Return the unique group name."""        
        return self._groupCertificate.get_subject().commonName
    
    def nrMonitoringRings(self):
        return int(self.getGroupCertificate().get_subject().organizationName.split()[0])
        
    def nrGossipingRings(self):
        return int(self.getGroupCertificate().get_subject().organizationName.split()[1])

    def startService(self):
        self.logger.info("join group %s as %s. Badness=%d", self.getGroupName(), self.getMe(), self.badness)
        MultiService.startService(self)        
        self.stats.join += 1

    def stopService(self):
        self.logger.info("leave group %s", self.getGroupName())      
        MultiService.stopService(self)
        self.stats.leave += 1
        self.nextEpoch()
                
    def getTLSOptions(self):
        """@return: TLS options (a Twisted context factory) for this member."""
        return self._sslCtx

    def getContext(self):
        """Lets the group itself be used as a Twisted context factory."""
        return self._sslCtx.getContext()

import fireflies.stats
def collectStatistic(group):
    isinstance(group, Group)
    s0 = fireflies.stats.Stats()
    
    s0 += group.stats
    
    for n in group.getAllMembers():
        s0 += n.stats
    return s0
    