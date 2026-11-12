######################################################################
## Filename:      group.py
## Description:   Fireflies group.
## Author:        Håvard Dagenborg <havard.dagenborg@outlook.com>
## Modified at:   Tue Jan 24 13:51:45 2006
## Modified by:   Håvard Dagenborg <havard.dagenborg@outlook.com>
## Licence:       MIT (see the LICENCE file).
##  
##         Copyright© 2006, Håvard Dagenborg
##                
## $Id: group.py,v 1.32 2014/06/16 07:49:47 haavardj Exp $
##                
######################################################################

"""Fireflies group interface."""

import logging
from typing import Any, Callable, Hashable

from OpenSSL import SSL
from twisted.application.service import MultiService
from twisted.internet import defer, ssl
from fireflies.state import Accusation, Note, Member, createInitialNote
from fireflies.view import View
from fireflies.crypto import identityFromCertificate
from fireflies.ring import Ring
import fireflies.stats
import fireflies.protocols
from fireflies import crypto
from fireflies.util import reactor

# An event handler: the function and the extra arguments it was registered with.
Upcall = tuple[Callable[..., Any], tuple[Any, ...], dict[str, Any]]
HandlerRef = tuple[Hashable, Upcall]


class Group(MultiService):
    """A Fireflies group. This class is the main interface to the Firelifes runtime. 
    """

    #maxGroupSize = 1000 
    #pByz = 0.20    
    tRebuttal: float = 60 #5 #2 * (2.5* 60)
    badness: int = 0
    name: "str | None" = "group"
    wasStarted = False
    
    def __init__(self, groupCertificate: crypto.Certificate, myKey: crypto.PrivateKey,
                 myCertificate: crypto.Certificate, myNote: "Note | None" = None,
                 logger: logging.Logger = logging.getLogger()) -> None:
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
        
        
        self._groupCertificate = groupCertificate
        self.name = groupCertificate.get_subject().commonName
        self._myKey = myKey

        self.view = View(self)

        self._eventSinkRegistry: dict[Hashable, list[Upcall]] = {
            "member.crash": [],
            "member.recover": [],
            "data.note":[],
            "data.accusation":[],
            "data.certificate":[]} 

        self.registerEventHandler("data.accusation", self.evSelfRebuttal)        
        
        self.view.addCertificate(myCertificate)
        self._me = self.view.getMemberByCertificate(myCertificate)

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
        
    def getLiveMembers(self) -> Ring[Member]:
        """@return: Return an iterable object of all currently live members."""
        return self.view.aRing

    def getFailedMembers(self) -> Ring[Member]:
        """@return: Return an iterable object of all currently failed members."""
        return self.view.fRing

    def getAllMembers(self) -> Ring[Member]:
        """@return: Return an iterable object of of all (live + failed) members."""
        return self.view.pRing

    def getMemberByCertificate(self, cert: crypto.Certificate) -> Member:
        return self.view.getMemberByIdentity(identityFromCertificate(cert))

    def getMemberByIdentity(self, id: str) -> Member:
        return self.view.sn2peer[id]

    def getMembersByAddress(self, address: str) -> list[Member]:
        return self.view.getMembersByAddress(address)

    def createEventChannel(self, name: Hashable) -> None:
        if name in self._eventSinkRegistry:
            raise KeyError("Name %s exist as eventhandler" %name)
        self._eventSinkRegistry[name] = []
    
    def registerEventHandler(self, name: Hashable, func: Callable[..., Any], *args: Any, **kwargs: Any) -> HandlerRef:
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
        upcall: Upcall = (func, args, kwargs)
        self._eventSinkRegistry[name].append(upcall)        
        return (name, upcall)
        
    def removeEventHandler(self, hdlr: HandlerRef) -> None:
        name, upcall = hdlr
        self._eventSinkRegistry[name].remove(upcall)
        
    def getPublicKey(self) -> crypto.PublicKey:
        return self.getGroupCertificate().get_pubkey()
        
    def getEventNames(self) -> list[Hashable]:
        """
        @return: List of all event names.
        """
        return list(self._eventSinkRegistry.keys())

    def notify(self, name: Hashable, *args: Any, **kwargs: Any) -> None:
        """Publish an event.
        
        @param name: Event name/type.
        @param args: Arguments.
        @param kwargs: keyword arguments.
        """
        try:
            #self.logger.debug("notify %s %s %s", name, args, kwargs)
            for f, a, k in self._eventSinkRegistry[name]:
                nk: dict[str, Any] = {}
                nk.update(k)
                nk.update(kwargs)
                na = args + a
                reactor.callLater(0, f, name, *na, **nk)
        except KeyError:
            self.logger.error("error: notify %s but no subscribers", name)
            raise

    def evSelfRebuttal(self, name: str, elm: Accusation, status: bool) -> None:
        """@todo: Check that the accusation is still valid when receiving this event."""
        assert name == "data.accusation"

        if status == True and elm.accused == self.getMe().identity:
            currentEpoch = self.getMe().getEpoch()
            if elm.epoch < currentEpoch:
                self.logger.warning("accusation %s old. Current epoch=%d.", self.view.pprint(elm), currentEpoch)
            elif elm.epoch == currentEpoch:        
                self.logger.warning("rebutting false accusation %s", self.view.pprint(elm))
                self.nextEpoch()            
                assert elm.epoch < self.getMe().getEpoch()
            else:
                self.logger.warning("accusation %s old. Current epoch=%d.", self.view.pprint(elm), currentEpoch)
                
                        
    def nextEpoch(self) -> None:
        n = self.getMe().nextNote()
        n.sign(self.getMyKey())
        self.view.addNote(n)        
            
    def __len__(self) -> int:
        """@return: Return the number of all members."""
        return len(self.view.aRing)

    def __contains__(self, member: object) -> bool:
        """@return: true if member is a live member of the group."""
        return member in self.view.aRing
    
    def size(self) -> int:
        """@return: Return the number of all members."""
        return len(self)

    def isSignedByCA(self, itm: crypto.Signable) -> bool:
        """
        Check if an object is correctly signed by the group CA.
        @param itm: Object that is to be checked.
        @type itm: Subclass of L{fireflies.crypto.Signable}
        @return: Return true if itm is signed by the group CA.
        """
        return itm.verify(self._groupCertificate)
        
    def getGroupCertificate(self) -> crypto.Certificate:
        """
        @return: Get group certificate.
        @rtype: L{fireflies.crypto.Certificate}
        """
        return self._groupCertificate

    def getView(self) -> View:
        """
        @return: Return the group's view object.
        @rtype: L{fireflies.view.View}"""
        return self.view

    def getMe(self) -> Member:
        """
        @return: Return your member object.
        @rtype: L{fireflies.state.Member}
        """
        return self._me
    
    def getMyKey(self) -> crypto.PrivateKey:
        """
        @return: Return your private key.
        @rtype: L{fireflies.crypto.PrivateKey}
        """
        return self._myKey

    def getGroupID(self) -> str:
        """@return: Return the unique group identity."""        
        return self._groupCertificate.identity

    def getGroupName(self) -> "str | None":
        """@return: Return the unique group name."""        
        return self._groupCertificate.get_subject().commonName
    
    def nrMonitoringRings(self) -> int:
        return self.getGroupCertificate().nrMonitoringRings()
        
    def nrGossipingRings(self) -> int:
        return self.getGroupCertificate().nrGossipingRings()

    def startService(self) -> None:
        self.logger.info("join group %s as %s. Badness=%d", self.getGroupName(), self.getMe(), self.badness)
        MultiService.startService(self)        
        self.stats.join += 1

    def stopService(self) -> defer.DeferredList:
        self.logger.info("leave group %s", self.getGroupName())      
        d = MultiService.stopService(self)
        self.stats.leave += 1
        self.nextEpoch()
        return d
                
    def getTLSOptions(self) -> ssl.CertificateOptions:
        """@return: TLS options (a Twisted context factory) for this member."""
        return self._sslCtx

    def getContext(self) -> SSL.Context:
        """Lets the group itself be used as a Twisted context factory."""
        return self._sslCtx.getContext()


def collectStatistic(group: Group) -> fireflies.stats.Stats:
    """Sum the group's counters and any separate per-member counters.
    Members share the group's Stats object, so count each object once."""
    s0 = fireflies.stats.Stats()
    seen: set[int] = set()
    for s in [group.stats] + [n.stats for n in group.getAllMembers()]:
        if id(s) not in seen:
            seen.add(id(s))
            s0 += s
    return s0
    