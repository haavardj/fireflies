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
## $Id: group.py,v 1.29 2011/12/21 10:10:09 haavardj Exp $
##                
######################################################################

"""Fireflies group interface."""

import logging
from twisted.internet import reactor
from twisted.application.service import MultiService
from fireflies.state import Accusation, Note, Member, createInitialNote
from fireflies.view import View
from fireflies.crypto import identityFromCertificate
import fireflies.stats
import fireflies.protocols
import M2Crypto



class Group(MultiService):
    """A Fireflies group. This class is the main interface to the Firelifes runtime. 
    """

    #maxGroupSize = 1000 
    #pByz = 0.20    
    tRebuttal = 60

    name = "group"
    
    def __init__(self, groupCertificate, myKey, myCertificate, myNote=None, logger=logging.getLogger()):
        """
        A group must be initialized with a group certificate and your member certificate and 
        private key.
        
        @param groupCertificate: The public certificate of the group CA.
        @type groupCertificate: L{M2Crypto.X509.X509}
        @param myKey: Your private key. 
        @type myKey: L{M2Crypto.EVP.PKey}
        @param myCertificate: Your member certificate, signed by the CA's private key,
        @type myCertificate: L{M2Crypto.X509.X509}
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
        
        if not isinstance(groupCertificate,  M2Crypto.X509.X509): raise ValueError, groupCertificate
        self._groupCertificate = groupCertificate
        
        maxSize, pByz, ftl = groupCertificate.get_issuer().organizationName.split()
        
        self.maxGroupSize = int(maxSize)
        self.pByz = float(pByz)
        self.faultToleranceLevel = float(ftl)
        
        self.name = groupCertificate.get_subject().commonName

        if not isinstance(myKey, M2Crypto.EVP.PKey): raise ValueError, myKey
        self._myKey = myKey
        
        if not isinstance(myCertificate, M2Crypto.X509.X509): raise ValueError, myCertificate

        self.view = View(self)

        self._eventSinkRegistry = {}
        self.registerEventHandler("data.accusation", self.evSelfRebuttal)        
        
        self.view.addCertificate(myCertificate)
        self._me = self.view.getMemberByCertificate(myCertificate)
        
        assert isinstance(self._me, Member)
        if myNote: self.view.addNote(myNote)
        else:
            myNote = createInitialNote(self._me)
            myNote.sign(self.getMyKey())
            self.view.addNote(myNote)

        self.joined = False        
        self.badness = myNote.badness

        
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
        return filter(lambda x: x.cert.address == address, self.view.pRing)        
    
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
        t = self._eventSinkRegistry.get(name, [])
        t.append((func, args, kwargs))
        self._eventSinkRegistry[name] = t
        
    def getPublicKey(self):
        return self.getGroupCertificate().get_pubkey()
        
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
            #self.logger.debug("notify %s %s %s", name, args, kwargs)
            for f, a, k in self._eventSinkRegistry[name]:
                nk = {}
                nk.update(k)
                nk.update(kwargs)
                na = args + a
                reactor.callLater(0, f, name, *na, **nk)
        except KeyError:
            pass
            #self.logger.debug("notify %s but no subscribers", name)
                        

    def evSelfRebuttal(self, name, elm, status):
        """@todo: Check that the accusation is still valid when receiving this event."""
        assert name == "data.accusation"
        if status == True and elm.accused == self.getMe().getIdentity():
            self.logger.warning("rebutting false accusation %s", elm)
            n = self.getMe().nextNote()
            isinstance(n, Note)
            n.sign(self.getMyKey())
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
        @rtype: L{M2Crypto.X509.X509}
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
        @rtype: L{M2Crypto.EVP.PKey}
        """
        return self._myKey

    def getGroupID(self):
        """@return: Return the unique group identity."""        
        return self._groupCertificate.identity

    def getGroupName(self):
        """@return: Return the unique group name."""        
        return self._groupCertificate.get_subject().commonName
    
    def getByzantineToleranceLevel(self):
        """@return: Return the Byzantine tolerance level set by the group's CA."""        
        return self.view.toleranceLevel
        
    def startService(self):
        
        self._sslCtx = fireflies.protocols.makeSSLCtx(
            self.getMe().getCertificate(), 
            self.getMyKey(),
            self.getGroupCertificate())
        
        MultiService.startService(self)        
        self.logger.info("join group %s", self.getGroupName())
        

    def stopService(self):
        MultiService.stopService(self)
        self.logger.info("leave group %s", self.getGroupName())      
                
    def getContext(self):
        return self._sslCtx
        #me = self.getMe()
        #myCert = me.getCertificate()
        #myKey = self.getMyKey()        
        #groupCA = self.getGroupCertificate()
        #assert isinstance(myKey, M2Crypto.EVP.PKey)
        #assert isinstance(myCert, M2Crypto.X509.X509)
        #assert isinstance(groupCA, M2Crypto.X509.X509)
        #assert groupCA.verify()
        #assert myCert.verify(groupCA.get_pubkey())
        #ctx = M2Crypto.SSL.Context("sslv23")
        #ctx.load_cert(self.store.filenameCertificate(myCert), keyfile=self.store.filenameKey(myKey))
        #ctx.set_client_CA_list_from_file(self.store.fileCaCert)
        #ctx.load_verify_locations(self.store.fileCaCert)
        ##ctx.set_allow_unknown_ca(True)
        ##ctx.set_verify(M2Crypto.SSL.verify_peer | M2Crypto.SSL.verify_fail_if_no_peer_cert, 9, sslVerifyCB)
        #ctx.set_verify(M2Crypto.SSL.verify_peer | M2Crypto.SSL.verify_fail_if_no_peer_cert, 9) #.verify_none,0)
        ##ctx.set_verify(M2Crypto.SSL.verify_client_once, 2)
        ##ctx.set_info_callback()
        

        #return ctx    
        
    
import fireflies.stats
def collectStatistic(group):
    isinstance(group, Group)
    s0 = fireflies.stats.Stats()
    
    s0 += group.stats
    
    for n in group.getAllMembers():
        s0 += n.stats
    return s0
    