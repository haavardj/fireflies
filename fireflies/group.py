# -*- coding: iso-8859-1 -*-
######################################################################
## Filename:      group.py
## Description:   Fireflies group.
## Author:        Håvard Dagenborg Johansen <haavardj@cs.uit.no>
## Modified at:   Tue Jan 24 13:51:45 2006
## Modified by:   Håvard Dagenborg Johansen <haavardj@cs.uit.no>
## Licence:       GPL (see the LICENSE file).
##  
##         Copyright© 2006, University of Tromsø (Norway)
##                
## $Id: group.py,v 1.11 2007/07/09 08:59:59 haavardj Exp $
##                
######################################################################

import logging
import gossip, fd, members
import fireflies.stats
from twisted.internet import reactor    

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
    peer = None
    
    def __init__(self, cacert, mkey, mcert, mnote=None):
        
        self.logger = logging.getLogger(mcert.address)
        self.cacert, self.mkey, self.mcert = cacert, mkey, mcert

        self.view = fireflies.view.View(self, byzantineToleranceNumber=cacert.config["T"])
        
        if not mnote:
            self.mnote = members.createInitialNote(mcert.serial, cacert.config["T"])
            self.view.stats.notesCreated += 1
        else: 
            self.mnote = mnote

        self.joined = False        
        self.badness = 0
        self.view.logger = self.logger

        self.stats = fireflies.stats.Stats()
        self._eventSinkRegistry = {}
        self.registerEventHandler("data.accusation", self.evSelfRebuttal)
    
    def registerEventHandler(self, name, func, *args, **kwargs): 
        t = self._eventSinkRegistry.get(name, [])
        t.append((func, args, kwargs))
        self._eventSinkRegistry[name] = t
    
    def getMemberBySerial(self, serial):
        return self.view.sn2peer[serial]
    
    def getEventNames(self):
        return self._eventSinkRegistry.keys()

    def notify(self, name, *args, **kwargs):
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
        self.logger.warning("leave %s", self.cacert.name)
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
            self.mkey.sign(n)
            reactor.callLater(0, self.view.addNote, n)

            
    def __len__(self):
        return len(self.view.aRing)

    def __contains__(self, serial):
        return serial in self.view.aRing
    
    def size(self):
        """Return the number of live members."""
        return len(self)

    def isSignedByCA(self, itm):
        return self.cacert.verify(itm)

    def getGroupCertificate(self):
        return self.cacert

    def getView(self):
        return self.view

    def getMembers(self):
        """Returns a list of all members."""
        return self.view.pRing

    def getGroupID(self):
        """Returns the unique identifier if the group."""        
        return self.cacert.serial

    def getGroupName(self):
        """Returns the group name."""
        return self.cacert.name
    
    def getByzantineToleranceLevel(self):
        return self.cacert.config['T']
        
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

        self.view.addCertificate(mcert)
        peer = self.view.sn2peer[mcert.serial]
        self.view.addNote(self.mnote)
        self.peer = self.me = peer
        isinstance(self.peer, members.Member)
        self.pinger = fd.FailureDetector(peer, self.mkey)
        self.gossiper = gossip.Gossip(self, peer)
        
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

