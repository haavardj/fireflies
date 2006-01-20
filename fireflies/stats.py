# -*- coding: iso-8859-1 -*-
######################################################################
## Filename:      stats.py
## Description:   Fireflies runtime statistic.
## Author:        Håvard Dagenborg Johansen <haavardj@cs.uit.no>
## Modified at:   Thu Jan 19 21:46:01 2006
## Modified by:   Håvard Dagenborg Johansen <haavardj@cs.uit.no>
## Licence:       GPL (see the LICENSE file).
##  
##         Copyright© 2006, University of Tromsø (Norway)
##                
## $Id: stats.py,v 1.1 2006/01/20 12:41:27 haavardj Exp $
##                
######################################################################



"""The following are collected by the library:

group:

join
leave

View:
accusationsTotal: total nr of received accusation.
accusationsRedundant: received accusation that was redundant.
accusationsCreated: created accusations
accusationsInvalid: invalid accusations.

notesTotal: total nr of received notes.
notesRedundant: received notes that are redundant
notesInvalid: invalid notes
notesCreated: created notes (rebuttals)

certsTotal: total nr of received certs.
certsRedundant: received certs that are redundant
certsInvalid: received certs that are redundant

tcpR: tcp bytes read 
tcpW: tcp bytes written 
tcpOpen

updR: udp bytes read
updW: upd bytes written


Member:

accuseByzantine: made Byzantine accusations.
accusePossible: made plausible accusations.
accuseReplaced: made accusation is replaced by another.
accuseCloser: made accusation that replaced another.

accusedByzantine: been target of Byzantine accusation.
accusedPossible: been suspected.
accusedFirst: correct->suspected state transitions.
accusedClear: suspected->correct state transitions.

noteUpdated: updated notes

revived: nr of times a member has joined
failed: nr of times a member has failed

redirect:

cputime: 

"""


import fireflies

def printStats(stats):
    """Prints standard stats collected by Fireflies."""
    
    return """
Connections:
      opened    %f


Accusations:
      created   %f
      received  %f
      accepted  %f
      discarded %f
      
Notes:
      created   %f
      received  %f
      discarded %f
      accepted  %f

Certs:
      received  %f
      discarded %f
      accepted  %f
      
Membership:
      failed  %f
      revived %f

      join %f
      leave %f

      redirect %f

System
      load %f
      """ %(stats.tcpOpen,          
            stats.accusationsCreated, stats.accusationsTotal, stats.accusationsRedundant,
            stats.accusationsTotal - stats.accusationsRedundant,

            stats.notesCreated,
            stats.notesTotal, stats.notesRedundant,
            stats.notesTotal - stats.notesRedundant,
            
            stats.certsTotal, stats.certsRedundant,
            stats.certsTotal - stats.certsRedundant, 

            stats.failed, stats.revived,
            stats.join, stats.leave,
            stats.redirect,
            stats.cputime
            )                    



class Stats:

    # List of collected items. The list also specifies the ordering of
    # the logline.    
    items = [
        'accusationsTotal',
        'accusationsRedundant',
        'accusationsCreated',
        'accusationsInvalid',
        
        'notesTotal',
        'notesRedundant',
        'notesInvalid',
        'notesCreated',
        
        'certsTotal',
        'certsRedundant',
        'certsInvalid',
                   
        'accuseByzantine',
        'accusePossible',
        'accuseReplaced',
        'accuseCloser',
        
        'accusedByzantine',
        'accusedPossible',
        'accusedFirst',
        'accusedClear',
        
        'noteUpdated',
        
        'revived',
        'failed',
        
        'udpR',
        'udpW',
        
        'tcpR',
        'tcpW',
        'tcpOpen',

        'join',
        'leave',
        'redirect',
        'cputime'
        ]
        
    def __init__(self):
        d = {}
        for k in Stats.items:
            d[k] = 0
        self.__dict__['_data'] = d
        
    def __getattr__(self, name):
        try:
            return self.__dict__["_data"][name]
        except KeyError:
            raise AttributeError("Invalid attribute %s" % name)
        
    def __setattr__(self, name, value):
        if not self._data.has_key(name):
            raise AttributeError("Invalid attribute %s" % name)
        self.__dict__["_data"][name] = value

    def __add__(self, other):
        s = Stats()
        for k in Stats.items:
            setattr(s, k, getattr(self, k) + getattr(other, k))
        return s

    def __sub__(self, other):
        s = Stats()
        for k in Stats.items:
            setattr(s, k, getattr(self, k) - getattr(other, k))
        return s

    def __div__(self, other):
        s = Stats()
        if isinstance(other, Stats):
            for k in Stats.items:
                setattr(s, k, getattr(self, k) / getattr(other, k))
        elif type(other) == int or type(other) == float:
            for k in Stats.items:
                setattr(s, k, float(getattr(self, k)) / float(other))
        else: raise AttributeError
        return s


    def __str__(self):
        d = map(lambda x: self._data[x], Stats.items)
        return ("%d " * len(d) ) % tuple(d)

def resetAll(group):
    group.stats = Stats()
    group.view.stats = Stats()
    for peer in group.view.pRing:
        peer.stats = Stats()


def collect(group):
    s = Stats()
    s += group.stats
    s += group.view.stats
    for peer in group.view.pRing:
        s = s + peer.stats
    return s
