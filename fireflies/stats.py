# -*- coding: utf-8 -*-
######################################################################
## Filename:      stats.py
## Description:   Fireflies runtime statistic.
## Author:        Håvard Dagenborg <havard.dagenborg@outlook.com>
## Modified at:   Tue Feb  7 14:18:02 2006
## Modified by:   Håvard Dagenborg <havard.dagenborg@outlook.com>
## Licence:       MIT (see the LICENCE file).
##  
##         Copyright© 2006, Håvard Dagenborg
##                
## $Id: stats.py,v 1.5 2014/06/16 07:49:47 haavardj Exp $
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


def printStats(stats):
    
    return """
Connections:
      opened    %f


Accusations:
      created   %f
      received  %f
      redundant  %f
      accepted %f
      
Notes:
      created   %f
      received  %f
      discarded %f
      accepted  %f
      invalid   %f

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

      """ %(stats.tcpOpen,
            
            stats.accusationsCreated, 
            stats.accusationsTotal, 
            stats.accusationsRedundant,
            stats.accusationsTotal - stats.accusationsRedundant,

            stats.notesCreated,
            stats.notesTotal, 
            stats.notesRedundant,
            stats.notesTotal-stats.notesRedundant, 
            stats.notesInvalid,
            
            stats.certsTotal, 
            stats.certsRedundant,
            stats.certsTotal - stats.certsRedundant,

            stats.failed, stats.revived,
            stats.join, stats.leave,
            stats.redirect
            )                    


statistics = {}

def addStatistic(name, doc="", pos=-1):
    if name in statistics: 
        raise ValueError("Statistic %s exists." % (name,))    
    statistics[name] = (doc, pos)

def listStatistics():
    return sorted(statistics, key=lambda k: statistics[k][1])

def labels():
    d = listStatistics()
    return ("%s " * len(d) ) % tuple(d)

class Stats:
        
    def __init__(self):
        self.clear()

    def clear(self):
        d = {}
        for k in list(statistics.keys()):
            d[k] = 0
        self.__dict__['_data'] = d
        
    def __getattr__(self, name):
        try:
            return self.__dict__["_data"][name]
        except KeyError:
            raise AttributeError("Invalid attribute %s" % name)
        
    def __setattr__(self, name, value):
        if name not in self._data:
            raise AttributeError("Invalid attribute %s" % name)
        self.__dict__["_data"][name] = value

    def __add__(self, other):
        s = Stats()
        for k in list(statistics.keys()):
            setattr(s, k, getattr(self, k) + getattr(other, k))
        return s

    def __sub__(self, other):
        s = Stats()
        for k in list(statistics.keys()):
            setattr(s, k, getattr(self, k) - getattr(other, k))
        return s

    def __truediv__(self, other):
        s = Stats()
        if isinstance(other, Stats):
            for k in list(statistics.keys()):
                setattr(s, k, getattr(self, k) / getattr(other, k))
        elif type(other) == int or type(other) == float:
            for k in list(statistics.keys()):
                setattr(s, k, float(getattr(self, k)) / float(other))
        else: raise AttributeError
        return s

    def __str__(self):
        d = [self._data[x] for x in listStatistics()]
        return ("%d " * len(d) ) % tuple(d)


#_stats = {"": Stats()}

#def allobjects(obj):
    #return True

#def resetAll(f=allobjects):
    #"""Reset all statistic where f(obj) evaluates to True."""
    
    #for obj, stat in _stats.items():
        #if f(obj): stat.reset()
    
#def collectAll(f=allobjects):
    #"""Return the combinet statistics of all objects where f(obj) returns True."""
    #s = Stats()

    #for obj, stat in _stats.items():
        #if f(obj): s += stat                 
    #return s
        

#def getStat(obj=""):    
    #"""Returns statistic object."""
    #if obj not in _stats:
        #_stats[obj] = Stats()
    #return _stats[obj]
    
    
