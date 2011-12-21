######################################################################
## Filename:      __init__.py
## Description:   Fireflies: a scalabe and intrusion tolerant membership
##                protocol. 
## Author:        Haavard Dagenborg Johansen <haavardj@cs.uit.no>
## Modified at:   Wed Feb  1 18:53:46 2006
## Modified by:   Haavard Dagenborg Johansen <haavardj@cs.uit.no>
## Licence:       GPL (see the LICENSE file).
##  
##         Copyright 2006, Haavard D Johansen (Norway)
##                
## $Id: __init__.py,v 1.22 2011/12/21 10:10:09 haavardj Exp $
##                
######################################################################

"""
Fireflies is a toolkit for building scalable intrusion-tolerant
peer-to-peer overlay-network services.  The key component of Fireflies
is a weakly consistent group membership protocol that provides to each
member an up-to-date view of all group members. The membership
protocol use redundancy to mask Byzantine fault such that malicious
members cannot wrongly claim that live members have crashed, nor that
crashed members are alive. These properties on the views are provided
with eventual probabilistic guarantees.
"""


protocol_version = (0,3,0)

__version__ = "%d.%d.%d" % protocol_version
version = __version__


import time as t
time = t
del t

EV_RECOVER_NEW = 0 # First time a member is considered live.
EV_RECOVER_REBUTTAL = 1 # Recover by rebuttal
EV_RECOVER_INVALIDATED = 2 # Recover by having all accusations becoming invalid
EV_CRASH_REVOKED = 3 # Crash by revoked member certificate
EV_CRASH_ACCUSED = 4  # Crash by accusation
EV_CRASH_NEW = 5 # A new member is discovered.

EV_DATA_VALID = True
EV_DATA_INVALID = False

import fireflies.stats

fireflies.stats.addStatistic('accusationsTotal', "", 0)
fireflies.stats.addStatistic('accusationsRedundant',"", 1)
fireflies.stats.addStatistic('accusationsCreated',"", 2)
fireflies.stats.addStatistic('accusationsInvalid',"", 3)
        
fireflies.stats.addStatistic('notesTotal',"", 4)
fireflies.stats.addStatistic('notesRedundant',"", 5)
fireflies.stats.addStatistic('notesInvalid',"", 6)
fireflies.stats.addStatistic('notesCreated',"", 7)
        
fireflies.stats.addStatistic('certsTotal',"", 8)
fireflies.stats.addStatistic('certsRedundant',"", 9)
fireflies.stats.addStatistic('certsInvalid',"", 10)
                   
fireflies.stats.addStatistic('accuseByzantine',"", 11)
fireflies.stats.addStatistic('accusePossible',"", 12)
fireflies.stats.addStatistic('accuseReplaced',"", 13)
fireflies.stats.addStatistic('accuseCloser',"", 14)
        
fireflies.stats.addStatistic('accusedByzantine',"", 15)
fireflies.stats.addStatistic('accusedPossible',"", 16)
fireflies.stats.addStatistic('accusedFirst',"", 17)
fireflies.stats.addStatistic('accusedClear',"", 18)
        
fireflies.stats.addStatistic('noteUpdated',"", 19)
        
fireflies.stats.addStatistic('revived',"", 20)
fireflies.stats.addStatistic('failed',"", 21)
        
fireflies.stats.addStatistic('udpR',"", 22)
fireflies.stats.addStatistic('udpW',"", 23)
        
fireflies.stats.addStatistic('tcpR',"", 24)
fireflies.stats.addStatistic('tcpW',"", 25)
fireflies.stats.addStatistic('tcpOpen',"", 26)

fireflies.stats.addStatistic('join',"", 27)
fireflies.stats.addStatistic('leave',"", 28)
fireflies.stats.addStatistic('redirect',"", 29)
fireflies.stats.addStatistic('cputime',"", 30)
fireflies.stats.addStatistic('members',"", 31)
fireflies.stats.addStatistic('fmembers',"", 32)
fireflies.stats.addStatistic('accusationsCreatedByzantine', "", 33)


defaultConfig = {

     # Length of encryption keys.
    'port': 14377,
    'RSA_SIZE': 2048,


    'tcptimeout': 360,

    # NOMGOSSIPRINGS and T reflects how many Byzantine members the
    # protocol can handle. Their values depend on the probability that
    # a member is Byzantine (P_byz) and the maximum number of members
    # in the group. NUMGOSSIPRINGS also depend on the chosen
    # probability that the gossip mesh is fully connected. Se the
    # documentation for detail on how to calculate these values. The
    # default configuration copes with a membership of up to 200
    # members with a probability of .20 that a member is
    # Byzantine. There gossip mesh is connected with a probability of
    # 0.999.
    


    }

class ByzantineError(Exception):
    """Raised when Byzantine behavior is detected."""


