######################################################################
## Filename:      __init__.py
## Description:   Fireflies: a scalabe and intrusion tolerant membership
##                protocol. 
## Author:        Håvard Dagenborg <havard.dagenborg@outlook.com>
## Modified at:   Wed Feb  1 18:53:46 2006
## Modified by:   Håvard Dagenborg <havard.dagenborg@outlook.com>
## Licence:       MIT (see the LICENCE file).
##  
##         Copyright© 2006, Håvard Dagenborg
##                
## $Id: __init__.py,v 1.23 2014/06/16 07:49:47 haavardj Exp $
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


protocol_version: tuple[int, int, int] = (0,3,0)

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

# How much debug data to produce
NOISELEVEL = 1


import fireflies.stats

fireflies.stats.addStatistic('accusationsTotal', "Accusations added to the view, from gossip or created here.", 0)
fireflies.stats.addStatistic('accusationsRedundant', "Accusations for an older note than the accused's current one.", 1)
fireflies.stats.addStatistic('accusationsCreated', "Accusations this member created.", 2)
fireflies.stats.addStatistic('accusationsInvalid', "Accusations discarded: unknown accuser or accused, accuser without a note, or a newer epoch than the accused's note.", 3)
        
fireflies.stats.addStatistic('notesTotal', "Notes added to the view, from gossip or created here.", 4)
fireflies.stats.addStatistic('notesRedundant', "Notes no newer than the member's current note.", 5)
fireflies.stats.addStatistic('notesInvalid', "Notes discarded as invalid.", 6)
fireflies.stats.addStatistic('notesCreated', "Notes this member created, including rebuttals.", 7)
        
fireflies.stats.addStatistic('certsTotal', "Member certificates added to the view.", 8)
fireflies.stats.addStatistic('certsRedundant', "Certificates for members already in the view.", 9)
fireflies.stats.addStatistic('certsInvalid', "Certificates not signed by the group CA.", 10)
                   
fireflies.stats.addStatistic('accuseByzantine', "Accusations from a member that broke the protocol: bad signature, no note for the accused, or not allowed to accuse on any ring.", 11)
fireflies.stats.addStatistic('accusePossible', "Not updated by the current code.", 12)
fireflies.stats.addStatistic('accuseReplaced', "Not updated by the current code.", 13)
fireflies.stats.addStatistic('accuseCloser', "Not updated by the current code.", 14)
        
fireflies.stats.addStatistic('accusedByzantine', "Times a member was the target of such an accusation.", 15)
fireflies.stats.addStatistic('accusedPossible', "Not updated by the current code.", 16)
fireflies.stats.addStatistic('accusedFirst', "Not updated by the current code.", 17)
fireflies.stats.addStatistic('accusedClear', "Not updated by the current code.", 18)
        
fireflies.stats.addStatistic('noteUpdated', "Not updated by the current code.", 19)
        
fireflies.stats.addStatistic('revived', "Members that went from failed to live.", 20)
fireflies.stats.addStatistic('failed', "Members that went from live to failed.", 21)
        
fireflies.stats.addStatistic('udpR', "Bytes received by the failure detector (UDP).", 22)
fireflies.stats.addStatistic('udpW', "Bytes sent by the failure detector (UDP).", 23)
        
fireflies.stats.addStatistic('tcpR', "Bytes received by gossip (TCP).", 24)
fireflies.stats.addStatistic('tcpW', "Bytes sent by gossip (TCP), including length prefixes.", 25)
fireflies.stats.addStatistic('tcpOpen', "Gossip connections opened.", 26)

fireflies.stats.addStatistic('join', "Times this member's group service started.", 27)
fireflies.stats.addStatistic('leave', "Times this member's group service stopped.", 28)
fireflies.stats.addStatistic('redirect', "Gossip connections redirected to a better partner.", 29)
fireflies.stats.addStatistic('cputime', "CPU time; set only in fireflyd's checkpoint log lines.", 30)
fireflies.stats.addStatistic('members', "Set only in fireflyd's checkpoint log lines.", 31)
fireflies.stats.addStatistic('fmembers', "Set only in fireflyd's checkpoint log lines.", 32)
fireflies.stats.addStatistic('accusationsCreatedByzantine', "Accusations created by a member configured to attack (fireflyd -b).", 33)
fireflies.stats.addStatistic('pongsRejected', "Pongs without an outstanding ping or a valid signature.", 34)


defaultConfig: dict[str, int] = {

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


