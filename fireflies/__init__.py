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
## $Id: __init__.py,v 1.18 2011/11/07 13:23:52 haavardj Exp $
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


protocol_version = (0,1,1)

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


defaultConfig = {

    #'MBAR': 10,
    #'BITSIZE': 160,

    # Length of encryption keys.
    'port': 14377,
    'RSA_SIZE': 1024,

    'maxGroupSize': 10000, 
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
    
    #'NUM_GOSSIPRINGS': 8,
    #'NUMMONRINGS': 13,
    'pByz': 0.20,

    # The probability of accusing a live member due to packet
    # loss. Lower number is better but increases the time it takes to
    # detect a failed member.
    #'PMISTAKE': 0.00001,

    # Do not accuse a member unless it has been pinged this many times.    
    #'TMIN': 3,

    # What factor the pinging protocol will use to smooth the expected
    # average loss rate.
    #'SMOOTHING': 0.999,

    # Time to wait between receiving an accusation and failing the
    # accused member. 
    #'REBUTTAL_TIME': 600,

    # How often gossip partner should exchange state (seconds).
    #'GOSSIP_ROUNDTIME': 60,

    # How often a monitor should ping (seconds).
    #'PING_ROUNDTIME': 30
    }

class ByzantineError(Exception):
    """Raised when Byzantine behavior is detected."""


#from members import Member, Note, Accusation
#from crypto import MemberCertificate, CACertificate
#from group import BaseGroup
#from view import View
