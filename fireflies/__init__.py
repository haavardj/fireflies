# -*- coding: iso-8859-1 -*-
######################################################################
## Filename:      __init__.py
## Description:   Fireflies: a scalabe and intrusion tolerant membership
##                protocol. 
## Author:        Håvard Dagenborg Johansen <haavardj@cs.uit.no>
## Modified at:   Fri Jan 20 13:28:54 2006
## Modified by:   Håvard Dagenborg Johansen <haavardj@cs.uit.no>
## Licence:       GPL (see the LICENSE file).
##  
##         Copyright© 2006, University of Tromsø (Norway)
##                
## $Id: __init__.py,v 1.1 2006/01/20 12:41:26 haavardj Exp $
##                
######################################################################



"""Fireflies is a scalable and intrusion tolerant group membership
service.

"""

__version__ = "0.27.1"
version = __version__

protocol_version = (0,27,1)

import time as t
time = t
del t


#from group import BaseGroup


defaultConfig = {

    'MBAR': 12,
    'BITSIZE': 160,

    # Length of encryption keys.
    'RSA_SIZE': 1024,

    'MAX_GROUP_SIZE': 200, 

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
    
    'NUM_GOSSIPRINGS': 9,
    #'NUMMONRINGS': 13,
    'T': 6,

    # The probability of accusing a live member due to packet
    # loss. Lower number is better but increases the time it takes to
    # detect a failed member.
    'PMISTAKE': 0.001,

    # Do not accuse a member unless it has been pinged this many times.    
    'TMIN': 3,

    # What factor the pinging protocol will use to smooth the expected
    # average loss rate.
    'SMOOTHING': 0.999,

    # Time to wait between receiving an accusation and failing the
    # accused member. 
    'REBUTTAL_TIME': 900,

    # How often gossip partner should exchange state (seconds).
    'GOSSIP_ROUNDTIME': 60,

    # How often a monitor should ping (seconds).
    'PING_ROUNDTIME': 30
    }


