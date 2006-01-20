######################################################################
## Filename:      setrecon.py
## Description:   High-Level set-recon library.
## Author:        Håvard Dagenborg Johansen <haavardj@cs.uit.no>
## Modified at:   Mon Jan 16 18:55:26 2006
## Modified by:   Håvard Dagenborg Johansen <haavardj@cs.uit.no>
##  
## Licence: GPL (see LICENCE file).
##         Copyright© 2006, University of Tromsø (Norway)
##                
## $Id: setrecon.py,v 1.1 2006/01/20 12:41:27 haavardj Exp $
##                
######################################################################

from setreconbase import *
from Crypto.Util.number import long_to_bytes, bytes_to_long


initialized = False
bitsize = 0
mbar = 0

def bytes_to_numstr(bytes):
    return "%d" % bytes_to_long(bytes)

def init(bz, mm):
    global initialized, bitsize, mbar
    bitsize, mbar, = bz, mm
    if initialized:
        raise RuntimeError("Already initialized")    
    reconciled_set_init(bitsize, mbar)
    initialized = True

    

class ReconSet:

    def __init__(self, p, k):
        if not initialized: raise RuntimeError("Not initialized.")
        self._recon = reconciled_set(p, k)
        self._data = {}

    def create_node(self):
        return self._recon.create_node()

    def __contains__(self, elm):

        zz_p = self.elmToZZp(elm)
        
        if zz_p in self._data:
            assert zz_p in self._recon
            return True
        else:
            assert not zz_p in self._recon
            return False

    def __getitem__(self, key):
        return self._data[key]

    def getByInternal(self, key):
        km = self._recon.internal2external(key)
        return self._data[km]

    def append(self, elm):
        zz_p = self.elmToZZp(elm)

        if elm in self._data:
            assert zz_p in self._recon
            raise ValueError("Element in set.")

        assert not zz_p in self._recon
        self._data[zz_p] = elm
        self._recon.add_element(zz_p)

        
    def remove(self, elm):
        zz_p = self.elmToZZp(elm)
        if zz_p not in self._data:
            assert not zz_p in self._recon, "%s in set" %elm
            raise ValueError("Element not in set.")
        else:
            assert zz_p in self._recon, "%s not in set" %elm
            del self._data[zz_p]
            self._recon.del_element(zz_p)

    def elmToZZp(self, elm):
        return to_ZZ_p(to_ZZ("%d"%elm))
            
    def getRootPartition(self):
        return self._recon.get_tree()

    def reconcile(self, rootA, samplevalues, extra, size):

        if rootA.isTerminal():
            raise RuntimeError("Root is terminal")
        
        return self._recon.reconcile(rootA, samplevalues, extra, size)
        

    def printTree(self):
        def _(lvl, node):
            if node.isTerminal():
                print "  "*lvl, node.hash_vector, "*"
            else:
                print "  "*lvl, node.hash_vector
            for child in iterChildren(node):
                if child: _(lvl+1, child)
        _(0, self.getRootPartition())
            
    
    

def iterChildren(node):
    for x in range(p):
        yield node.getChild(x)

def iterZZ(zz):
    for x in zz_length(zz):
        yield zz_getItem(zz, x)



if __name__ == "__main__":

    init(160, 3, 2, 3)

    elms1 = [1, 2, 3, 4, 5, 6, 8]
    elms2 = [1, 2, 3, 4, 5, 6, 7]
    
    s1 = ReconSet()
    for x in elms1: s1.append(x)

    s2 = ReconSet()
    for x in elms2: s2.append(x)

    r, m, h = s1.reconcile(s1.getRootPartition(), s2.getRootPartition())

    print r, m, h
    import sys
    
    sys.exit(1)
    elms = []
    import random
    for x in range(500):
        elms.append(random.randint(0, 2**160))
                    
    s1 = ReconSet()
    for x in elms:
        s1.append(x)
        assert x in s1


    random.shuffle(elms)
    while elms:
        x = elms.pop()
        s1.remove(x)
        assert not x in s1
          


##if not rootB:

##    if rootA and not rootA.isTerminal():
##        sendB(rootA)

##elif rootB.isTerminal():

##    if rootA==None or rootA.isTerminal():
##        return diff( rootA.terminal_data(), rootB.terminal_data() )

##    else:
##        sendB( rootA.terminal_data())
##        return diff(rootA.terminal_data(),  rootB.terminal_data())

##else not rootB.isTerminal():

    
