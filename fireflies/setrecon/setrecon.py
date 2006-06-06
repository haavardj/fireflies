# -*- coding: iso-8859-1 -*-
######################################################################
## Filename:      setrecon.py
## Description:   High-Level set-recon library.
## Author:        Håvard Dagenborg Johansen <haavardj@cs.uit.no>
## Modified at:   Thu Jan 26 00:04:56 2006
## Modified by:   Håvard Dagenborg Johansen <haavardj@cs.uit.no>
##  
## Licence: GPL (see LICENCE file).
##         Copyright© 2006, University of Tromsø (Norway)
##                
## $Id: setrecon.py,v 1.4 2006/06/06 21:06:53 haavardj Exp $
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

        if isinstance(elm, ZZ_p):
            zz_p = elm
        else:
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
        if isinstance(elm, ZZ_p):
            zz_p = elm
        else:
            zz_p = self.elmToZZp(elm)
        
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

    def reconcile(self, aHashes, aExtra, aSize, bHashes,  bExtra, bSetsize, valids):

        #if rootA.isTerminal():
        #    raise RuntimeError("Root is terminal")
        
        return self._recon.reconcile(aHashes,
                                     aExtra,
                                     aSize,
                                     bHashes, 
                                     bExtra,
                                     bSetsize,
                                     valids)
        

    def printTree(self):
        def _(lvl, node):
            if node.isTerminal():
                print "  "*lvl, node.hash_vector, "*"
            else:
                print "  "*lvl, node.hash_vector
            for child in iterChildren(node):
                if child: _(lvl+1, child)
        _(0, self.getRootPartition())
            

    def internal2external(self, hash_vec):
        return self._recon.internal2external(hash_vec)

    def external2internal(self, hash_vec):
        return self._recon.external2internal(hash_vec)


def iterChildren(node):
    for x in range(p):
        yield node.getChild(x)

def iterZZ(zz):
    for x in zz_length(zz):
        yield zz_getItem(zz, x)



if __name__ == "__main__":

    bitsize = 160
    init(bitsize, 3)

    import random
    #random.seed(1)

    common = []
    diffA = []
    diffB = []
    for x in range(1000):
        i = random.randint(30, 2**bitsize)
        if i not in common: 
            common.append(i)
            
    for x in range(30):
        i = random.randint(30, 2**bitsize)
        if i not in common: 
            diffA.append(i)
    setA = common + diffA            

    for x in range(20):
        i = random.randint(30, 2**bitsize)
        if i not in setA: 
            diffB.append(i)

    setB = common + diffB
    
    s1 = ReconSet(3, 5)
    for x in setA: s1.append(x)

    s2 = ReconSet(3, 5)
    for x in setB: s2.append(x)

    n1s = [s1.getRootPartition()]
    n2s = [s2.getRootPartition()]

    aDiff = vec_ZZ_p()
    bDiff = vec_ZZ_p()
    while n1s:

        n1 = n1s.pop()
        n2 = n2s.pop()

        if n1 == None or n2 == None or n1.setsize == 0 or n2.setsize == 0:
            print "Node is empty. Continue"
            continue

        if n2.isTerminal() or n1.isTerminal():
            print "Terminal nodes. Continue"
            continue
        
        r1, d1, u1 = s1.reconcile(n1.hash_vector,
                                  n1.extra_hashes,
                                  n1.setsize,
                                  n2.hash_vector,
                                  n2.extra_hashes,
                                  n2.setsize,
                                  n1.valids
                                  )
        print "r1=", r1, d1, u1        
        r2, d2, u2 = s1.reconcile(n1.hash_vector,
                                  n1.extra_hashes,
                                  n1.setsize,
                                  n2.hash_vector,
                                  n2.extra_hashes,
                                  n2.setsize,
                                  n2.valids
                                  )
        print "r2=", r2, d2, u2
          
        for x in d1:
            assert long("%s"%x) in s2, "%s in s1" %x 
            assert long("%s"%x) not in s1, "%s not in s2" %x
            assert x not in aDiff
            #aDiff.append(x)

        for x in d2:
            assert long("%s"%x) in s2, "%s in s1" %x 
            assert long("%s"%x) not in s1, "%s not in s2" %x
            assert x not in aDiff
            aDiff.append(x)

            
        for x in u2:
            assert long("%s"%x) in s1, "%s in s1" %x 
            assert long("%s"%x) not in s2, "%s not in s2" %x
            assert x not in bDiff
            #bDiff.append(x)

        for x in u1:
            assert long("%s"%x) in s1, "%s in s1" %x 
            assert long("%s"%x) not in s2, "%s not in s2" %x
            assert x not in bDiff
            bDiff.append(x)


        if r2 != r1:

            #print "n1.terminal", n1.terminal_data()
            #print "n2.terminal", n2.terminal_data()
            
            #n1.printNode(0)
            print "--------------"
            print "--------------"
            #n2.printNode(0)

        assert r2 == r1
        
        if r1 == 0:
            print "Recon failed. Do children."
            assert r2 == 0

            for x in range(s1._recon.p):
                n1s = [n1.getChild(x)] + n1s
                n2s = [n2.getChild(x)] + n2s
        else:
            print "Recon success"
                
            
    print "Recon done"
    print "aDiff", aDiff
    print "bDiff", bDiff
    import sys
    
    sys.exit(1)
    import random
    
    elms = []
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
          



    
