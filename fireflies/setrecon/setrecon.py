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
## $Id: setrecon.py,v 1.7 2008/02/04 13:42:34 haavardj Exp $
##                
######################################################################

from setreconbase import *
from fireflies.util import long_to_bytes, bytes_to_long
import sha

initialized = False
bitsize = 0
mbar = 0

NODE_STATUS_EMPTY = 0
NODE_STATUS_TERMINAL = 1
NODE_STATUS_NONTERMINAL = 2

verbose = True

def bytes_to_numstr(bytes):
    return "%d" % bytes_to_long(bytes)

def init(bz=160, mm=3):
    """Initialize the setrecon library. Must be called once before the library can be used.
    
    @param bz: The number of bits per data-item.
    @type elm: int
    @param mm: Max set difference.
    """
    
    global initialized, bitsize, mbar
    bitsize, mbar, = bz, mm
    if initialized:
        raise RuntimeError("Already initialized")    
    reconciled_set_init(bitsize, mbar)
    initialized = True
    
def isEmptyNode(node): 
    if not node: return True     
    if node:
        if node.intree:
            if node.ref_count() < 2: node.printNode(0)
            assert node.ref_count() > 1, "refcount is %d shoud be 2. intree=%s" %(node.ref_count(), node.intree)
        else:
            if node.ref_count() == 0: node.printNode(0)
            assert node.ref_count() > 0, "refcount is %d shoud be >0. intree=%s" %(node.ref_count(), node.intree)            
    return bool(   (node == None) or (node.setsize==0) or (node.intree == False))

def isTerminalNode(node):
    if not node: return False
    return node.isTerminal()
        
class Reconciliation:
    
    def __init__(self, rset):
        if 0: isinstance(rset, ReconSet)
        self.rset = rset                
        r = rset.getRootPartition()
        if r: r.ref()
        self.nodes = [r]
        self.current = None

        self.meMissing = set()
        self.otherMissing = set()

    def run(self):
        while 1:
            yield self.next()
   
    def next(self):
        if self.current: self.current.unref()
        if not self.nodes: raise StopIteration
        self.current = self.nodes.pop(0)
        if self.current: self.current.ref()
        return self.current
    
    def requestByHashes(self, hashes):
        for h in hashes:
            self.otherMissing.add(self.rset[h])
        
        
    def update(self, n):
        c = self.current
        
        if isEmptyNode(n) and isEmptyNode(c): return
    
        if isEmptyNode(n):
            for x in self.rset.internal2external(c.terminal_data()):
                assert x not in self.otherMissing
                assert x not in self.meMissing
                #assert x in self.rset
                self.otherMissing.add(self.rset[x])                    
            return
        
        if isEmptyNode(c): return
        
        if isTerminalNode(n) or isTerminalNode(c):
            
            if isTerminalNode(n):
                myData = c.terminal_data()
                for x in self.rset.internal2external(difference_set(myData, n.hash_vector)):
                    assert x not in self.meMissing
                    assert x not in self.otherMissing
                    self.meMissing.add(x)        
                    
                for x in self.rset.internal2external(difference_set(n.hash_vector, myData)):
                    assert x not in self.meMissing
                    assert x not in self.otherMissing
                    self.otherMissing.add(self.rset[x])                        

            return
                                
        status, a, b = self.rset.reconcile(c.hash_vector,
                                          c.extra_hashes,
                                          c.setsize,
                                          n.hash_vector,
                                          n.extra_hashes,
                                          n.setsize,
                                          c.valids)
              
        if status == 0:
            t = []
            for x in range(self.rset.p):
                i = c.getChild(x)
                if i: i.ref()                    
                t.append(i)
            self.nodes = t + self.nodes                 

        else:
            for x in a:            
                assert not self.rset.has_key(x) #i not in setA
                assert x not in self.meMissing
                self.meMissing.add(x)
                
            for x in b:
                assert self.rset.has_key(x)
                assert x not in self.otherMissing
                #print "add to bMissing", x
                self.otherMissing.add(self.rset[x])
                    
             
    def doChildren(self):
        for child in iterChildren(self.current, self.rset.p):
            self.nodes.insert(0, child)
    
    
    
def diffs(setA, setB):
    
    nodeAs = [setA.getRootPartition()]
    nodeBs = [setB.getRootPartition()]
    nodeAs[0].ref()
    nodeBs[0].ref()
    aMissing = set()
    bMissing = set()

    nodeA = nodeB = None
    round = -1
    
    while nodeAs:
        if nodeA: nodeA.unref()
        if nodeB: nodeB.unref()
        nodeA = nodeAs.pop()
        nodeB = nodeBs.pop()
        round += 1
        
        if nodeA and nodeB:
            assert nodeA.start == nodeB.start
            assert nodeB.stop == nodeA.stop

        if isEmptyNode(nodeA) and isEmptyNode(nodeB): 
            continue
        
        if isEmptyNode(nodeA) or isEmptyNode(nodeB):
            # One of the nodes is empty. Transfer any items to that node.
                        
            if isEmptyNode(nodeB):
                # setB's node is empty. Transfer elements A -> B
                for x in setA.internal2external(nodeA.terminal_data()):                
                    assert x not in bMissing
                    assert x not in aMissing
                    #assert x in setA
                    bMissing.add(x)
                    
            if isEmptyNode(nodeA):
                # setA's node is empty. Transfer elementts B <- A   
                for x in setB.internal2external(nodeB.terminal_data()):                
                    assert x not in aMissing
                    assert x not in bMissing
                    #assert x in setB                    
                    aMissing.add(x)
                
            continue

        
        if nodeA.isTerminal() or nodeB.isTerminal():
            #Having a terminal node means that we can compute the difference
            #directly.If both are none terminal, we must use the set
            #reconciliation algorithm.
            for x in setA.internal2external(difference_set(nodeB.terminal_data(), nodeA.terminal_data())):
                assert x not in bMissing
                assert x not in aMissing
                #assert x in setA
                #assert x not in setB        
                bMissing.add(x)
            for x in setB.internal2external(difference_set(nodeA.terminal_data(), nodeB.terminal_data())):
                assert x not in aMissing
                assert x not in bMissing
                #assert x in setB
                #assert x not in setA                                
                aMissing.add(x)
            continue
                
        # Both nodes er neither terminal or empty. 
        status, a, b = setA.reconcile(nodeA.hash_vector,
                                      nodeA.extra_hashes,
                                      nodeA.setsize,
                                      nodeB.hash_vector,
                                      nodeB.extra_hashes,
                                      nodeB.setsize,
                                      nodeA.valids)
        
        
        if status == 0:
            # Setrecon failed. Do children
            for x in range(setA._recon.p):
                t = []
                if nodeA.hasChild(x):
                    n = nodeA.getChild(x)
                    n.ref()                    
                    t.append(n)
                else:
                    t.append(None)
                nodeAs = t + nodeAs      
            for x in range(setB._recon.p):
                t = []
                if nodeB.hasChild(x):
                    n = nodeB.getChild(x)
                    n.ref()
                    t.append(n)
                else:
                    t.append(None)
                nodeBs = t + nodeBs
        else:
            for x in a:            
                assert setB.has_key(x) 
                assert not setA.has_key(x) 
                assert x not in aMissing
                aMissing.add(x)
            for x in b:
                assert setA.has_key(x) 
                assert not setB.has_key(x) 
                assert x not in bMissing
                bMissing.add(x)
            
            
       
    assert not nodeBs
    assert not nodeAs
    #nodeA.unref()
    #nodeB.unref()
    aDiff = set(map(lambda x: setB[x], aMissing))
    bDiff = set(map(lambda x: setA[x], bMissing))
    return aDiff, bDiff
    
    
    
class ReconSet:

    def __init__(self, p, k):
        """
        @param p: Partitioning factor
        @type p: int
        @param k: Factor controling probability of false positives.
        @type k: int
        """
        if not initialized: raise RuntimeError("Not initialized.")
        self._recon = reconciled_set(p, k)
        self._data = {}
        self.p = p

    def create_node(self):
        return self._recon.create_node()
    
    def items(self):
        return self._data.values()

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
    
    def __iter__(self):
        return iter(self._data.values())
    
    def has_key(self, key):
        try:
            self[key]
            return True
        except KeyError:
            return False

    def getByInternal(self, key):
        km = self._recon.internal2external(key)
        return self._data[km]

    def insert(self, elm):

        zz_p = self.elmToZZp(elm)
        if elm in self._data:
            assert zz_p in self._recon
            raise ValueError("Element in set.")

        assert not zz_p in self._recon
        self._data[zz_p] = elm
        self._recon.add_element(zz_p)

    add = insert
        
    def hash(self):
        hsh = sha.new()
        n = self.getRootPartition()
        hv = map(lambda x: str(x), n.hash_vector)
        hv.sort()
        for x in hv: hsh.update(x)
        return hsh.digest()
        
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
                print "  "*lvl, self.internal2external(node.hash_vector), "*"
            else:
                print "  "*lvl, self.internal2external(node.hash_vector)
            for child in iterChildren(node, self._recon.p):
                if child: _(lvl+1, child)
        _(0, self.getRootPartition())
            

    def internal2external(self, hash_vec):
        return self._recon.internal2external(hash_vec)

    def external2internal(self, hash_vec):
        return self._recon.external2internal(hash_vec)


def iterChildren(node, p):
    for x in range(p):
        yield node.getChild(x)

def iterZZ(zz):
    for x in zz_length(zz):
        yield zz_getItem(zz, x)
     
def dottySet(s):
    
    import pydot

    dot = pydot.Dot()
    p = s.getRootPartition()
        
    def _r(p):    

        l = "%s %s %s" % (s.internal2external(p.hash_vector), p.start, p.stop)
        if p.isTerminal():        
            n = pydot.Node(str(p), label=l, shape="octagon")
        else:
            n = pydot.Node(str(p), label=l, shape="box")
        
        dot.add_node(n)
        
        for child in iterChildren(p, s._recon.p):

            if child:  
                _r(child)
                dot.add_edge(pydot.Edge(str(p), str(child)))

    _r(p)

    
    return dot


    
        


 