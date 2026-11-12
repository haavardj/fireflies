######################################################################
## Filename:      setrecon.py
## Description:   High-Level set-recon library.
## Author:        Håvard Dagenborg <havard.dagenborg@outlook.com>
## Modified at:   Thu Jan 26 00:04:56 2006
## Modified by:   Håvard Dagenborg <havard.dagenborg@outlook.com>
##  
## Licence: MIT (see the LICENCE file).
##         Copyright© 2006, Håvard Dagenborg
##                
## $Id: setrecon.py,v 1.10 2014/06/16 07:49:48 haavardj Exp $
##                
######################################################################

import hashlib
import importlib
from collections.abc import Callable, Iterable, Iterator
from typing import Any, Generic, TypeVar

from fireflies.util import bytes_to_long

from . import setreconbase as _base
from .setreconbase import *
from .setreconbase import (
    ZZ,
    ZZ_p,
    difference_set,
    node,
    reconciled_set,
    to_ZZ,
    to_ZZ_p,
    vec_ZZ_p,
)

E = TypeVar("E")


#
# Python 3 adaptations of the SWIG proxies. Python 3 ignores __cmp__
# and __div__, and != no longer falls back to identity, so comparing a
# ZZ_p with None would hit SWIG's overload dispatch and raise.
#

def to_ZZFromBytes(data: "bytes | bytearray") -> ZZ:
    """Convert a little-endian byte string (NTL's ZZFromBytes order) to a ZZ."""
    if not isinstance(data, (bytes, bytearray)):  # pyright: ignore[reportUnnecessaryIsInstance]  # callers may be untyped
        raise TypeError("to_ZZFromBytes needs bytes, got %s" % type(data).__name__)
    return _base._to_ZZFromBytes(bytes(data))  # pyright: ignore[reportPrivateUsage]  # SWIG name


def _zz_cmp(self: ZZ, other: "ZZ | int") -> int:
    return self.__cmp__(other)

def _zz_op(test: Callable[[int], bool]) -> Callable[..., Any]:
    def op(self: ZZ, other: object) -> Any:
        if not isinstance(other, (ZZ, int)):
            return NotImplemented
        return test(_zz_cmp(self, other))
    return op

def _hashStr(self: object) -> int:
    return hash(str(self))

ZZ.__eq__ = _zz_op(lambda c: c == 0)
ZZ.__ne__ = _zz_op(lambda c: c != 0)
ZZ.__lt__ = _zz_op(lambda c: c < 0)
ZZ.__le__ = _zz_op(lambda c: c <= 0)
ZZ.__gt__ = _zz_op(lambda c: c > 0)
ZZ.__ge__ = _zz_op(lambda c: c >= 0)
ZZ.__hash__ = _hashStr
ZZ.__truediv__ = ZZ.__div__

_zzp_eq = ZZ_p.__eq__

def _zzp_equal(self: ZZ_p, other: object) -> Any:
    if not isinstance(other, (ZZ_p, int)):
        return NotImplemented
    return bool(_zzp_eq(self, other))

def _zzp_notequal(self: ZZ_p, other: object) -> Any:
    r = _zzp_equal(self, other)
    return r if r is NotImplemented else not r

ZZ_p.__eq__ = _zzp_equal
ZZ_p.__ne__ = _zzp_notequal
ZZ_p.__hash__ = _hashStr
ZZ_p.__truediv__ = ZZ_p.__div__

initialized = False
bitsize = 0
mbar = 0

NODE_STATUS_EMPTY = 0
NODE_STATUS_TERMINAL = 1
NODE_STATUS_NONTERMINAL = 2

verbose = True

def bytes_to_numstr(data: bytes) -> str:
    return "%d" % bytes_to_long(data)

def init(bz: int = 160, mm: int = 3) -> None:
    """Initialize the setrecon library. Must be called once before the library can be used.
    
    @param bz: The number of bits per data-item.
    @type elm: int
    @param mm: Max set difference.
    """
    
    global initialized, bitsize, mbar
    bitsize, mbar, = bz, mm
    if initialized:
        raise RuntimeError("Already initialized")    

    # SWIG 4.1+ no longer generates the flattened reconciled_set_init.
    reconciled_set.init(bitsize, mbar)
    initialized = True
    
def isEmptyNode(node: "node | None") -> bool:
    if not node: return True
    if node.intree:
        if node.ref_count() < 2: node.printNode(0)
        assert node.ref_count() > 1, "refcount is %d shoud be 2. intree=%s" %(node.ref_count(), node.intree)
    else:
        if node.ref_count() == 0: node.printNode(0)
        assert node.ref_count() > 0, "refcount is %d shoud be >0. intree=%s" %(node.ref_count(), node.intree)
    return node.setsize == 0 or not node.intree

def isTerminalNode(node: "node | None") -> bool:
    if not node: return False
    return node.isTerminal()
        
class Reconciliation(Generic[E]):

    def __init__(self, rset: "ReconSet[E]") -> None:
        self.rset = rset
        r = rset.getRootPartition()
        if r: r.ref()
        self.nodes: list[node | None] = [r]
        self.current: node | None = None

        self.meMissing: set[ZZ_p] = set()
        self.otherMissing: set[E] = set()

    def run(self) -> "Iterator[node | None]":
        # PEP 479: a StopIteration escaping a generator is an error.
        while 1:
            try:
                n = next(self)
            except StopIteration:
                return
            yield n
   
    def __next__(self) -> "node | None":
        if self.current: self.current.unref()
        if not self.nodes: raise StopIteration
        self.current = self.nodes.pop(0)
        if self.current: self.current.ref()
        return self.current
    
    def requestByHashes(self, hashes: Iterable[ZZ_p]) -> None:
        for h in hashes:
            self.otherMissing.add(self.rset[h])
        
        
    def update(self, n: "node | None") -> None:
        c = self.current

        # Nothing to do if my node is empty, whether or not his is.
        if c is None or isEmptyNode(c): return

        if n is None or isEmptyNode(n):
            for x in self.rset.internal2external(c.terminal_data()):
                assert x not in self.otherMissing
                assert x not in self.meMissing
                #assert x in self.rset
                self.otherMissing.add(self.rset[x])                    
            return

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
            t: list[node | None] = []
            for x in range(self.rset.p):
                i = c.getChild(x)
                if i: i.ref()                    
                t.append(i)
            self.nodes = t + self.nodes                 

        else:
            for x in a:            
                assert x not in self.rset #i not in setA
                assert x not in self.meMissing
                self.meMissing.add(x)
                
            for x in b:
                assert x in self.rset
                assert x not in self.otherMissing
                #print "add to bMissing", x
                self.otherMissing.add(self.rset[x])
                    
             
    def doChildren(self) -> None:
        assert self.current is not None
        for child in iterChildren(self.current, self.rset.p):
            self.nodes.insert(0, child)
    
    
    
def diffs(setA: "ReconSet[E]", setB: "ReconSet[E]") -> tuple[set[E], set[E]]:

    rootA = setA.getRootPartition()
    rootB = setB.getRootPartition()
    rootA.ref()
    rootB.ref()
    nodeAs: list[node | None] = [rootA]
    nodeBs: list[node | None] = [rootB]
    aMissing: set[ZZ_p] = set()
    bMissing: set[ZZ_p] = set()

    nodeA: node | None = None
    nodeB: node | None = None
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
                assert nodeA is not None
                for x in setA.internal2external(nodeA.terminal_data()):                
                    assert x not in bMissing
                    assert x not in aMissing
                    #assert x in setA
                    bMissing.add(x)
                    
            if isEmptyNode(nodeA):
                # setA's node is empty. Transfer elementts B <- A   
                assert nodeB is not None
                for x in setB.internal2external(nodeB.terminal_data()):                
                    assert x not in aMissing
                    assert x not in bMissing
                    #assert x in setB                    
                    aMissing.add(x)
                
            continue

        assert nodeA is not None and nodeB is not None
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
            for x in range(setA.p):
                t: list[node | None] = []
                n = nodeA.getChild(x) if nodeA.hasChild(x) else None
                if n is not None:
                    n.ref()
                    t.append(n)
                else:
                    t.append(None)
                nodeAs = t + nodeAs      
            for x in range(setB.p):
                t = []
                n = nodeB.getChild(x) if nodeB.hasChild(x) else None
                if n is not None:
                    n.ref()
                    t.append(n)
                else:
                    t.append(None)
                nodeBs = t + nodeBs
        else:
            for x in a:            
                assert x in setB 
                assert x not in setA 
                assert x not in aMissing
                aMissing.add(x)
            for x in b:
                assert x in setA 
                assert x not in setB 
                assert x not in bMissing
                bMissing.add(x)
            
            
       
    assert not nodeBs
    assert not nodeAs
    #nodeA.unref()
    #nodeB.unref()
    aDiff = set([setB[x] for x in aMissing])
    bDiff = set([setA[x] for x in bMissing])
    return aDiff, bDiff
    
    
    
class ReconSet(Generic[E]):
    """A set of elements of type E that can be reconciled with a remote copy."""

    def __init__(self, p: int, k: int) -> None:
        """
        @param p: Partitioning factor
        @type p: int
        @param k: Factor controling probability of false positives.
        @type k: int
        """
        if not initialized: raise RuntimeError("Not initialized.")
        self._recon = reconciled_set(p, k)
        self._data: dict[ZZ_p, E] = {}
        self.p = p

    def items(self) -> list[E]:
        return list(self._data.values())

    def __contains__(self, elm: "E | ZZ_p") -> bool:

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

    def __getitem__(self, key: ZZ_p) -> E:
        return self._data[key]
    
    def __iter__(self) -> Iterator[E]:
        return iter(list(self._data.values()))
    
    def has_key(self, key: ZZ_p) -> bool:
        try:
            self[key]
            return True
        except KeyError:
            return False

    def getByInternal(self, key: ZZ_p) -> E:
        km = self._recon.internal2external(key)
        return self._data[km]

    def insert(self, elm: E) -> None:

        zz_p = self.elmToZZp(elm)
        if zz_p in self._data:
            assert zz_p in self._recon
            raise ValueError("Element in set.")

        assert not zz_p in self._recon
        self._data[zz_p] = elm
        self._recon.add_element(zz_p)

    add = insert
        
    def hash(self) -> bytes:
        hsh = hashlib.sha1()
        n = self.getRootPartition()
        hv = [str(x) for x in n.hash_vector]
        hv.sort()
        for x in hv: hsh.update(x.encode())
        return hsh.digest()
        
    def remove(self, elm: "E | ZZ_p") -> None:

        if isinstance(elm, ZZ_p):
            zz_p = elm
        else:
            zz_p = self.elmToZZp(elm)
        if zz_p not in self._data:
            assert not zz_p in self._recon, "%s in set" %elm
            raise ValueError("Element not in set %s." % elm)
        else:
            assert zz_p in self._recon, "%s not in set" %elm
            del self._data[zz_p]
            self._recon.del_element(zz_p)

    def elmToZZp(self, elm: E) -> ZZ_p:
        """Map an element to the field. This default takes integers;
        subclasses map other element types."""
        return to_ZZ_p(to_ZZ("%d" % elm))
            
    def getRootPartition(self) -> node:
        return self._recon.get_tree()

    def reconcile(self, aHashes: vec_ZZ_p, aExtra: vec_ZZ_p, aSize: int, bHashes: vec_ZZ_p,
                  bExtra: vec_ZZ_p, bSetsize: int, valids: vec_ZZ_p) -> tuple[int, vec_ZZ_p, vec_ZZ_p]:
        return self._recon.reconcile(aHashes,
                                     aExtra,
                                     aSize,
                                     bHashes, 
                                     bExtra,
                                     bSetsize,
                                     valids)
        
    def printTree(self) -> None:

        def _(lvl: int, n: node) -> None:
            if n.isTerminal():
                print("  "*lvl, self.internal2external(n.hash_vector), "*")
            else:
                print("  "*lvl, self.internal2external(n.hash_vector))
            for child in iterChildren(n, self.p):
                if child: _(lvl+1, child)
        _(0, self.getRootPartition())
            

    def internal2external(self, hash_vec: vec_ZZ_p) -> vec_ZZ_p:
        return self._recon.internal2external(hash_vec)

    def external2internal(self, hash_vec: vec_ZZ_p) -> vec_ZZ_p:
        return self._recon.external2internal(hash_vec)


def iterChildren(parent: node, p: int) -> "Iterator[node | None]":
    for x in range(p):
        yield parent.getChild(x)

     
def dottySet(s: "ReconSet[Any]") -> Any:

    # Optional, for debugging.
    pydot: Any = importlib.import_module("pydot")

    dot = pydot.Dot()
    p = s.getRootPartition()

    def _r(p: node) -> None:

        l = "%s %s %s" % (s.internal2external(p.hash_vector), p.start, p.stop)
        if p.isTerminal():        
            n = pydot.Node(str(p), label=l, shape="octagon")
        else:
            n = pydot.Node(str(p), label=l, shape="box")
        
        dot.add_node(n)
        
        for child in iterChildren(p, s.p):

            if child:  
                _r(child)
                dot.add_edge(pydot.Edge(str(p), str(child)))

    _r(p)

    
    return dot


    
        


 