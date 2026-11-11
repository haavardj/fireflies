# -*- coding: utf-8 -*-
######################################################################
## Filename:      ring.py
## Description:   Ring classes.
## Author:        Håvard Dagenborg <havard.dagenborg@outlook.com>
## Modified at:   Tue Jan 24 10:39:41 2006
## Modified by:   Håvard Dagenborg <havard.dagenborg@outlook.com>
## Licence:       MIT (see the LICENCE file).
##  
##         Copyright© 2006,2007, Håvard Dagenborg
##                
## $Id: ring.py,v 1.24 2014/06/16 07:49:47 haavardj Exp $
##                
######################################################################

import bisect, hashlib

def _ringIterator(ring, start=0):
    for idx in range(start, len(ring)):
        x = ring[idx]
        yield x
        
def _ringTraverse(ring, start):
    """Yield the items after index start, wrapping around, up to but not
    including the item at start."""
    l = len(ring)
    idx = (start + 1) % l
    while idx != start:
        yield ring[idx]
        idx = (idx + 1) % l

        
        
class Ring(object):
    """A ring is a finite field of items. A ring is similar to Python
    list but items are kept sorted according to their sort
    key. Inserting two items with the same key will raise a ValueError
    exception.
    
    This implementation uses the return value of the items hash
    function as the sort keys. To use a different sort key,
    re-implement the _sortKey method in a subclass. Keys can be any
    object that implements __hash__ and ordering methods, and is
    unique to each object.    
    """

    def __init__(self):
        self.__keylist = []
        self.__key2itm = {}

    def _sortKey(self, item):
        """Return item's sorting key.
        
        This implementation uses the item's hash function return value
        as a key. Reimplement this method in a subclass to use other
        sort keys."""
        return item.identity

    def __iter__(self):
        """Iterate the ring starting at the lowest number.
        
        The ring should not be modified during iteration."""
        return _ringIterator(self, 0)

    def traverse(self, item):
        """Iterate the ring from item's successor around to item's
        predecessor."""
        idx = self.__keylist.index(self._sortKey(item))
        return _ringTraverse(self, idx)

    def __len__(self):
        """Return the number of items in the ring."""
        return len(self.__keylist)
        
    def __getitem__(self, idx):
        """Return the item with the sort key idx."""
        return self.__key2itm[self.__keylist[idx]]
        
    def __contains__(self, item):
        """Return True if item is in the ring."""
        
        key = self._sortKey(item)
        return key in self.__key2itm
    
    def items(self):
        return list(self.__key2itm.values())

    def index(self, item):
        """Return the item's index in the ring. 

        Raises ValueError if the item is not in the ring."""

        key = self._sortKey(item)
        try:
            return self.__keylist.index(key)
        except ValueError:
            raise ValueError("Item %s not in ring" % str(item))
        
    def insert(self, item):
        """Insert item into the ring. 

        Raises ValueError if the item is already in the ring. Return index
        where item was inserted."""

        key = self._sortKey(item)
        if key in self.__key2itm:
            raise ValueError("Item %s already in list" % (str(item)))        
        idx = bisect.bisect_right(self.__keylist, key)
        self.__keylist.insert(idx, key)
        self.__key2itm[key] = item
        return idx

    def remove(self, item):
        """Remove item from the ring. 

        Raises ValueError if the item is not in the ring."""
        
        try:
            del self[self.index(item)]
        except ValueError:
            raise ValueError("Item %s not in ring" % str(item))
        
    def __delitem__(self, idx):
        key = self.__keylist[idx]
        del self.__keylist[idx]
        del self.__key2itm[key]
    
    def isBetween(self, pred, item, succ):
        """Return True if item lies between (intercepts) pred and succ on the ring according to the succesor relationship.

        Please note the following semantic:

          - Rule 1: An item never intercepts a range contining itself. That is, if either pred or succ is item, False is returned.

          - Rule: Nothing lies between an item and and itself. That is, if pred == succ, then 
          this method always returns False.
                    
          - Raises a ValueError if succ, pred, or item is not in the ring.          
        """
        
        li = self.index(pred)
        bi = self.index(item)
        hi = self.index(succ)
        
        #Rule 1: An item always lies between itself. 
        if li == bi or hi == bi:
            return False         
        
        if li < hi:
            if li < bi and bi < hi: return True 
            else: return False
        elif hi < li:            
            if bi < hi or li < bi: return True
            else: return False
        else: # hi == li
            #Rule: Nothing lies between an item and itself (a null range).
            return False
       
    def betweenSucc(self, start, stop):
        """Return all clockwise items between (but not including) start item and stop item.

        Raises ValueError if start or stop is not in the ring."""
        self.index(stop)
        lst = []
        s = self.succ(start)
        while s:
            if s.identity == stop.identity: break
            lst.append(s)
            s = self.succ(s)
        return lst        
                
    def betweenPred(self, start, stop):
        """Return all counter-clockwise items between (but not including) start and stop.

        Raises ValueError if start or stop is not in the ring."""
        self.index(stop)
        lst = []
        s = self.pred(start)
        while s:
            if s.identity == stop.identity: break
            lst.append(s)
            s = self.pred(s)
        return lst        

    def collectPred(self, start, stopFunc):
        """"Return a list of all items counter-clock wise in the ring from
        (but excluding) start item to (but excluding) the first item where
        stopFunc(item) evaluates to True."""

        lst = []
        s = self.pred(start)
        while s:
            if s.identity == start.identity: break
            if stopFunc(s): break
            lst.append(s)
            s = self.pred(s)
        return lst        
        
    def collectSucc(self, start, stopFunc):
        """"Return a list of all items clock wise in the ring from (but excluding)
        start item to (but excluding) the first item where stopFunc(item)
        evaluates to True."""
        
        lst = []
        s = self.succ(start)
        while s:
            if s.identity == start.identity: break
            if stopFunc(s): break
            lst.append(s)
            s = self.succ(s)
        return lst            
        
    def succ(self, item, func=lambda x: True):
        """Return the first successor of item for which func evaluates
        to True. The default func always evaluates to True.

        The search goes once around the ring and ends at item itself, so
        item is returned if func is True for item and for no other item.
        Callers rely on this. Returns None if func is True for no item.

        Raises ValueError if item is not in the ring.
        """
        l = len(self.__keylist)
        key = self._sortKey(item)
        idx1 = idx = self.__keylist.index(key)     
        idx = (idx + 1) % l
        key = self.__keylist[idx]
        while not func(self.__key2itm[key]):
            if idx == idx1: return None            
            idx = (idx + 1) % l
            key = self.__keylist[idx]       
        return self.__key2itm[key]
    
    def pred(self, item, func=lambda x: True):
        """Return the first predecessor of item for which func evaluates to
        True. The default func always evaluates to True.

        As for succ, item itself is returned if func is True for item and
        for no other item. Returns None if func is True for no item.

        Raises ValueError if item is not in the ring.
        """

        l = len(self.__keylist)
        key = self._sortKey(item)
        idx1 = idx = self.__keylist.index(key)
        idx = (idx - 1) % l
        key = self.__keylist[idx]
        while not func(self.__key2itm[key]):
            if idx == idx1: return None            
            idx = (idx - 1) % l
            key = self.__keylist[idx]                       
        return self.__key2itm[key]
    
    def rank(self, item, base):
        """Returns the number of successor relations between base and item."""
        
        idxItem = self.index(base)
        idxDest = self.index(item)
        
        if idxDest < idxItem:
            return len(self) - idxItem + idxDest
        else:
            return idxDest - idxItem

    @property
    def maxrank(self):
        return len(self)-1

class NamedRing(Ring):
    """A ring with a name/identity."""
    
    def __init__(self, name):
        self.name = name
        Ring.__init__(self)
     
    @property   
    def identity(self):
        return self.name
    

class NameHashedRing(NamedRing):
    """A named ring that will sort items differently for different ring names."""
    
    mRingIDCache = {}    
        
    def _sortKey(self, item):
        iId = item.identity
        try:
            return NameHashedRing.mRingIDCache[iId][self.identity]
        except KeyError:
            ids = NameHashedRing.mRingIDCache.get(iId, {})
            idOnRing = hashlib.sha1(("%s-%s" % (iId, self.identity)).encode("utf-8")).digest()
            ids[self.identity] = idOnRing
            NameHashedRing.mRingIDCache[iId] = ids
            return idOnRing

        
class RingSet(object):
    """A list of rings that will contain the same items.
    
    Rings added to a ringset will have their insert method disabled in order 
    prevent accidential item insertion into invidual rings. 
    All item insertions must go through the ringset object.
    """
         
    def __init__(self):
        self._items = []
        self._rings = []
        self._ringinsertfunc = []

    def succ(self, itm, func=lambda x: True):
        """Return for each ring the first successor of itm for which func evaluates to true."""
        return [x.succ(itm, func) for x in self._rings]

    def pred(self, itm, func=lambda x: True):
        """Return for each ring the first predecessor of itm for which func evaluates to true."""
        return [x.pred(itm, func) for x in self._rings]
    
    def insertItem(self, itm):
        """Insert itm in all rings."""
        if itm in self._items: raise ValueError("Item exist")
        self._items.append(itm)
        for nr, ring in enumerate(self._rings): 
            self._ringinsertfunc[nr](itm) 

    def __len__(self):
        return len(self._rings)
    
    def __iter__(self):
        return iter(self._rings)
    
    def __getitem__(self, key):
        return self._rings[key]
                     
    def insertRing(self, ring):
        """Insert itm in all rings. Items in ring will be merged with contained items."""
        for itm in ring:
            if itm not in self._items: self.insertItem(itm)
        for itm in self._items:
            if itm not in ring: ring.insert(itm)
            
        self._rings.append(ring)
        self._ringinsertfunc.append(ring.insert)
        ring.insert = None
        
    def getRings(self):
        """Return a list of all contained rings."""
        return self._rings
    
    def getItems(self):
        """Return a list of all contained items."""
        return self._items

    def hasItem(self, item):
        return item in self.getItems()
    
    def hasRing(self, ring):
        return ring in self.getRings()

    hadRing = hasRing  # old misspelt name
    
    def itemCount(self):
        return len(self.getItems())
           

class RankTable(object):
    """An RankTable list the ranks, one for each ring, for some item relative to item 'base' for a particular set of rings. 
    
    RankTables with matching bases are comparebale using the following rules:
       A == B: For all i in range(A), A[i] == B[i]
       A != B: There is one i such that A[i] != B[i]
       A <= B: for each entry i, A[i] <= B[i]      
       A <  B: There is one i such that A[i] < B[i] 
       A >= B: for each entry i, A[i] >= B[i]      
       A >  B: There is one i such that A[i] > B[i] 

       
    Less formaly, the RankTable comparison says that A will be larger than B if B is not ranked 
    higher than A on any ring.
    
    Due to the ring structure, the condition A == B implies A.item == B.item.
    
    """ 
  
    INVALID = 0
    
    def __init__(self, item, base, rings):
        self.item = item
        self.base = base
        self.rings = rings
        self.values = [self.INVALID] * len(self.rings)
        
        if item:
            for nr, ring in enumerate(self.rings):
                isinstance(ring, Ring)
                ring.rank
                self[nr] = ring.rank(item, self.base)

            
    def __len__(self):
        return len(self.values)
    
    def __getitem__(self, key):
        return self.values[key]
    
    def __setitem__(self, key, value):
        self.values[key] = value
        
    def __iter__(self):
        return iter(self.values)             
    
    def __add__(self, other): 
        if other.base != self.base:
            raise ValueError("RankTable comparison must have same base.")        

        v = type(self)(0, self.base, self.rings)
        for nr, ring in enumerate(self.rings):
            v[nr] = max(self[nr], other[nr])
        return v
    
    def __iadd__(self, other):
        if other.base != self.base:
            raise ValueError("RankTable comparison must have same base.")        

        for nr, ring in enumerate(self.rings):
            self[nr] = max(self[nr], other[nr])
        return self
    
    def __sub__(self, other): 
        if other.base != self.base:
            raise ValueError("RankTable comparison must have same base.")        

        v = type(self)(0, self.base, self.rings)
        for nr, ring in enumerate(self.rings):
            v[nr] = min(self[nr], other[nr])
        return v

    def __isub__(self, other):
        if other.base != self.base:
            raise ValueError("RankTable comparison must have same base.")        

        for nr, ring in enumerate(self.rings):
            self[nr] = min(self[nr], other[nr])
        return self

            
            
    def __lt__(self, other):
        """True if at least one rank entry of this table is smaller than in other."""
        
        if other.base != self.base:
            raise ValueError("RankTable comparison must have same base.")        
        for x in range(len(self)):
            if self[x] < other[x]: return True
        return False

    def __le__(self, other):
        """True if all entries are smaller or equal to the ones in other."""
        
        if other.base != self.base:
            raise ValueError("RankTable comparison must have same base.")        

        for x in range(len(self)):
            if self[x] > other[x]: return False
        return True   
    
    def __gt__(self, other):
        """True if at least one rank entry in other is larger than in other."""
        
        if other.base != self.base:
            raise ValueError("RankTable comparison must have same base.")        
        for x in range(len(self)):
            if self[x] > other[x]: return True
        return False
    
    def __ge__(self, other):
        """True if all entries are larger or equal to the ones in other."""
         
        if other.base != self.base:
            raise ValueError("RankTable comparison must have same base.")        
        
        for x in range(len(self)):
            if self[x] < other[x]: return False
        return True
                  
    def __eq__(self, other):
        """True if all entries are equal."""
        
        if other.base != self.base:
            raise ValueError("RankTable comparison must have same base.")        

        for x in range(len(self)):
            if self[x] != other[x]: return False
        return True
    
    def __ne__(self, other):
        """True if at least one entry is different from other."""
        if other.base != self.base:
            raise ValueError("RankTable comparison must have same base.")        
        
        for x in range(len(self)):
            if self[x] != other[x]: return True
        return False
    
    def __str__(self):
        return str(self.values)

        
            
        
    
    
class Relation:
    """A rule determining if item relate to otherItem in some manner on one particular ring.
    Implement relational rule in the isValid method in subclasses.""" 
    
    def __init__(self, item, otherItem, ring):
        self.item, self.otherItem, self.ring = item, otherItem, ring
        
    def isValid(self):   
        raise NotImplementedError
    
    def rank(self):
        """Return the rank of the items relative to each other."""
        return self.ring.rank(self.item, self.otherItem)
        
    # Compare rank. Note: this might be semantically bad idea since objects
    # might have differend otherItem and ring attributes.
    def __eq__(self, other):
        return self.rank() == other.rank()

    def __lt__(self, other):
        return self.rank() < other.rank()

    def __le__(self, other):
        return self.rank() <= other.rank()

    def __gt__(self, other):
        return self.rank() > other.rank()

    def __ge__(self, other):
        return self.rank() >= other.rank()

    __hash__ = None  # pyright: ignore[reportAssignmentType]  # unhashable: equality is by rank

class SuccessorRelation(Relation):
    """Rule determining if two an item is the successor of another item in a ring."""
    
    def isValid(self):
        return self.ring.succ(self.item) == self.otherItem
                
class PredecessorRelation(Relation):
    """Rule determining if two an item is the predecessor of another item in a ring."""
    
    def isValid(self):
        return self.ring.pred(self.item) == self.otherItem

        